// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {error, IRequest, json, Router, RouterType, StatusError} from 'itty-router';
import {Buffer} from 'node:buffer';
import {AsyncLock, generateParts, readIntFromHeader, toBase64, WritableStreamBuffer} from './util';
import {Env} from './index';
import {Digester, noopDigester, sha256Digester} from './digest';
import {parseChecksum, parseUploadMetadata} from './parse';
import {
    DEFAULT_RETRY_PARAMS,
    isR2ChecksumError,
    isR2MultipartDoesNotExistError, isR2RateLimitError,
    RetryBucket,
    RetryMultipartUpload
} from './retry';
import {R2UploadedPart} from '@cloudflare/workers-types';

export const TUS_VERSION = '1.0.0';

// uploads larger than this will be rejected
export const MAX_UPLOAD_LENGTH_BYTES = 1024 * 1024 * 1024 * 50; // 50GB

export const X_SIGNAL_CHECKSUM_SHA256 = 'X-Signal-Checksum-Sha256';

// how long an unfinished upload lives in ms
const UPLOAD_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;

// how much we'll buffer in memory, must be greater than or equal to R2's min part size (5MB)
// https://developers.cloudflare.com/r2/objects/multipart-objects/#limitations
const BUFFER_SIZE = 1024 * 1024 * 5;

// Maximum number of concurrent R2 part uploads
const MAX_CONCURRENT_UPLOADS = 6;

// how much of the upload we've written
const UPLOAD_OFFSET_KEY = 'upload-offset';

// key for StoredUploadInfo
const UPLOAD_INFO_KEY = 'upload-info';

// Stored for each part with the key of the multipart part number. Part numbers start with 1
interface StoredR2Part {
    part: R2UploadedPart,

    // the length of the part
    length: number
}

// Infrequently changing information about the upload
interface StoredUploadInfo {
    uploadLength?: number,
    checksum?: Uint8Array,
    multipartUploadId?: string
}


// UploadHandlers represent an in-progress resumable upload to cloudflare R2.
//
// This class is a 'template' for a cloudflare durable object, which are
// created by upstream workers for each unique object upload. See
// https://developers.cloudflare.com/workers/runtime-apis/durable-objects/
//
// Uploads use the TUS protocol https://tus.io/protocols/resumable-upload.
// When a client interacts with a particular upload name, all requests are
// routed to the durable object id derived from that name (or a new durable
// object is created if it doesn't already exist). POSTs initialize the
// upload, and subsequent PATCH requests append to  it. If a client gets
// disconnected, a HEAD returns the current upload offset for the upload so
// the upload can be resumed.
//
// Uploads are staged via R2 multipart upload, which is completed when the
// client uploads the last byte. Multipart upload only supports 5MB boundaries,
// which is more than we'd like clients to have to reupload. If a client does
// not complete the upload in a single request (either because of a disconnect
// or because the request is broken into multiple patches), the remainder after
// the last 5MB boundary is saved in a temporary R2 object, which is then read
// on a subsequent PATCH.
export class UploadHandler {
    state: DurableObjectState;
    env: Env;
    router: RouterType;
    parts: StoredR2Part[];
    multipart: RetryMultipartUpload | undefined;
    retryBucket: RetryBucket;

    // only allow a single request to operate at a time
    requestGate: AsyncLock;


    constructor(state: DurableObjectState, env: Env, bucket: R2Bucket) {
        this.state = state;
        this.env = env;
        this.parts = [];
        this.requestGate = new AsyncLock();
        this.retryBucket = new RetryBucket(bucket, DEFAULT_RETRY_PARAMS);
        this.router = Router()
            .post('/upload/:bucket', this.exclusive(this.create))
            .patch('/upload/:bucket/:id+', this.exclusive(this.patch))
            .head('/upload/:bucket/:id+', this.exclusive(this.head))
            .all('*', () => error(404));
    }

    // forbid concurrent requests while running clsMethod
    exclusive(clsMethod: (r: IRequest) => Promise<Response>): (r: IRequest) => Promise<Response> {
        return async request => {
            const release = await this.requestGate.lock();
            try {
                return await clsMethod.bind(this)(request);
            } catch (e) {
                if (e instanceof UnrecoverableError) {
                    try {
                        const ue = e as UnrecoverableError;
                        console.error(`Upload for ${ue.r2Key} failed with unrecoverable error ${ue.message}`);
                        // this upload can never make progress, try to clean up
                        await this.cleanup(ue.r2Key);
                    } catch (cleanupError) {
                        // ignore errors cleaning up
                        console.error('error cleaning up ' + cleanupError);
                    }
                }
                throw e;
            } finally {
                release();
            }
        };
    }

    fetch(request: Request): Promise<Response> {
        return this.router.fetch(request).then(json).catch(e => {
            if (e instanceof StatusError) {
                return error(e);
            }
            console.error('server error processing request: ' + e);
            throw e;
        });
    }

    async alarm() {
        return await this.cleanup();
    }

    // create a new TUS upload
    async create(request: IRequest): Promise<Response> {
        const uploadMetadata = parseUploadMetadata(request.headers);
        const checksum = parseChecksum(request.headers);

        const r2Key = uploadMetadata.filename;
        if (r2Key == null) {
            return error(400, 'bad filename metadata');
        }

        const existingUploadOffset: number | undefined = await this.state.storage.get(UPLOAD_OFFSET_KEY);
        if (existingUploadOffset != null && existingUploadOffset > 0) {
            console.log('duplicate object creation');
            await this.cleanup(r2Key);
            return error(409, 'object already exists');
        }

        // The client may provide an initial request body (creation-with-upload)
        const contentType = request.headers.get('Content-Type');
        if (contentType != null && contentType !== 'application/offset+octet-stream') {
            return error(415, 'create only supports application/offset+octet-stream content-type');
        }
        const contentLength = readIntFromHeader(request.headers, 'Content-Length');
        if (!isNaN(contentLength) && contentLength > 0 && contentType == null) {
            return error(415, 'body requires application/offset+octet-stream content-type');
        }
        const hasContent = request.body != null && contentType != null;
        const uploadLength = readIntFromHeader(request.headers, 'Upload-Length');
        const uploadDeferLength = readIntFromHeader(request.headers, 'Upload-Defer-Length');
        if (isNaN(uploadLength) && isNaN(uploadDeferLength)) {
            return error(400, 'must contain Upload-Length or Upload-Defer-Length header');
        }

        if (!isNaN(uploadDeferLength) && uploadDeferLength !== 1) {
            return error(400, 'bad Upload-Defer-Length');
        }

        const uploadInfo: StoredUploadInfo = {};

        const expiration = new Date(Date.now() + UPLOAD_EXPIRATION_MS);
        await this.state.storage.setAlarm(expiration);
        if (!isNaN(uploadLength)) {
            uploadInfo.uploadLength = uploadLength;
        }
        if (checksum != null) {
            uploadInfo.checksum = checksum;
        }
        await this.state.storage.put(UPLOAD_OFFSET_KEY, 0);
        await this.state.storage.put(UPLOAD_INFO_KEY, uploadInfo);

        const uploadLocation = new URL(r2Key, request.url.endsWith('/') ? request.url : request.url + '/');

        const uploadOffset = hasContent
            ? await this.appendBody(r2Key, request.body, 0, uploadInfo)
            : 0;
        return new Response(null, {
            status: 201,
            headers: new Headers({
                'Location': uploadLocation.href,
                'Upload-Expires': expiration.toString(),
                'Upload-Offset': uploadOffset.toString(),
                'Tus-Resumable': TUS_VERSION
            })
        });
    }

    // get the current upload offset to resume an upload
    async head(request: IRequest): Promise<Response> {
        const r2Key = request.params.id!;

        let offset: number | undefined = await this.state.storage.get(UPLOAD_OFFSET_KEY);
        let uploadLength: number | undefined;
        if (offset == null) {
            const headResponse = await this.retryBucket.head(r2Key);
            if (headResponse == null) {
                return error(404);
            }
            offset = headResponse.size;
            uploadLength = headResponse.size;
        } else {
            const info: StoredUploadInfo | undefined = await this.state.storage.get(UPLOAD_INFO_KEY);
            uploadLength = info?.uploadLength;
        }

        const headers = new Headers({
            'Upload-Offset': offset.toString(),
            'Upload-Expires': (await this.expirationTime()).toString(),
            'Cache-Control': 'no-store',
            'Tus-Resumable': TUS_VERSION
        });
        if (uploadLength != null) {
            headers.set('Upload-Length', uploadLength.toString());
        }
        return new Response(null, {headers});
    }


    // append to the upload at the current upload offset
    async patch(request: IRequest): Promise<Response> {
        const patchStart = Date.now();
        const r2Key = request.params.id!;
        console.log(`[TIMING] PATCH START for ${r2Key}`);

        const getOffsetStart = Date.now();
        let uploadOffset: number | undefined = await this.state.storage.get(UPLOAD_OFFSET_KEY);
        console.log(`[TIMING] storage.get(offset) took ${Date.now() - getOffsetStart}ms`);
        if (uploadOffset == null) {
            return error(404);
        }

        const headerOffset = readIntFromHeader(request.headers, 'Upload-Offset');
        if (uploadOffset !== headerOffset) {
            return error(409, 'incorrect upload offset');
        }

        const getInfoStart = Date.now();
        const uploadInfo: StoredUploadInfo | undefined = await this.state.storage.get(UPLOAD_INFO_KEY);
        console.log(`[TIMING] storage.get(info) took ${Date.now() - getInfoStart}ms`);
        if (uploadInfo == null) {
            throw new UnrecoverableError('existing upload should have had uploadInfo', r2Key);
        }
        const headerUploadLength = readIntFromHeader(request.headers, 'Upload-Length');
        if (uploadInfo.uploadLength != null && !isNaN(headerUploadLength) && uploadInfo.uploadLength !== headerUploadLength) {
            return error(400, 'upload length cannot change');
        }

        // check if we now know the upload length
        if (uploadInfo.uploadLength == null && !isNaN(headerUploadLength)) {
            uploadInfo.uploadLength = headerUploadLength;
            await this.state.storage.put(UPLOAD_INFO_KEY, uploadInfo);
        }

        if (request.body == null) {
            return error(400, 'Must provide request body');
        }

        uploadOffset = await this.appendBody(r2Key, request.body, uploadOffset, uploadInfo);

        const expirationStart = Date.now();
        const expiration = await this.expirationTime();
        console.log(`[TIMING] expirationTime took ${Date.now() - expirationStart}ms`);

        console.log(`[TIMING] PATCH DONE for ${r2Key}: total=${Date.now() - patchStart}ms`);
        return new Response(null, {
            status: 204, headers: new Headers({
                'Upload-Offset': uploadOffset.toString(),
                'Upload-Expires': expiration.toString(),
                'Tus-Resumable': TUS_VERSION
            })
        });
    }


    // Append body to the upload starting at uploadOffset. Returns the new uploadOffset
    // Uses parallel uploads: up to MAX_CONCURRENT_UPLOADS R2 uploads in flight simultaneously
    async appendBody(r2Key: string, body: ReadableStream<Uint8Array>, uploadOffset: number, uploadInfo: StoredUploadInfo): Promise<number> {
        const appendStart = Date.now();
        console.log(`[TIMING] appendBody START for ${r2Key}, offset=${uploadOffset}`);

        const uploadLength = uploadInfo.uploadLength;
        if ((uploadLength || 0) > MAX_UPLOAD_LENGTH_BYTES) {
            await this.cleanup(r2Key);
            throw new StatusError(413, 'Upload-Length exceeds maximum upload size');
        }

        // We'll repeatedly use this to buffer data we'll send to R2
        const mem = new WritableStreamBuffer(new ArrayBuffer(BUFFER_SIZE));

        const resumeStart = Date.now();
        uploadOffset = await this.resumeUpload(r2Key, uploadOffset, uploadInfo, mem);
        console.log(`[TIMING] resumeUpload took ${Date.now() - resumeStart}ms, newOffset=${uploadOffset}`);

        const isSinglePart = uploadLength != null && uploadLength <= BUFFER_SIZE;
        const checksum: Uint8Array | undefined = uploadInfo.checksum;
        const digester: Digester = checksum != null && uploadOffset == 0 && !isSinglePart ? sha256Digester() : noopDigester();

        let partCount = 0;

        // Track pending R2 uploads - up to MAX_CONCURRENT_UPLOADS in flight
        type PendingUpload = {promise: Promise<R2UploadedPart>, length: number, partNum: number};
        const pendingUploads: PendingUpload[] = [];

        // Helper to flush completed uploads and store their results
        const flushCompleted = async () => {
            const flushStart = Date.now();
            const count = pendingUploads.length;
            // Wait for all pending uploads to complete
            const results = await Promise.all(pendingUploads.map(p => p.promise));
            const r2Time = Date.now() - flushStart;
            for (let i = 0; i < results.length; i++) {
                this.parts.push({part: results[i], length: pendingUploads[i].length});
            }
            // Batch write all parts to storage
            const storageOps = pendingUploads.map((p, i) =>
                this.state.storage.put(p.partNum.toString(), {part: results[i], length: p.length})
            );
            await Promise.all(storageOps);
            const totalTime = Date.now() - flushStart;
            console.log(`[TIMING] flush ${count} uploads: r2=${r2Time}ms, storage=${totalTime - r2Time}ms, total=${totalTime}ms`);
            pendingUploads.length = 0;
        };

        const loopStart = Date.now();
        for await (const part of generateParts(body, mem)) {
            partCount++;

            const newLength = uploadOffset + part.bytes.byteLength;
            if (uploadLength != null && newLength > uploadLength) {
                await flushCompleted();
                await this.cleanup(r2Key);
                throw new StatusError(413, 'body exceeds Upload-Length');
            }
            if (newLength > MAX_UPLOAD_LENGTH_BYTES) {
                await flushCompleted();
                await this.cleanup(r2Key);
                throw new StatusError(413, 'body exceeds maximum upload size');
            }

            await digester.update(part.bytes);

            switch (part.kind) {
                case 'intermediate': {
                    if (this.multipart == null) {
                        await flushCompleted();
                        const createStart = Date.now();
                        this.multipart = await this.r2CreateMultipartUpload(r2Key, uploadInfo);
                        console.log(`[TIMING] r2CreateMultipartUpload took ${Date.now() - createStart}ms`);
                    }

                    // If at max concurrent uploads, wait for all to complete
                    if (pendingUploads.length >= MAX_CONCURRENT_UPLOADS) {
                        console.log(`[TIMING] flushing ${pendingUploads.length} pending uploads`);
                        await flushCompleted();
                    }

                    // Copy bytes since buffer will be reused
                    const bytesCopy = new Uint8Array(part.bytes);
                    const partNum = this.parts.length + pendingUploads.length + 1;

                    // Start upload without awaiting
                    pendingUploads.push({
                        promise: this.r2UploadPart(r2Key, partNum, bytesCopy),
                        length: bytesCopy.byteLength,
                        partNum
                    });

                    uploadOffset += part.bytes.byteLength;
                    console.log(`[TIMING] part ${partCount} queued (intermediate, ${part.bytes.byteLength}b), pending=${pendingUploads.length}`);
                    break;
                }
                case 'final':
                case 'error': {
                    // Must await all pending uploads before handling final
                    if (pendingUploads.length > 0) {
                        console.log(`[TIMING] flushing ${pendingUploads.length} pending uploads before final`);
                        await flushCompleted();
                    }

                    const finished = uploadLength != null && uploadOffset + part.bytes.byteLength === uploadLength;
                    const isFullPart = part.bytes.byteLength === mem.buf.byteLength;
                    console.log(`[TIMING] part ${partCount} (${part.kind}, ${part.bytes.byteLength}b): finished=${finished}, isFullPart=${isFullPart}, hasMultipart=${!!this.multipart}`);

                    if (!finished && this.multipart && isFullPart) {
                        const r2Start = Date.now();
                        this.parts.push({
                            part: await this.r2UploadPart(r2Key, this.parts.length + 1, part.bytes),
                            length: part.bytes.byteLength
                        });
                        uploadOffset += part.bytes.byteLength;
                        const writePart = this.state.storage.put(this.parts.length.toString(), this.parts.at(-1));
                        const writeOffset = this.state.storage.put(UPLOAD_OFFSET_KEY, uploadOffset);
                        await Promise.all([writePart, writeOffset]);
                        console.log(`[TIMING] final fullPart: r2=${Date.now() - r2Start}ms`);
                    } else if (!finished) {
                        const r2Start = Date.now();
                        await this.r2Put(this.tempkey(), part.bytes);
                        uploadOffset += part.bytes.byteLength;
                        await this.state.storage.put(UPLOAD_OFFSET_KEY, uploadOffset);
                        console.log(`[TIMING] final temp write: r2=${Date.now() - r2Start}ms`);
                    } else if (!this.multipart) {
                        const r2Start = Date.now();
                        await this.r2Put(r2Key, part.bytes, checksum);
                        console.log(`[TIMING] single-part r2Put took ${Date.now() - r2Start}ms`);
                        uploadOffset += part.bytes.byteLength;
                        await this.cleanup();
                    } else {
                        const r2Start = Date.now();
                        const uploadedPart = await this.r2UploadPart(r2Key, this.parts.length + 1, part.bytes);
                        this.parts.push({part: uploadedPart, length: part.bytes.byteLength});
                        console.log(`[TIMING] final r2UploadPart took ${Date.now() - r2Start}ms`);

                        const completeStart = Date.now();
                        await this.r2CompleteMultipartUpload(r2Key, await digester.digest(), checksum);
                        console.log(`[TIMING] r2CompleteMultipartUpload took ${Date.now() - completeStart}ms`);

                        uploadOffset += part.bytes.byteLength;
                        await this.cleanup();
                    }
                    break;
                }
            }
        }

        // Final offset update
        await this.state.storage.put(UPLOAD_OFFSET_KEY, uploadOffset);
        console.log(`[TIMING] appendBody DONE: total=${Date.now() - appendStart}ms, loop=${Date.now() - loopStart}ms, parts=${partCount}`);
        return uploadOffset;
    }

    // Check a checksum, throwing a 415 if the checksum does not match
    async checkChecksum(r2Key: string, expected: Uint8Array, actual: ArrayBuffer) {
        if (!Buffer.from(actual).equals(expected)) {
            await this.cleanup(r2Key);
            throw new StatusError(415, `The SHA-256 checksum you specified ${toBase64(actual)} did not match what we received ${toBase64(expected)}.`);
        }
    }

    // Compute the SHA-256 checksum of a remote r2 object
    async retrieveChecksum(r2Key: string): Promise<ArrayBuffer> {
        const body = await this.retryBucket.get(r2Key);
        if (body == null) {
            throw new UnrecoverableError(`Object ${r2Key} not found directly after uploading`, r2Key);
        }
        const digest = new crypto.DigestStream('SHA-256');
        await body.body.pipeTo(digest);
        return await digest.digest;
    }


    // Prepare to begin uploading from uploadOffset.
    // Resume any ongoing multipart upload, and fetch stashed temporary object from R2 into mem.
    //
    // Return the uploadOffset for the first byte of mem
    async resumeUpload(r2Key: string, uploadOffset: number, uploadInfo: StoredUploadInfo, mem: WritableStreamBuffer): Promise<number> {
        if (uploadOffset === 0) {
            return 0;
        }

        // Resume any existing multipart upload
        const partOffset = await this.hydrateParts(r2Key, uploadOffset, uploadInfo);
        if (partOffset === uploadOffset) {
            // the uploadOffset the client is starting at picks up exactly at the end
            // of the last multipart part we uploaded
            return partOffset;
        }

        // Otherwise, we should have stashed a temporary object in R2 with whatever was
        // left-over after the last part we uploaded
        const tempobj = await this.retryBucket.get(this.tempkey());
        if (tempobj == null) {
            throw new UnrecoverableError(`we claimed to have ${uploadOffset} bytes, only had ${partOffset}`, r2Key);
        }
        if (partOffset + tempobj.size !== uploadOffset) {
            throw new UnrecoverableError(`we claimed to have ${uploadOffset} bytes,  had ${partOffset + tempobj.size}`, r2Key);
        }

        // Fill mem with the temporary object
        if (tempobj.size > mem.buf.byteLength) {
            throw new UnrecoverableError(`bad temp object ${this.tempkey()} of length ${tempobj.size}`, r2Key);
        }

        // copy into our temp buffer
        await tempobj.body.pipeTo(new WritableStream({
            write(chunk) {
                return mem.write(chunk);
            }
        }));

        // return the location in the overall upload where our memory buffer starts
        return uploadOffset - tempobj.size;
    }

    // load part infos from durable object storage
    async hydrateParts(r2Key: string, uploadOffset: number, uploadInfo: StoredUploadInfo): Promise<number> {
        if (this.multipart != null) {
            return this.parts
                .map(p => p.length)
                .reduce((a, b) => a + b, 0);
        }

        // Batch read all stored parts using list() instead of sequential get() calls
        // This is much faster for uploads with many parts (e.g., 100MB chunks = 20 parts)
        const allEntries = await this.state.storage.list<StoredR2Part>();

        // Filter to only numeric keys (part numbers) and sort by part number
        // Non-part keys like 'upload-offset' and 'upload-info' are excluded
        const partEntries = [...allEntries.entries()]
            .filter(([key]) => /^\d+$/.test(key))
            .sort(([a], [b]) => parseInt(a) - parseInt(b));

        let partOffset = 0;
        for (const [, part] of partEntries) {
            partOffset += part.length;
            if (partOffset > uploadOffset) {
                // this part is past where we've told the client to start uploading
                break;
            }
            this.parts.push(part);
        }
        if (this.parts.length > 0) {
            if (uploadInfo.multipartUploadId == null) {
                throw new UnrecoverableError(`had ${this.parts.length} stored parts but no stored multipartUploadId`, r2Key);
            }
            this.multipart = this.r2ResumeMultipartUpload(r2Key, uploadInfo.multipartUploadId);
        }
        return partOffset;
    }

    async r2CreateMultipartUpload(r2Key: string, uploadInfo: StoredUploadInfo): Promise<RetryMultipartUpload> {
        const customMetadata: Record<string, string> = {};
        if (uploadInfo.checksum != null) {
            customMetadata[X_SIGNAL_CHECKSUM_SHA256] = toBase64(uploadInfo.checksum);
        }
        const upload = await this.retryBucket.createMultipartUpload(r2Key, {customMetadata});
        uploadInfo.multipartUploadId = upload.r2MultipartUpload.uploadId;
        await this.state.storage.put(UPLOAD_INFO_KEY, uploadInfo);
        return upload;
    }

    r2ResumeMultipartUpload(r2Key: string, multipartUploadId: string): RetryMultipartUpload {
        return this.retryBucket.resumeMultipartUpload(r2Key, multipartUploadId);
    }

    async r2Put(r2Key: string, bytes: Uint8Array, checksum?: Uint8Array) {
        try {
            await this.retryBucket.put(r2Key, bytes, checksum);
        } catch (e) {
            if (isR2ChecksumError(e)) {
                console.error(`checksum failure: ${e}`);
                await this.cleanup();
                throw new StatusError(415);
            }
            if (isR2RateLimitError(e)) {
                console.log(`Rate-limit exceeded on PUT for key ${r2Key}`);
            }
            throw e;
        }
    }

    async r2UploadPart(r2Key: string, partIndex: number, bytes: Uint8Array): Promise<R2UploadedPart> {
        if (this.multipart == null) {
            throw new UnrecoverableError('cannot call complete multipart with no multipart upload', r2Key);
        }
        try {
            return await this.multipart.uploadPart(partIndex, bytes);
        } catch (e) {
            if (isR2MultipartDoesNotExistError(e)) {
                // The multipart transaction we persisted no longer exists. It either expired, or it's possible we
                // finished the transaction but failed to update the state afterwords. Either way, we should give up.
                throw new UnrecoverableError(`multipart upload does not exist ${e}`, r2Key);
            }
            if (isR2RateLimitError(e)) {
                console.log(`Rate-limit exceeded on upload part for key ${r2Key}`);
            }
            throw e;
        }
    }

    async r2CompleteMultipartUpload(r2Key: string, actualChecksum?: ArrayBuffer, expectedChecksum?: Uint8Array) {
        if (this.multipart == null) {
            throw new UnrecoverableError('cannot call complete multipart with no multipart upload', r2Key);
        }

        // If we were able to calculate the streaming digest, we can accept or reject now.
        if (actualChecksum != null && expectedChecksum != null) {
            await this.checkChecksum(r2Key, expectedChecksum, actualChecksum);
        }

        try {
            await this.multipart.complete(this.parts.map(storedPart => storedPart.part));
        } catch (e) {
            if (isR2RateLimitError(e)) {
                console.log(`Rate-limit exceeded on complete multipart for key ${r2Key}`);
            }
            throw e;
        }

        // Otherwise we have to compute the digest from the finished upload
        if (actualChecksum == null && expectedChecksum != null) {
            await this.checkChecksum(r2Key, expectedChecksum, await this.retrieveChecksum(r2Key));
        }
    }


    tempkey(): string {
        return 'temporary/' + this.state.id.toString();
    }

    // Cleanup the state for this durable object. If r2Key is provided, the method will make
    // a best-effort attempt to clean any partial R2 objects that may exist.
    //
    // Cleanup should be called when:
    // 1. The upload is successfully completed
    // 2. The server experiences an error condition where retrying would be futile. Cleanup ensures a subsequent retry
    //    will hit a 404.
    // 3. The client has made a mistake uploading that cannot be fixed by retrying with different arguments. e.g.,
    //    an upload with an incorrect checksum.
    async cleanup(r2Key?: string): Promise<void> {
        // Try our best to clean up R2 state we may have left around, but if
        // we fail these objects/transactions will eventually expire. We don't
        // bother removing temporaries because the majority of uploads should
        // not need them and they will expire automatically.
        try {
            if (r2Key != null) {
                await this.hydrateParts(
                    r2Key,
                    await this.state.storage.get(UPLOAD_OFFSET_KEY) || 0,
                    await this.state.storage.get(UPLOAD_INFO_KEY) || {});
                if (this.multipart != null) {
                    await this.multipart.abort();
                }
            }
        } catch (e) {
            console.log('failed to cleanup R2 state: ' + e);
        }

        this.multipart = undefined;
        this.parts = [];
        await this.state.storage.deleteAll();
        await this.state.storage.deleteAlarm();
    }

    // After this time, the upload can no longer be used
    async expirationTime(): Promise<Date> {
        const expiration = await this.state.storage.getAlarm();
        if (expiration == null) {
            return new Date();
        }
        return new Date(expiration);
    }
}

export class AttachmentUploadHandler extends UploadHandler {
    constructor(state: DurableObjectState, env: Env) {
        super(state, env, env.ATTACHMENT_BUCKET);
    }
}

export class BackupUploadHandler extends UploadHandler {
    constructor(state: DurableObjectState, env: Env) {
        super(state, env, env.BACKUP_BUCKET);
    }
}

class UnrecoverableError extends Error {
    r2Key: string;

    constructor(message: string, r2Key: string) {
        super(message);
        this.name = this.constructor.name;
        this.r2Key = r2Key;
    }
}


