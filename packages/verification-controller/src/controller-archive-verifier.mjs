import { inflateRawSync } from 'node:zlib';

export const MAX_VERIFICATION_ARCHIVE_BYTES = 64 * 1024 * 1024;

const SAFE_PATH = /^(?!\/)(?!.*\/{2})(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\\)[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const WINDOWS_RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_EXPANDED_BYTES = 128 * 1024 * 1024;
const MAX_ENTRIES = 256;

function responseHeader(response, name) {
  if (typeof response?.headers?.get === 'function') return response.headers.get(name);
  if (response?.headers && typeof response.headers === 'object') {
    const key = Object.keys(response.headers)
      .find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key === undefined ? null : response.headers[key];
  }
  return null;
}

export async function readBoundedResponseBytes(response, limit) {
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('invalid limit');
  const rawLength = responseHeader(response, 'content-length');
  let declaredLength = null;
  if (rawLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(rawLength)) throw new Error('invalid length');
    declaredLength = Number(rawLength);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > limit) {
      throw new Error('body too large');
    }
  }
  if (response?.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!(value instanceof Uint8Array)) throw new Error('invalid body');
        total += value.byteLength;
        if (total > limit) {
          await reader.cancel();
          throw new Error('body too large');
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      reader.releaseLock();
    }
    if (declaredLength !== null && total !== declaredLength) throw new Error('length mismatch');
    return Buffer.concat(chunks, total);
  }
  if (declaredLength === null || typeof response?.arrayBuffer !== 'function') {
    throw new Error('bounded body unavailable');
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length !== declaredLength || bytes.length > limit) throw new Error('length mismatch');
  return bytes;
}

function validPath(value) {
  return typeof value === 'string'
    && SAFE_PATH.test(value)
    && value.split('/').every((segment) => (
      !segment.endsWith('.')
      && !segment.endsWith(' ')
      && !WINDOWS_RESERVED.test(segment)
    ));
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function parseExtraFields(buffer, start, length) {
  const end = start + length;
  if (!Number.isSafeInteger(end) || end > buffer.length) throw new Error('invalid extra');
  let cursor = start;
  while (cursor < end) {
    if (cursor + 4 > end) throw new Error('invalid extra');
    const id = buffer.readUInt16LE(cursor);
    const size = buffer.readUInt16LE(cursor + 2);
    cursor += 4;
    if (id === 0x0001 || cursor + size > end) throw new Error('unsafe extra');
    cursor += size;
  }
}

function decodeEntryPath(bytes, flags) {
  if (bytes.includes(0)) throw new Error('nul path');
  if ((flags & 0x0800) === 0 && [...bytes].some((byte) => byte > 0x7f)) {
    throw new Error('ambiguous path');
  }
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  if (!validPath(value)) throw new Error('unsafe path');
  return value;
}

function endOfCentralDirectory(buffer) {
  const earliest = Math.max(0, buffer.length - 22 - 0xffff);
  const candidates = [];
  for (let offset = buffer.length - 22; offset >= earliest; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== 0x06054b50) continue;
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength === buffer.length) candidates.push(offset);
  }
  if (candidates.length !== 1) throw new Error('ambiguous central directory');
  return candidates[0];
}

export function extractBoundedZipArchive(archive) {
  const buffer = Buffer.from(archive);
  if (
    buffer.length < 22
    || buffer.length > MAX_VERIFICATION_ARCHIVE_BYTES
  ) throw new Error('archive size');
  const endOffset = endOfCentralDirectory(buffer);
  const entryCount = buffer.readUInt16LE(endOffset + 10);
  const centralSize = buffer.readUInt32LE(endOffset + 12);
  const centralOffset = buffer.readUInt32LE(endOffset + 16);
  if (
    buffer.readUInt16LE(endOffset + 4) !== 0
    || buffer.readUInt16LE(endOffset + 6) !== 0
    || buffer.readUInt16LE(endOffset + 8) !== entryCount
    || entryCount < 2
    || entryCount > MAX_ENTRIES
    || buffer.readUInt16LE(endOffset + 20) !== 0
    || centralOffset + centralSize !== endOffset
  ) throw new Error('invalid central directory');

  const centralRecords = [];
  const identities = new Set();
  let cursor = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > endOffset || buffer.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error('missing central entry');
    }
    const madeBy = buffer.readUInt16LE(cursor + 4);
    const flags = buffer.readUInt16LE(cursor + 8);
    const method = buffer.readUInt16LE(cursor + 10);
    const checksum = buffer.readUInt32LE(cursor + 16);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const uncompressedSize = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const startDisk = buffer.readUInt16LE(cursor + 34);
    const attributes = buffer.readUInt32LE(cursor + 38);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const recordEnd = cursor + 46 + nameLength + extraLength + commentLength;
    if (
      recordEnd > endOffset
      || nameLength < 1
      || commentLength !== 0
      || startDisk !== 0
      || compressedSize === 0xffffffff
      || uncompressedSize === 0xffffffff
      || compressedSize > MAX_VERIFICATION_ARCHIVE_BYTES
      || uncompressedSize > MAX_FILE_BYTES
      || (flags & 0x0001) !== 0
      || (flags & ~(0x0800 | 0x0008 | 0x0006)) !== 0
      || ![0, 8].includes(method)
      || (method === 0 && (flags & 0x0006) !== 0)
    ) throw new Error('unsafe central entry');
    const mode = attributes >>> 16;
    const type = mode & 0o170000;
    if (
      (attributes & 0x10) !== 0
      || ((madeBy >>> 8) === 3 && ![0, 0o100000].includes(type))
      || (mode & 0o111) !== 0
    ) throw new Error('unsafe entry type');
    const nameStart = cursor + 46;
    const nameBytes = Buffer.from(buffer.subarray(nameStart, nameStart + nameLength));
    const entryPath = decodeEntryPath(nameBytes, flags);
    const identity = entryPath.toLowerCase();
    if (identities.has(identity)) throw new Error('duplicate path');
    identities.add(identity);
    parseExtraFields(buffer, nameStart + nameLength, extraLength);
    centralRecords.push({
      checksum,
      compressedSize,
      entryPath,
      flags,
      localOffset,
      method,
      nameBytes,
      uncompressedSize,
    });
    cursor = recordEnd;
  }
  if (cursor !== endOffset) throw new Error('central trailing data');

  const ordered = [...centralRecords].sort((left, right) => left.localOffset - right.localOffset);
  if (ordered[0].localOffset !== 0) throw new Error('leading data');
  const entries = new Map();
  let expandedSize = 0;
  for (let index = 0; index < ordered.length; index += 1) {
    const record = ordered[index];
    const boundary = index + 1 < ordered.length
      ? ordered[index + 1].localOffset
      : centralOffset;
    const local = record.localOffset;
    if (local + 30 > boundary || buffer.readUInt32LE(local) !== 0x04034b50) {
      throw new Error('missing local entry');
    }
    const localFlags = buffer.readUInt16LE(local + 6);
    const localMethod = buffer.readUInt16LE(local + 8);
    const localCrc = buffer.readUInt32LE(local + 14);
    const localCompressed = buffer.readUInt32LE(local + 18);
    const localUncompressed = buffer.readUInt32LE(local + 22);
    const localNameLength = buffer.readUInt16LE(local + 26);
    const localExtraLength = buffer.readUInt16LE(local + 28);
    const nameStart = local + 30;
    const extraStart = nameStart + localNameLength;
    const dataStart = extraStart + localExtraLength;
    const dataEnd = dataStart + record.compressedSize;
    if (
      localFlags !== record.flags
      || localMethod !== record.method
      || localNameLength !== record.nameBytes.length
      || dataEnd > boundary
      || !buffer.subarray(nameStart, nameStart + localNameLength).equals(record.nameBytes)
    ) throw new Error('local mismatch');
    parseExtraFields(buffer, extraStart, localExtraLength);
    if ((record.flags & 0x0008) === 0) {
      if (
        localCrc !== record.checksum
        || localCompressed !== record.compressedSize
        || localUncompressed !== record.uncompressedSize
        || dataEnd !== boundary
      ) throw new Error('local size mismatch');
    } else {
      if (
        ![0, record.checksum].includes(localCrc)
        || ![0, record.compressedSize].includes(localCompressed)
        || ![0, record.uncompressedSize].includes(localUncompressed)
      ) throw new Error('stream size mismatch');
      const descriptorLength = boundary - dataEnd;
      const valuesStart = descriptorLength === 16
        && buffer.readUInt32LE(dataEnd) === 0x08074b50
        ? dataEnd + 4
        : descriptorLength === 12 ? dataEnd : -1;
      if (
        valuesStart < 0
        || buffer.readUInt32LE(valuesStart) !== record.checksum
        || buffer.readUInt32LE(valuesStart + 4) !== record.compressedSize
        || buffer.readUInt32LE(valuesStart + 8) !== record.uncompressedSize
      ) throw new Error('descriptor mismatch');
    }
    if (record.method === 0 && record.compressedSize !== record.uncompressedSize) {
      throw new Error('stored size mismatch');
    }
    const compressed = buffer.subarray(dataStart, dataEnd);
    const output = record.method === 0
      ? Buffer.from(compressed)
      : inflateRawSync(compressed, { maxOutputLength: MAX_FILE_BYTES });
    expandedSize += output.length;
    if (
      output.length !== record.uncompressedSize
      || expandedSize > MAX_EXPANDED_BYTES
      || crc32(output) !== record.checksum
    ) throw new Error('payload mismatch');
    entries.set(record.entryPath, Buffer.from(output));
  }
  return entries;
}
