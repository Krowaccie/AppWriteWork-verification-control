import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  link,
  lstat,
  open,
  readdir,
  realpath,
  unlink,
} from "node:fs/promises";
import path from "node:path";

import {
  createHostedSiteBuildIdentity,
  serializeHostedSiteBuildIdentity,
} from "./verification/hosted-site-build-identity.mjs";
import {
  digestFileSet,
  sha256Bytes,
} from "./verification/canonical-json.mjs";

const WRITER_KEYS = Object.freeze([
  "outputDir",
  "sourceRevision",
  "sitePayloadDigest",
  "verifierManifestDigest",
]);
const ROOT_IDENTITY_PATH = "build-identity.json";
const EMPTY_DIAGNOSTICS = Object.freeze([]);
const STAT_FIELDS = Object.freeze([
  "dev",
  "ino",
  "mode",
  "nlink",
  "uid",
  "gid",
  "rdev",
  "size",
  "blksize",
  "blocks",
  "mtimeNs",
  "ctimeNs",
  "birthtimeNs",
]);

class HostedSiteIdentityError extends Error {
  constructor(code, safeMessage) {
    super(safeMessage);
    this.name = "HostedSiteIdentityError";
    this.code = code;
    this.safeMessage = safeMessage;
  }
}

function fail(code, safeMessage) {
  throw new HostedSiteIdentityError(code, safeMessage);
}

function pass(value) {
  return Object.freeze({
    status: "PASS",
    value,
    diagnostics: EMPTY_DIAGNOSTICS,
  });
}

function blocked(code, safeMessage) {
  const diagnostic = Object.freeze({
    code,
    safeMessage,
    retryable: false,
  });
  return Object.freeze({
    status: "BLOCKED",
    value: null,
    diagnostics: Object.freeze([diagnostic]),
  });
}

function inspectWriterInput(value) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return null;
    }

    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== WRITER_KEYS.length ||
      ownKeys.some((key) => typeof key !== "string") ||
      ownKeys.some((key) => !WRITER_KEYS.includes(key)) ||
      WRITER_KEYS.some((key) => !ownKeys.includes(key))
    ) {
      return null;
    }

    const data = Object.create(null);
    for (const key of WRITER_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        descriptor.enumerable !== true ||
        !("value" in descriptor) ||
        "get" in descriptor ||
        "set" in descriptor
      ) {
        return null;
      }
      data[key] = descriptor.value;
    }
    return data;
  } catch {
    return null;
  }
}

function sameStat(left, right) {
  return STAT_FIELDS.every((field) => left[field] === right[field]);
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertSafeOutputPath(outputDir) {
  const hostCanonical = typeof outputDir === "string" &&
    path.normalize(outputDir) === outputDir;
  const posixCanonical = typeof outputDir === "string" &&
    outputDir.startsWith("/") &&
    !outputDir.includes("\\") &&
    path.posix.normalize(outputDir) === outputDir;
  if (
    typeof outputDir !== "string" ||
    outputDir.length === 0 ||
    outputDir.includes("\0") ||
    !path.isAbsolute(outputDir) ||
    (!hostCanonical && !posixCanonical)
  ) {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site output path.");
  }
}

function assertContained(rootRealPath, candidateRealPath) {
  const relative = path.relative(rootRealPath, candidateRealPath);
  if (
    relative !== "" &&
    (path.isAbsolute(relative) ||
      relative === ".." ||
      relative.startsWith(`..${path.sep}`))
  ) {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload path.");
  }
}

function assertSafePayloadName(name) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name === "." ||
    name === ".." ||
    name.includes("/") ||
    name.includes("\\") ||
    name.includes(":") ||
    /[\u0000-\u001f\u007f]/u.test(name)
  ) {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload path.");
  }
}

function normalizedFileMode(mode) {
  return (mode & 0o111n) === 0n ? "100644" : "100755";
}

async function safeLstat(absolutePath) {
  try {
    return await lstat(absolutePath, { bigint: true });
  } catch (error) {
    if (error?.code === "ENOENT") {
      fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site output path.");
    }
    throw error;
  }
}

async function readRegularFileSafely(
  absolutePath,
  rootRealPath,
  initialStat = undefined,
) {
  const beforePath = initialStat ?? (await safeLstat(absolutePath));
  if (
    beforePath.isSymbolicLink() ||
    !beforePath.isFile() ||
    beforePath.nlink !== 1n
  ) {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload entry.");
  }

  let resolvedBefore;
  try {
    resolvedBefore = await realpath(absolutePath);
  } catch {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload path.");
  }
  assertContained(rootRealPath, resolvedBefore);

  let handle;
  try {
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    handle = await open(absolutePath, fsConstants.O_RDONLY | noFollow);
    const beforeHandle = await handle.stat({ bigint: true });
    if (!sameStat(beforePath, beforeHandle)) {
      fail("ARTIFACT_PATH_UNSAFE", "Hosted Site payload changed during read.");
    }

    const bytes = await handle.readFile();
    const afterHandle = await handle.stat({ bigint: true });
    if (!sameStat(beforeHandle, afterHandle)) {
      fail("ARTIFACT_PATH_UNSAFE", "Hosted Site payload changed during read.");
    }

    await handle.close();
    handle = undefined;

    const afterPath = await safeLstat(absolutePath);
    let resolvedAfter;
    try {
      resolvedAfter = await realpath(absolutePath);
    } catch {
      fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload path.");
    }
    if (
      !sameStat(beforePath, afterPath) ||
      resolvedAfter !== resolvedBefore
    ) {
      fail("ARTIFACT_PATH_UNSAFE", "Hosted Site payload changed during read.");
    }

    return { bytes, stat: afterPath };
  } catch (error) {
    if (error instanceof HostedSiteIdentityError) {
      throw error;
    }
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload entry.");
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function collectPayloadDirectory(
  absoluteDirectory,
  relativeSegments,
  rootRealPath,
  files,
) {
  const beforeDirectory = await safeLstat(absoluteDirectory);
  if (beforeDirectory.isSymbolicLink() || !beforeDirectory.isDirectory()) {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload directory.");
  }

  let resolvedBefore;
  try {
    resolvedBefore = await realpath(absoluteDirectory);
  } catch {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload directory.");
  }
  assertContained(rootRealPath, resolvedBefore);

  let directoryEntries;
  try {
    directoryEntries = await readdir(absoluteDirectory, { withFileTypes: true });
  } catch {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload directory.");
  }
  directoryEntries.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );

  for (const directoryEntry of directoryEntries) {
    assertSafePayloadName(directoryEntry.name);
    const childSegments = [...relativeSegments, directoryEntry.name];
    const relativePath = childSegments.join("/");
    const absolutePath = path.join(absoluteDirectory, directoryEntry.name);
    const entryStat = await safeLstat(absolutePath);

    if (entryStat.isSymbolicLink()) {
      fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload entry.");
    }
    if (entryStat.isDirectory()) {
      await collectPayloadDirectory(
        absolutePath,
        childSegments,
        rootRealPath,
        files,
      );
      continue;
    }
    if (!entryStat.isFile()) {
      fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload entry.");
    }

    const { bytes, stat } = await readRegularFileSafely(
      absolutePath,
      rootRealPath,
      entryStat,
    );
    if (relativePath === ROOT_IDENTITY_PATH) {
      continue;
    }

    files.push({
      path: relativePath,
      mode: normalizedFileMode(stat.mode),
      contentDigest: sha256Bytes(bytes),
    });
  }

  const afterDirectory = await safeLstat(absoluteDirectory);
  let resolvedAfter;
  try {
    resolvedAfter = await realpath(absoluteDirectory);
  } catch {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site payload directory.");
  }
  if (
    !sameStat(beforeDirectory, afterDirectory) ||
    resolvedBefore !== resolvedAfter
  ) {
    fail("ARTIFACT_PATH_UNSAFE", "Hosted Site payload changed during read.");
  }
}

export async function computeHostedSitePayloadDigest(outputDir) {
  assertSafeOutputPath(outputDir);

  const rootStat = await safeLstat(outputDir);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site output directory.");
  }

  let rootRealPath;
  try {
    rootRealPath = await realpath(outputDir);
  } catch {
    fail("ARTIFACT_PATH_UNSAFE", "Unsafe hosted Site output directory.");
  }

  const files = [];
  await collectPayloadDirectory(outputDir, [], rootRealPath, files);
  return digestFileSet(files);
}

async function pathDoesNotExist(absolutePath) {
  try {
    await lstat(absolutePath);
    return false;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return true;
    }
    throw error;
  }
}

async function publishIdentityAtomically(outputDir, identityBytes, afterLink = async () => {}) {
  const identityPath = path.join(outputDir, ROOT_IDENTITY_PATH);
  const rootRealPath = await realpath(outputDir);

  if (!(await pathDoesNotExist(identityPath))) {
    const existing = await readRegularFileSafely(identityPath, rootRealPath);
    if (!existing.bytes.equals(identityBytes)) {
      fail(
        "ARTIFACT_NOT_REPRODUCIBLE",
        "Existing hosted Site identity does not match requested identity.",
      );
    }
    return { created: false, stat: existing.stat };
  }

  const temporaryPath = path.join(
    outputDir,
    `.hosted-site-build-identity.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle;
  let published = false;
  let publicationStat;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(identityBytes);
    await handle.sync();
    await handle.chmod(0o644);
    await handle.sync();
    await handle.close();
    handle = undefined;

    await link(temporaryPath, identityPath);
    published = true;
    publicationStat = await lstat(identityPath, { bigint: true });
    await afterLink(Object.freeze({ identityPath }));
    const postCallbackStat = await lstat(identityPath, { bigint: true });
    if (
      postCallbackStat.isSymbolicLink()
      || !postCallbackStat.isFile()
      || !sameInode(postCallbackStat, publicationStat)
    ) {
      fail("ARTIFACT_PATH_UNSAFE", "Hosted Site identity could not be published safely.");
    }
    await unlink(temporaryPath);

    const publishedFile = await readRegularFileSafely(identityPath, rootRealPath);
    if (!sameInode(publishedFile.stat, publicationStat) || !publishedFile.bytes.equals(identityBytes)) {
      fail(
        "ARTIFACT_NOT_REPRODUCIBLE",
        "Hosted Site identity publication could not be verified.",
      );
    }
    return { created: true, stat: publishedFile.stat };
  } catch (error) {
    if (published && publicationStat !== undefined) {
      try {
        const current = await lstat(identityPath, { bigint: true });
        if (
          !current.isSymbolicLink()
          && current.isFile()
          && sameInode(current, publicationStat)
        ) {
          await unlink(identityPath);
        }
      } catch {
        // Never broaden cleanup beyond the inode published by this call.
      }
    }
    if (error instanceof HostedSiteIdentityError) {
      throw error;
    }
    fail("ARTIFACT_PATH_UNSAFE", "Hosted Site identity could not be published safely.");
  } finally {
    await handle?.close().catch(() => {});
    await unlink(temporaryPath).catch((error) => {
      if (error?.code !== "ENOENT") {
        // A surviving exclusive temp file makes the output unusable; the caller blocks.
      }
    });
    if (published && (await pathDoesNotExist(identityPath))) {
      published = false;
    }
  }
}

export function __testOnlyPublishIdentityAtomically(outputDir, identityBytes, afterLink) {
  return publishIdentityAtomically(outputDir, identityBytes, afterLink);
}

async function removeCreatedIdentityIfUnchanged(outputDir, publication) {
  if (!publication?.created) {
    return;
  }
  const identityPath = path.join(outputDir, ROOT_IDENTITY_PATH);
  try {
    const current = await lstat(identityPath, { bigint: true });
    if (
      !current.isSymbolicLink() &&
      current.isFile() &&
      sameStat(current, publication.stat)
    ) {
      await unlink(identityPath);
    }
  } catch {
    // Cleanup is best-effort and never broadens the path being removed.
  }
}

export async function writeHostedSiteBuildIdentity(options) {
  const input = inspectWriterInput(options);
  if (input === null) {
    return blocked(
      "ARTIFACT_SCHEMA_INVALID",
      "Hosted Site identity writer input is invalid.",
    );
  }

  let identity;
  try {
    identity = createHostedSiteBuildIdentity({
      schemaVersion: "hosted-site-build-identity.v1",
      sourceRevision: input.sourceRevision,
      sitePayloadDigest: input.sitePayloadDigest,
      verifierManifestDigest: input.verifierManifestDigest,
    });
  } catch {
    return blocked(
      "ARTIFACT_SCHEMA_INVALID",
      "Hosted Site identity writer input is invalid.",
    );
  }

  if (typeof input.outputDir !== "string") {
    return blocked(
      "ARTIFACT_SCHEMA_INVALID",
      "Hosted Site identity writer input is invalid.",
    );
  }

  let publication;
  try {
    const observedDigest = await computeHostedSitePayloadDigest(input.outputDir);
    if (observedDigest !== identity.sitePayloadDigest) {
      fail(
        "ARTIFACT_NOT_REPRODUCIBLE",
        "Hosted Site payload does not match its declared digest.",
      );
    }

    const identityBytes = Buffer.from(
      serializeHostedSiteBuildIdentity(identity),
      "utf8",
    );
    publication = await publishIdentityAtomically(input.outputDir, identityBytes);

    const finalDigest = await computeHostedSitePayloadDigest(input.outputDir);
    if (finalDigest !== identity.sitePayloadDigest) {
      fail(
        "ARTIFACT_NOT_REPRODUCIBLE",
        "Hosted Site payload changed while identity was being written.",
      );
    }

    return pass(identity);
  } catch (error) {
    await removeCreatedIdentityIfUnchanged(input.outputDir, publication);
    if (error instanceof HostedSiteIdentityError) {
      return blocked(error.code, error.safeMessage);
    }
    return blocked(
      "ARTIFACT_PATH_UNSAFE",
      "Hosted Site identity could not be written safely.",
    );
  }
}
