import { canonicalJson } from "./canonical-json.mjs";

export const HOSTED_SITE_BUILD_IDENTITY_SCHEMA_VERSION =
  "hosted-site-build-identity.v1";

const IDENTITY_KEYS = Object.freeze([
  "schemaVersion",
  "sourceRevision",
  "sitePayloadDigest",
  "verifierManifestDigest",
]);
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;

function frozenValidation(ok, errors) {
  return Object.freeze({ ok, errors: Object.freeze(errors) });
}

function inspectClosedDataObject(value) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, error: "identity must be an object" };
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return { ok: false, error: "identity must be a plain object" };
    }

    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== IDENTITY_KEYS.length ||
      ownKeys.some((key) => typeof key !== "string") ||
      ownKeys.some((key) => !IDENTITY_KEYS.includes(key)) ||
      IDENTITY_KEYS.some((key) => !ownKeys.includes(key))
    ) {
      return { ok: false, error: "identity fields do not match the schema" };
    }

    const data = Object.create(null);
    for (const key of IDENTITY_KEYS) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        descriptor.enumerable !== true ||
        !("value" in descriptor) ||
        "get" in descriptor ||
        "set" in descriptor
      ) {
        return { ok: false, error: "identity fields must be enumerable data" };
      }
      data[key] = descriptor.value;
    }

    return { ok: true, data };
  } catch {
    return { ok: false, error: "identity could not be inspected safely" };
  }
}

export function validateHostedSiteBuildIdentity(value) {
  const inspected = inspectClosedDataObject(value);
  if (!inspected.ok) {
    return frozenValidation(false, [inspected.error]);
  }

  const errors = [];
  const {
    schemaVersion,
    sourceRevision,
    sitePayloadDigest,
    verifierManifestDigest,
  } = inspected.data;

  if (schemaVersion !== HOSTED_SITE_BUILD_IDENTITY_SCHEMA_VERSION) {
    errors.push("schemaVersion must identify hosted Site build identity v1");
  }
  if (
    typeof sourceRevision !== "string" ||
    !SOURCE_REVISION_PATTERN.test(sourceRevision)
  ) {
    errors.push("sourceRevision must be a full lowercase Git revision");
  }
  if (
    typeof sitePayloadDigest !== "string" ||
    !SHA256_DIGEST_PATTERN.test(sitePayloadDigest)
  ) {
    errors.push("sitePayloadDigest must be a lowercase sha256 digest");
  }
  if (
    typeof verifierManifestDigest !== "string" ||
    !SHA256_DIGEST_PATTERN.test(verifierManifestDigest)
  ) {
    errors.push("verifierManifestDigest must be a lowercase sha256 digest");
  }

  return frozenValidation(errors.length === 0, errors);
}

export function createHostedSiteBuildIdentity(input) {
  const inspected = inspectClosedDataObject(input);
  if (!inspected.ok) {
    throw new TypeError("Hosted Site build identity is invalid.");
  }
  const snapshot = {
    schemaVersion: inspected.data.schemaVersion,
    sourceRevision: inspected.data.sourceRevision,
    sitePayloadDigest: inspected.data.sitePayloadDigest,
    verifierManifestDigest: inspected.data.verifierManifestDigest,
  };
  const validation = validateHostedSiteBuildIdentity(snapshot);
  if (!validation.ok) {
    throw new TypeError("Hosted Site build identity is invalid.");
  }
  return Object.freeze(snapshot);
}

export function serializeHostedSiteBuildIdentity(identity) {
  const validated = createHostedSiteBuildIdentity(identity);
  return `${canonicalJson(validated)}\n`;
}
