# Appwrite Test Live Readback Producer Design

Status: APPROVED

Approval: `conversation:user:2026-08-20:approved-live-readback-producer`

## Purpose

The protected controller can validate canonical Appwrite Test setup bindings,
but it currently has no trusted component that obtains the live provider state
needed to create those bindings. This design adds that missing producer so the
first controller bundle and the recurring `Verify Test Cloud` lane can use
evidence read from the fixed Appwrite Test project rather than placeholders or
test fixtures.

## Scope and boundaries

The producer is limited to:

- controller repository `Krowaccie/AppWriteWork-verification-control`;
- Appwrite endpoint `https://fra.cloud.appwrite.io/v1`;
- Appwrite project `69137c5d003952a36d4c`;
- Site `694579860016df0d2d3c`;
- source repository `Krowaccie/AppWriteWork`;
- protected GitHub environment `appwrite-test`;
- the existing operator and fixture credential classes.

The producer must never read, reference, or mutate production project
`69eb4818000afa64a7fa`, production Site `69eb4a020024c520642e`, or the
`production` branch. It must not map `APPWRITE_TEST_RECOVERY_API_KEY`, create
sessions, invoke functions, deploy artifacts, or mutate Appwrite resources.

## Selected architecture

Add one read-only producer module and one manual protected workflow. The
producer accepts only an exact closed request containing the controller SHA,
source SHA, initial-seed mode, the fixed Appwrite inventory, and a separately
generated source-browser artifact policy. It uses the existing operator key for
Site, Function, and runner-variable readback and the fixture key for user,
session, and fixed lease readback.

The workflow runs only on `workflow_dispatch`, only at the exact trusted
controller SHA, and only in `appwrite-test`. It writes a canonical,
secret-free artifact containing:

- provider setup readback JSON and SHA-256 digest;
- provider setup attestation JSON and SHA-256 digest;
- hosted prepublication or ordinary hosted readback JSON and digest;
- hosted attestation JSON and digest;
- sanitized projection evidence and safe diagnostics.

The eight values are intentionally not GitHub environment variables. The
provider document is larger than GitHub's per-variable limit, and the complete
set can exceed the Windows process-environment limit. A small artifact ID and
raw ZIP digest are the only persistent pointers. Both consuming workflows
download the same-repository artifact, verify its metadata, workflow head SHA,
raw ZIP digest, exact member set, per-file manifest, canonical JSON, and setup
semantics, then read the verified files directly.

Secrets exist only in the process environment of the producer step. They are
removed before artifact upload and must not appear in stdout, stderr, files, or
GitHub outputs.

## Components

### `appwrite-test-live-readback.mjs`

This module owns network acquisition and projection. It must:

1. validate the exact controller/source SHA tuple and fixed inventory before
   reading either credential;
2. create separate credential handles so operator and fixture reads remain
   auditable and disjoint;
3. make only allowlisted `GET` requests to exact fixed Appwrite paths;
4. reject redirects, unexpected response formats, duplicate JSON keys,
   oversized responses, unknown fields needed by closed projections, and any
   response containing either credential;
5. derive runner-variable value digests without emitting raw values;
6. derive identity-role bindings and zero-session evidence without emitting
   user IDs, emails, passwords, or raw preference documents;
7. derive Site and Function configuration digests from live responses;
8. verify the fixed idle lease row;
9. combine those projections with the approved provider-schema descriptor and
   source-browser policy;
10. return only a frozen secret-free projection.

### `appwrite-test-setup-bindings.mjs`

This pure module assembles canonical documents and attestations. It must not
perform network calls or read environment variables. It consumes the sanitized
live projection plus the source-browser policy and produces the eight binding
values. It validates its own result with the existing setup, hosted setup, and
attestation validators before returning PASS.

The initial-seed hosted document uses
`test-cloud.hosted-prepublication-readback.v1` and contains no artifact ID or
bundle digest. The ordinary document uses
`test-cloud.hosted-setup-readback.v1` and requires the exact provider artifact
ID and raw ZIP digest.

### `collect-appwrite-test-readback.yml`

The workflow must:

- be manual-only;
- use `windows-2025` and Node `24.11.1`;
- use environment `appwrite-test`;
- require `github.sha == vars.TRUSTED_CONTROLLER_SHA`;
- map only the two Appwrite read credentials, source-artifact reader key, and
  the three identity email values needed for identity-safe digest projection;
- accept the exact controller SHA, successful source `Verify Main` tuple,
  runner SHA, initial-seed mode, and optional controller artifact tuple;
- upload one artifact named
  `appwrite-test-setup-readback-<controller-sha>-<source-sha>`;
- upload only the eight binding values, sanitized evidence, and a canonical
  per-file manifest;
- use the repository's seven-day retention;
- never log JSON binding values because they may contain nonsecret but private
  identity-derived digests.

## Source-browser policy

The first 25 browser-policy rows bind the exact browser members in the source
verification artifact. They must be generated from the exact source revision
by existing browser-artifact-set logic and may not be copied from the synthetic
setup corpus. The remaining Appwrite request rows must be derived from the
approved provider contract and the fixed Appwrite Test project/origin. The
producer rejects `test-only.invalid`, `example`, production hosts, placeholder
digests, duplicate ordinals, or a policy whose self-field-free digest does not
match.

The source-browser policy is generated inside the collector from the exact
successful `Verify Main` artifact. Its first 25 rows therefore come from the
same source revision and artifact tuple used later by the hosted verifier.

## Data flow

1. Merge the independently reviewed source candidate and obtain a successful
   `Verify Main` artifact tuple.
2. Dispatch the protected initial readback workflow at the exact controller
   SHA and source tuple.
3. Read Appwrite Test state using disjoint operator and fixture credentials.
4. Generate the browser policy from the source artifact and assemble all eight
   canonical bindings.
5. Upload the redacted readback artifact and record only its artifact ID and
   raw ZIP digest in each consuming environment.
6. Have the publisher independently download and validate that artifact, then
   publish the initial controller bundle.
7. Read back the controller bundle artifact ID and raw ZIP digest.
8. Produce an ordinary readback artifact bound to that exact controller tuple
   and replace only the two small pointer variables.
9. Have `Verify Test Cloud` independently validate and materialize the ordinary
   artifact, then run against the successful source `Verify Main` tuple.

## Failure and retry behavior

Every failure is terminal for the current workflow run and emits one safe
allowlisted `BLOCKED_*` code. No credential-bearing request is retried
automatically. A new manual run is required after a code or environment fix.
Failures never weaken validation, substitute repository fixtures, or reuse an
expired attestation.

## Testing

Tests must cover:

- exact allowlisted HTTP paths, methods, and credential classes;
- no credential read before fixed-target validation;
- no recovery or production name in workflow environment mappings;
- secret redaction from success and all failure paths;
- runner-variable and identity digests from realistic provider responses;
- nonzero session rejection;
- Site/Function/lease mismatch rejection;
- synthetic or placeholder browser-policy rejection;
- initial and ordinary hosted binding production;
- canonical JSON/digest parity and attestation validity windows;
- workflow trigger, environment, runner, action pins, and artifact name.

Completion requires focused tests, the complete standalone controller test
suite, controller validation on the public PR, independent artifact readback,
and a real `Verify Test Cloud` PASS. A local PASS alone is not completion.
