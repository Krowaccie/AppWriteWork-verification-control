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
- map only `APPWRITE_TEST_OPERATOR_API_KEY` and
  `APPWRITE_TEST_FIXTURE_API_KEY`;
- accept exact controller SHA, source SHA, initial-seed mode, and a canonical
  source-policy input artifact;
- upload one artifact named
  `appwrite-test-setup-readback-<controller-sha>-<source-sha>`;
- upload only the eight binding values and sanitized evidence;
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

The source-policy artifact is secret-free data. Its generation can occur on
the source feature branch before source `main` moves, but the hosted verifier
will independently compare its first 25 rows to the exact source artifact
published by `Verify Main`.

## Data flow

1. Generate the source-browser policy from the exact candidate source SHA.
2. Dispatch the protected readback workflow at the exact controller SHA.
3. Read Appwrite Test state using disjoint operator and fixture credentials.
4. Assemble and self-validate the eight canonical bindings.
5. Upload only the redacted readback artifact.
6. Independently download and validate the artifact by ID and digest.
7. Set the eight values in `appwrite-test` and `controller-promotion` as
   required by their consuming workflows.
8. Dispatch the initial controller publisher.
9. Read back the uploaded controller artifact ID and raw ZIP digest.
10. Produce the ordinary hosted binding and replace the initial hosted pair.
11. Run `Verify Test Cloud` against the successful source `Verify Main` tuple.

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

