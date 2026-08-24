# Trusted Verification Controller Setup

Status: Appwrite Test controller bootstrap is implemented and the public
controller is protected at
`eeaaaf7619bdac124101cfb1d8c628e8447d83be`. The remaining test-only sequence is
source-`main` artifact publication, protected readback collection, controller
bundle publication, ordinary readback collection, and `Verify Test Cloud`.
Recovery and every production operation remain outside this procedure.
This document does not authorize recovery, production deployment, production
release, or rollback execution.

## Fixed repositories and workflows

- Application source: `Krowaccie/AppWriteWork`.
- Protected controller: `Krowaccie/AppWriteWork-verification-control`.
- Source workflow name/path: `Verify Main` / `.github/workflows/verify-main.yml`.
- Controller test workflows: `collect-appwrite-test-readback.yml`,
  `publish-controller-bundle.yml`, and `verify-test-cloud.yml`. Production
  templates remain separate and inactive.
- `Verify Main` remains credential-free. Pull requests run only local verification; `push` to `main` and `workflow_dispatch` may publish only `verification-artifacts-<40-character-revision>` through the protected action at `eeaaaf7619bdac124101cfb1d8c628e8447d83be` and still receive no controller, Appwrite, release, or browser credential.

The controller repository must have a default-deny ruleset, CODEOWNERS approval for controller code, schemas, workflows, policies, and the lockfile, required reviewers, prevent self-review, required status checks, signed or otherwise policy-approved commits, and deletion/force-push protection. Record repository ID, workflow IDs, ruleset IDs, CODEOWNERS digest, and effective policy readback.

## Deterministic source-to-controller promotion boundary

AppWriteWork is the controller authoring authority; the protected controller
repository is the runtime trust authority. A controller candidate must be
materialized from one exact committed source revision using the closed
`controller-seed-source-sets.v1` descriptor and its fixed relocations. The
read-only source sync comparison must reject unknown, duplicate, missing,
escaping, symlinked, or unclassified inputs. Product web, local MCP,
and secret-bearing paths are outside the controller candidate and make
descriptor validation fail closed. Existing production workflows stay in the
full controller closure but must be exact and are excluded from this Test Cloud
change; missing or differing production workflow bytes remain unresolved.

Do not copy either repository wholesale. If protected controller bytes differ,
the conservative mismatch classification requires provenance review; it does
not prove that either side is a hotfix. A confirmed load-bearing direct
controller hotfix must be backported to its AppWriteWork authoring path before
the next promotion. The final materialized candidate requires zero unresolved
provenance/backport records. Test-only validation bytes may enter the seed
validation closure but not the signed runtime bundle, and must still match
exactly. See [REPOSITORY-BOUNDARIES.md](REPOSITORY-BOUNDARIES.md).

## Offline source-artifact launcher foundation

The A1 foundation is implemented and locally contract-tested. The trusted hosted artifact launcher
is installed as a protected controller action at full SHA
`eeaaaf7619bdac124101cfb1d8c628e8447d83be` and pins the public OCI image by
immutable digest. The source workflow remains credential-free; hosted
eligibility is limited to the canonical main-bound request, and operational
proof requires an exact successful workflow/artifact readback.

The two serialized contracts are closed canonical JSON data:

- a request is at most 128 UTF-8 bytes and contains exactly `commandId` and
  `protocolVersion: source-artifact-launcher.v1`;
- a publication descriptor is at most 8 KiB and contains exactly
  `artifactManifestDigest`, `artifactName`, and `artifactPath`; its canonical
  absolute path is at most 4,096 UTF-8 bytes and is bound to the same full
  source revision as the artifact name.

The publication descriptor is information, not upload authority. The retained
output identity, root handles, identity-revalidation operation, and bounded
stream capability stay private to the parent session and are invalidated by
close. No path, glob, retention setting, credential, callback, provider
identifier, or second-upload option is accepted from candidate data.

`openSession()` creates two disjoint ports. Candidate code receives only
`candidatePort.identity`, `candidatePort.workspace`, `runCommand`, and
`writeOutputMember`. It never receives the parent port, source/workspace
leases, handles, validator, publication sink, abort signal, or cleanup
capability. The parent alone owns `validateOutput`, optional
`publishValidatedOutput`, and `close`. The exact `repository`, `workflow`,
`sourceRef`, `sourceRevision`, `sourceTreeDigest`,
`verifierManifestDigest`, `workflowRunId`, and `workflowRunAttempt` values are
parent-derived expectations; candidate values can only be compared with them.

The trusted command map is exact and ordered:

| Order | Command ID | Parent-mapped executable and argv | cwd | Network |
| ---: | --- | --- | --- | --- |
| 1 | `root-npm-ci` | `npmExecutable ci --ignore-scripts --no-audit --no-fund` | `exportRoot` | `registry-only` |
| 2 | `web-npm-ci` | `npmExecutable ci --ignore-scripts --no-audit --no-fund` | `exportRoot/src/web` | `registry-only` |
| 3 | `bundle-catalog` | `nodeExecutable scripts/bundle-catalog.mjs` | `exportRoot` | `deny` |
| 4 | `typecheck` | `npmExecutable exec -- tsc -b --pretty false` | `exportRoot/src/web` | `deny` |
| 5 | `vite-build` | `npmExecutable exec -- vite build --outDir <siteOutput> --emptyOutDir` | `exportRoot/src/web` | `deny` |

Both executables are parent-pinned absolute regular non-link files;
`<siteOutput>` is a parent-created private path. Candidate data cannot change
argv, cwd, environment, shell mode, timeout, retry, or network mode.

Both npm inputs must be regular non-link lockfile-v3 files. Only the root
package record at `packages[""]` may omit `resolved` and `integrity`; every
external package record requires the exact `https://registry.npmjs.org`
origin and exactly one valid `sha512` integrity value. All weaker algorithms,
alternate origins, credentials, query data, redirects, mutable URLs, links,
aliases, and escapes block before a sandbox call.

After all five commands and all 39 output members arrive in order, the parent
calls `inspectTreeAtomically` and the closed
`validateSourceArtifactOutputSnapshot` validator. It verifies the exact Site,
35 release-eligible Functions, test-only runner, manifest, and handoff byte
set; canonical manifest and handoff bindings; repository/workflow/ref/
revision/tree/run/attempt identity; member digests; archive safety; and output
limits. A private retained identity is rechecked before descriptor emission
and around every future upload-stream chunk. Every failed path is
fail-closed. Cleanup seals/aborts the session, waits for quiescence, and closes
the authenticated workspace lease before the source lease; incomplete cleanup
takes diagnostic precedence.

Future hosted activation still requires separately approved values for these
tuple fields: trusted action repository, trusted action full commit SHA,
launcher protocol promotion binding, launcher executable SHA-256, platform
tuple, POSIX sandbox mechanism, canonical installation path outside the
checkout/output, update policy, complete transitive runtime/schema closure
digest, and promotion/owner review reference. This document supplies or
approves none of those values. The local fake source/filesystem/sandbox/upload
tests and static workflow guards are not hosted network-isolation evidence.

## Source artifact reader GitHub App

Create the GitHub App only under separate authority:

- slug: `appwritework-verification-artifact-reader`;
- installation scope: exactly `Krowaccie/AppWriteWork`;
- repository permission: `Actions: Read-only`;
- implicit permission: `Metadata: Read-only`;
- no other repository or organization permission;
- no user authorization and no webhook.

Store these nonsecret variables in each protected controller environment that reads a source artifact:

- `SOURCE_ARTIFACT_READER_APP_ID`
- `SOURCE_ARTIFACT_READER_INSTALLATION_ID`
- `SOURCE_REPOSITORY_ID`
- `SOURCE_VERIFY_MAIN_WORKFLOW_ID`

Store only `SOURCE_ARTIFACT_READER_PRIVATE_KEY` as the reader secret. Readback must prove the installation repository set and permission map are exact. The short-lived token stays in memory, is limited to the one source repository, is used only for repository/workflow/run/artifact GETs, and is revoked in `finally`.

## Archive intake limits

The trusted archive reader accepts archives no larger than 64 MiB, with no
single file larger than 32 MiB, expanded contents no larger than 128 MiB, and
at most 256 entries. It rejects links, executables, encryption, ZIP64, path
collisions (including case-insensitive collisions), corrupt or bomb archives,
and trailing data.

## Immutable controller tuple

Every hosted entrypoint must validate this tuple before mapping a credential:

- repository `Krowaccie/AppWriteWork-verification-control`;
- `TRUSTED_CONTROLLER_SHA`: one exact 40-character lowercase commit SHA;
- artifact name exactly `verification-controller-bundle-${TRUSTED_CONTROLLER_SHA}`, derived only from that full SHA and never selected by prefix, `latest`, or recency;
- `TRUSTED_CONTROLLER_ARTIFACT_ID`: immutable controller bundle artifact ID;
- `TRUSTED_CONTROLLER_BUNDLE_DIGEST`: `sha256:<64 lowercase hex>`.

The trusted controller fields and their binding are one atomic generation.
Rotate and read back the controller SHA, controller artifact ID/digest, binding
artifact ID/digest, source revision, and runner revision together. Never mix a
new SHA with an artifact or binding from a previous generation. Candidate
materialization, local sync, or a previously successful readback cannot make a
mixed tuple trusted.

The committed `controller-bundle.proposal.json` is non-promotable
`controller-bundle.proposal.v2` input. It carries only `UNMATERIALIZED`
sentinels. The protected B1 publisher must rebuild a final
`controller-bundle.v2` from exact committed controller blobs, distinct
source/controller revisions, same-run runner qualification, four canonical
trust materials, and provenance. It uploads direct members as exactly
`verification-controller-bundle-<trustedSha>`; the upload action creates the
only outer ZIP. Provider artifact ID and raw outer ZIP digest are readback-only
and never publisher inputs or local claims.

The checked-in proposal remains deliberately ineligible even though Task 4B
has produced the final standalone transfer seed. It must continue to use
`UNMATERIALIZED` for values that only protected B1 can produce. The final
`controller-bundle.v2`, its `controllerRevision`, the provider artifact ID, and
the provider-created raw outer-ZIP digest do not exist locally.

The executable boundary remains fail closed: source without an exact committed
revision returns `BLOCKED_UNCOMMITTED_SOURCE`, and the sentinel proposal cannot
validate as a final bundle and returns `CONTROLLER_BUNDLE_INVALID`. Task 4B seed
evidence does not weaken either result.

The source repository exposes only the pure `materializeControllerBundleProposal` contract. It accepts a closed sentinel proposal, an independently selected exact full commit SHA, the exact sorted byte set for every declared file and schema with no missing, extra, duplicate, or escaped path, and the four fixed trust-material byte fields `transcriptCorpus`, `evaluator`, `networkPolicy`, and `evidenceValidator`. It computes deterministic digests and returns inert manifest data only. It never reads Git, the working tree, or the filesystem; never writes the manifest; and cannot package, publish, promote, or advance a controller tuple. A later separately authorized trusted post-commit reader must obtain every byte from that exact committed revision and independently verify the generated output before promotion review.

## Phase A to B1 bootstrap handoff

Task 4B produced two byte-identical final local materializations. The B1
operator must bind every transfer and readback comparison to this exact
secret-free evidence:

| Field | Exact local value |
| --- | --- |
| `sourceRepositoryRevision` | `b29df5c65a6a93125bcbf6d40915b949a973f89d` |
| `sourceRootDigest` | `sha256:179e9ebfb852db0cbf4ae85f87c3b430be819fa58d39147bf780f9a3d4f1a923` |
| `CONTROLLER_SEED_SHA` | `34b279996e609efe60f57f60cab60211a2a05c99` |
| Git tree OID | `7e070b86ffaa49a789d5794d62c7c19496344dbd` |
| `seedTreeDigest` | `sha256:72815731d3fc8efe7dd8091f39b50143d81b2a9f07cf3257553c2f714107fcc6` |
| `closureDigest` | `sha256:6fac1fe8ea27e2ba1064a62cae634349f6602760d1058bf62d5c7b262a8d5d9e` |
| `internalManifestDigest` | `sha256:9f3b3396e380b6d3941cd712e306aac8fa968b49a2534db2d48fa70ddd522943` |
| Seed archive | `docs/plans/codex/artifacts/2026-08-14-verification-control-seed/run-a-b29df5c-final/artifacts/controller-seed.v1.tar` |
| `archiveDigest` | `sha256:8ef6824a6c53495ca00595389580c3931a8b19ce205c90c21cde0e909d6acdbd` |
| External provenance manifest | `docs/plans/codex/artifacts/2026-08-14-verification-control-seed/run-a-b29df5c-final/artifacts/seed-provenance-manifest.v1.json` |
| `externalProvenanceManifestDigest` | `sha256:fa7764d6beca06429922e046543f784ce977f0ebd1ea04fa56cce6c3fdf8af75` |
| `twoRunByteEquality` | `true` |

The B1 handoff and readback also pin these target identities: GitHub App slug
`appwritework-verification-artifact-reader`; source workflow
`.github/workflows/verify-main.yml` named `Verify Main`; Appwrite endpoint
`https://fra.cloud.appwrite.io/v1`, project `69137c5d003952a36d4c`, Site
`694579860016df0d2d3c`, and origin
`https://appwritework.appwrite.network`. The exact A1 platform tuple is the
checked-in `verification-a1-platform-tuple.v1` policy: Linux x64 on
`ubuntu-24.04`, installation root `/opt/appwritework/verification-a1`, the
external POSIX supervisor/workspace-kernel protocols, and immutable-image-
digest-only updates. These are fixed local target identities, not operator
choices.

The controller uses the GitHub Free compatibility profile. The controller
repository and A1 OCI package are public, while every committed file, workflow
log, artifact, and package byte is classified `PUBLIC_SECRET_FREE`. Only
standard GitHub-hosted runners are eligible, Actions artifacts and logs retain
for seven days, and credential-bearing workflows accept only
`workflow_dispatch`. Pull-request validation remains secretless. Protected
environment secrets are never exposed to fork or pull-request execution. This
keeps the two-repository trust boundary without requiring a paid GitHub plan.

`CONTROLLER_SEED_SHA` is a deterministic parentless transfer commit. It may be
pushed unchanged only to a non-default transfer ref. It is never
`controllerRevision` or `TRUSTED_CONTROLLER_SHA`. The protected controller PR
must start from the governance-only default branch, apply the exact seed tree,
and add the final `action.yml` pinned to the qualified immutable OCI digest.
That reviewed PR commit must differ from `CONTROLLER_SEED_SHA`; only the exact
40-character commit produced through the protected merge and verified by
readback may become `TRUSTED_CONTROLLER_SHA`.

Perform B1 in this order under its own separate authority:

1. Create public, secret-free, and protect
   `Krowaccie/AppWriteWork-verification-control`, including its governance-only
   default branch, restricted Actions policy, CODEOWNERS, required
   checks/review, branch protection, and self-review prevention. Configure
   standard GitHub-hosted runners only, seven-day artifact/log retention, and
   manual-only credential-bearing workflows.
   Create the empty protected `appwrite-test` and `controller-promotion`
   environments with reviewer policy at this point, then independently read
   back every repository, ruleset, workflow, environment, reviewer, and
   self-review-prevention identifier before any seed transfer.
2. Push the unchanged `CONTROLLER_SEED_SHA` only to a non-default transfer ref
   and compare the transferred commit and tree to every local value above.
3. Build and qualify public A1 OCI from that exact seed against the fixed local
   A1 platform tuple and record only its full immutable
   `ghcr.io/...@sha256:<64-hex>` reference.
4. From the protected governance default branch, open, validate, owner-review,
   and merge the controller PR that applies the seed tree and adds final
   `action.yml` pinned to the immutable OCI digest.
5. Read back the resulting full protected commit and record it as
   `TRUSTED_CONTROLLER_SHA` only after its tree and action digest match the
   reviewed PR.
6. Create and configure the least-privilege source-artifact-reader GitHub App
   and the exact Appwrite test resources and identities.
7. Populate the already protected `appwrite-test` and
   `controller-promotion` environments with independently read nonsecret
   variables and name-only secret bindings. Environment creation and reviewer
   protection occurred in step 1; this step does not recreate or weaken them.
8. Run the protected manual publisher at exactly `TRUSTED_CONTROLLER_SHA` after
   all preceding readbacks pass, uploading exactly
   `verification-controller-bundle-<TRUSTED_CONTROLLER_SHA>`.
9. Independently read back the workflow head, direct bundle-member inventory,
   materialized manifest, matcher-based
   `verification-runner-transcript-corpus.v2` digest, remaining trust-material
   digests, provider artifact ID, and provider-created raw outer-ZIP digest.
10. Only after that independent readback, populate
    `TRUSTED_CONTROLLER_ARTIFACT_ID` and
    `TRUSTED_CONTROLLER_BUNDLE_DIGEST` and approve the exact promotion tuple.

In B1 handoff/readback data, locally generated fields above use their exact
values. A nonsecret field that requires an operator choice uses only
`PENDING_USER` until selected. A field created or assigned by GitHub, GHCR, or
Appwrite uses only `PENDING_PROVIDER` until independently read back. Secret
fields and secret values are omitted entirely; secret names may appear only in
name-only inventories.

The checked-in readback template starts at `readbackState=PENDING_B1`. A2 may
consume only `readbackState=COMPLETE_B1`, with no pending sentinel anywhere and
all eleven closed consistency checks equal to `MATCH`. Independent comparison must
prove that protected merge, trusted controller, workflow head, manifest,
artifact ID/digest bindings, source revision, exact target identities, GitHub
Free profile, A1 tuple,
and full OCI reference agree. JSON Schema validation is structural evidence;
it is not a substitute for those provider readbacks and equality comparisons.

## Protected environments

### appwrite-test

Configure required reviewers and prevent self-review. Nonsecret variables contain only the immutable controller tuple, fixed Appwrite test identity, source repository/workflow IDs, and GitHub App IDs. Secrets are disjoint:

- `SOURCE_ARTIFACT_READER_PRIVATE_KEY`
- `APPWRITE_TEST_OPERATOR_API_KEY`
- `APPWRITE_TEST_FIXTURE_API_KEY`
- `E2E_OWNER_EMAIL` and `E2E_OWNER_PASSWORD`
- `E2E_EDITOR_EMAIL` and `E2E_EDITOR_PASSWORD`
- `E2E_VIEWER_EMAIL` and `E2E_VIEWER_PASSWORD`

The eight setup bindings below are immutable artifact members rather than
GitHub environment variables:

- `TEST_CLOUD_SETUP_READBACK_JSON`
- `TEST_CLOUD_SETUP_READBACK_DIGEST`
- `TEST_CLOUD_SETUP_ATTESTATION_JSON`
- `TEST_CLOUD_SETUP_ATTESTATION_DIGEST`
- `TEST_CLOUD_HOSTED_SETUP_READBACK_JSON`
- `TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST`
- `TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON`
- `TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST`

Configure only the artifact pointer in both `appwrite-test` and
`controller-promotion`:

- `TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_ID`
- `TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_DIGEST`

`collect-appwrite-test-readback.yml` creates the artifact from read-only
provider/GitHub projection. The artifact must contain exactly the eight
`<NAME>.txt` files, `evidence.json`, and `binding-manifest.json` and use seven-day
retention. The publisher and hosted controller download only the explicitly
selected artifact, verify its raw ZIP and member digests, and expose the eight
validated files through a private directory. This avoids GitHub's per-variable
and Windows environment-size limits without weakening the canonical binding
checks.

The first controller publication uses a closed prepublication variant rather
than inventing provider outputs that do not exist yet. Its hosted readback has
schema `test-cloud.hosted-prepublication-readback.v1`, omits
`controller.bundle` and `bootstrap` entirely, and carries only the exact
`initialSeed.sourceRepositoryRevision`, `initialSeed.controllerRevision`, and
the approved `initialSeed.approvalMode=single-maintainer`. Provider artifact
IDs and bundle digests are forbidden in this variant. The publisher may select
it only with `initial_seed=true`, and it must compare both revisions to the
workflow inputs before materialization. After upload, independent provider
readback replaces this variant with the ordinary
`test-cloud.hosted-setup-readback.v1` binding containing the real artifact ID
and digest; every later publication uses `initial_seed=false`.

The ordinary lane must not map `APPWRITE_TEST_RECOVERY_API_KEY`. Recovery is a separate approved job. Concurrency is `appwrite-test-verification`, automatic cancellation is disabled, timeout is 45 minutes, and the controller never receives a production credential.

`executionObservationPolicyDigest` and
`primaryExecutionRetentionMaxSeconds` must be derived from independently read
bytes in `TEST_CLOUD_HOSTED_SETUP_READBACK_JSON` and bound by the distinct
hosted readback/attestation digests. They must not be copied from
`TEST_CLOUD_SETUP_READBACK_JSON`, repository inventory defaults, or publisher
inputs. The ordinary provider setup bindings retain
`test-cloud.setup-readback.v1`; the hosted setup bindings retain their separate
hosted schemas.

The source-tree `test-cloud-cleanup-protocol-v1` mapping is local proposal
evidence only. A promoted controller may consume it only after the exact
controller bundle is materialized from a committed SHA, the ordinary workflow
still excludes the recovery key, and a separately approved recovery job maps
`APPWRITE_TEST_RECOVERY_API_KEY` only for supervised lease recovery. The current
application repository must not run the recovery job, copy secrets, import
candidate modules into the protected process, or infer hosted activation from
local fake-transport PASS results.

The current successor workflow is active only through manual
`workflow_dispatch` in `appwrite-test`. It maps the exact source-reader,
Appwrite Test, and E2E identity secrets only after the controller artifact and
binding artifact have passed their independent verifiers. The ordinary lane
never maps the recovery credential. The reviewed live process containment uses
the Windows Job Object helper. Candidate checkouts and source artifacts remain
inert data and are never imported or executed as controller authority.

### controller-promotion

Configure required reviewers and prevent self-review. The previous trusted controller validates the successor lock, bundle, schemas, scenarios, negative corpus, evaluator, network policy, evidence validator, and exact full SHA. A human reviewer approves that same SHA. Candidate code can create only inert proposal data; it cannot advance the tuple.

Initial seeding is a manual trust ceremony. For this single-maintainer
repository, the explicitly approved exception is
`approvalMode=single-maintainer`; it still requires the exact first SHA,
independent local validation, protected-environment readback, provider artifact
readback, and an immutable evidence record. It does not create a reusable
self-approval path: after the first provider artifact exists, the ordinary
full readback is mandatory.

### production-readonly

Configure required reviewers and prevent self-review where supported. Map `APPWRITE_PRODUCTION_READONLY_API_KEY` only in the `production-metadata` job, with exact Appwrite scopes `sites.read` and `functions.read`. Configure the nonsecret `TRUSTED_PRODUCTION_RELEASE_RECORD_ARTIFACT_ID` as one exact positive numeric artifact ID. Scheduled and manual read-only runs fail closed when that pointer is absent or malformed and never infer the newest or latest record. Updating and reading back the pointer after a qualifying release is a separate trusted post-release action that is not implemented or authorized here.

The GitHub-only `release-record-handoff` job maps only its job-scoped `GITHUB_TOKEN`, verifies the exact protected release record, and uploads the canonical `verified-release-record-handoff.v1.json`. The Appwrite-only `production-metadata` job downloads that artifact by the exact upload artifact ID, then a secretless step validates its exact canonical bytes, self-field-free digest, controller tuple, current workflow run/attempt, release binding, and record before the first Appwrite credential mapping. The credentialed policy process revalidates the same file and expected digest before reading the Appwrite key, then emits only the closed browser policy. The Playwright browser job remains secretless. No job or invoked process maps both credentials, and no execution, login, session, row, storage, write, or release scope is allowed.

### production-release

Configure required reviewers and prevent self-review. Source-read, Appwrite release, and GitHub publication jobs keep credentials disjoint:

- source-read: the four source variables plus `SOURCE_ARTIFACT_READER_PRIVATE_KEY`;
- Appwrite release: only `APPWRITE_PRODUCTION_RELEASE_API_KEY`, scoped exactly to `sites.read`, `sites.write`, `functions.read`, and `functions.write`;
- release-record publication: only the controller job `GITHUB_TOKEN` with `deployments: write`.

The production release key has no execution, logs, database, row, storage, account, session, domain, or project-administration permission. Production never deploys or invokes `verification-runner-py` and requests no `execution.write`.

## Successor promotion and rollback

1. Materialize a successor bundle for one committed SHA without credentials.
2. Have the previous trusted controller validate the closed manifest and all pinned bytes in a secretless sandbox.
3. Obtain required human approval naming the same SHA and bundle digest in `controller-promotion`.
4. Under separate promotion authority, update the protected tuple once.
5. Perform repository, environment, artifact, full-SHA, digest, ruleset, CODEOWNERS, and workflow readback.
6. Preserve the prior tuple as immutable rollback evidence.

Rollback means a separately authorized pointer change to one previously validated tuple. It is not a candidate-triggered mutation, automatic retry, or bypass of review.

## Dry validation and readback record

Before any hosted use, record and independently compare:

- repository, workflow, GitHub App, installation, ruleset, environment, reviewer, and self-review-prevention IDs;
- exact variables and secrets by name only, never secret values;
- effective GitHub App permission/repository response;
- exact controller SHA, artifact ID, archive digest, manifest digest, lockfile digest, and every declared content digest;
- workflow action/image pins, concurrency, timeout, environment, and absence of a recovery credential in the ordinary lane;
- Appwrite key scope readback, composite environment identity, fixed logical targets, and test/production separation;
- source artifact repository/workflow/run/attempt/ref/revision/name/digest;
- setup checker output and independent reviewer result.

Record the result in
`docs/verification/controller-bootstrap-readback.v1.json.template` and validate
it against its schema. Only a separately reviewed `COMPLETE_B1` instance is
eligible for A2; the checked-in `PENDING_B1` template is intentionally
ineligible.

The source workflow contract now pins the protected hosted launcher action at full SHA `eeaaaf7619bdac124101cfb1d8c628e8447d83be`; that action pins `ghcr.io/krowaccie/appwritework-verification-a1@sha256:a752173ccf4649dd5e453990a40ea2e6f4b61dbd1da6ae018e3424cab70645b4`. `Verify Main` pins Node `24.11.1`, asserts npm `11.6.2`, and invokes the launcher only on `push` to `main` or `workflow_dispatch`, after local verification. Do not claim final Appwrite Test readiness until the exact source artifact, binding artifact, controller bundle, and hosted verification readbacks succeed.

The launcher protocol remains closed to exactly five candidate command IDs: `root-npm-ci`, `web-npm-ci`, `bundle-catalog`, `typecheck`, and `vite-build`. Candidate code cannot choose executable paths, argv, cwd, inherited environment, network mode, timeout, registry, output path, or upload path.

The active closeout is test-only. Source-`main` publication remains a distinct
repository-policy gate; after it succeeds, the protected collector, publisher,
and hosted Appwrite Test workflow may complete the approved lane. Recovery,
production read-only execution, production release, and every mutation of the
separate production project/Site/branch remain blocked pending their own plan
and authority. Local or test-cloud evidence must never be presented as
production proof.
