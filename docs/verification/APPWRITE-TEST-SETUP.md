# Appwrite Test Environment Setup

Status: `IN_PROGRESS` for Appwrite Test only. The protected read-only producer,
binding-artifact verifier, controller publisher, and hosted verification
workflow are implemented in the public controller repository at
`eeaaaf7619bdac124101cfb1d8c628e8447d83be`. Final activation still requires a
successful source-`main` `Verify Main` artifact, an ordinary provider readback,
the immutable controller bundle, and a successful `Verify Test Cloud` run.
Nothing in this procedure authorizes or targets production.

## Fixed test identity

The only allowed environment is the composite identity recorded in `dev/verification/environments/test-cloud.inventory.v1.json`:

- endpoint `https://fra.cloud.appwrite.io/v1`;
- project ID `69137c5d003952a36d4c`;
- Site ID `694579860016df0d2d3c`;
- public origin `https://appwritework.appwrite.network`;
- environment class `appwrite-cloud-test`.

Preflight must reject every production endpoint, project, Site, origin, host suffix, or production credential name before client construction.

This test Site follows source branch `main`. The separate production Appwrite
project `69eb4818000afa64a7fa` and production Site
`69eb4a020024c520642e` follow branch `production` and are outside this setup.
Merging or deploying the test lane must not activate, configure, or read a
production credential or deployment.

## Controller generation boundary

Appwrite Test consumes one protected controller generation; it does not consume
working-tree controller code or the AppWriteWork authoring copy directly. The
candidate must come from the deterministic source-set materialization described
in [REPOSITORY-BOUNDARIES.md](REPOSITORY-BOUNDARIES.md), pass protected
controller review, and publish an immutable bundle before Test Cloud execution.
Browser product files, the local `packages/salmora-mcp` stdio bridge,
and secret-bearing paths are excluded from this promotion scope. Existing
production workflows remain in the complete controller closure and must be
preserved byte-for-byte; this Test Cloud change may neither omit nor modify
them.

Treat `TRUSTED_CONTROLLER_SHA`, controller artifact ID/digest, binding artifact
ID/digest, source revision, and runner revision as one atomic tuple. Environment
variables and binding evidence must be rotated and independently read back as
one generation. Any mixture of old and new fields blocks setup and hosted
verification; selecting the newest artifact or reusing an earlier successful
readback is forbidden.

## Phase A handoff and pending-value rules

The Appwrite setup belongs after controller-repository protection, unchanged
non-default-ref seed transfer, immutable A1 OCI qualification, and protected PR
merge. The exact local inputs are
`sourceRepositoryRevision=b29df5c65a6a93125bcbf6d40915b949a973f89d`,
`CONTROLLER_SEED_SHA=34b279996e609efe60f57f60cab60211a2a05c99`,
`seedTreeDigest=sha256:72815731d3fc8efe7dd8091f39b50143d81b2a9f07cf3257553c2f714107fcc6`,
and
`closureDigest=sha256:6fac1fe8ea27e2ba1064a62cae634349f6602760d1058bf62d5c7b262a8d5d9e`.
The complete archive, provenance, tree, and manifest evidence is recorded in
[CONTROLLER-SETUP.md](CONTROLLER-SETUP.md#phase-a-to-b1-bootstrap-handoff).

Locally generated fields use those exact values. A nonsecret field that needs
an operator choice uses only `PENDING_USER` until selected. A GitHub, GHCR, or
Appwrite-assigned field uses only `PENDING_PROVIDER` until independent
readback. Secret fields are absent from handoff/readback templates rather than
represented by placeholders; only secret names and approved scope sets may be
recorded.

Before seed transfer, B1 must already create and protect the empty
`appwrite-test` and `controller-promotion` environments and independently read
back their IDs and reviewer/self-review policies. After GitHub App and Appwrite
resources exist, B1 populates those same environments with nonsecret values and
name-only secret bindings. This sequencing does not permit environment
population before provider readback or seed transfer before environment
protection.

## Required resource delta

Under separate authority, create or read back exactly:

- database `verification_control`;
- lease table `verification_leases` and singleton row `appwrite_test_verification`;
- intent projection table `verification_intents`;
- append-only audit table `verification_audit_events`;
- private test-only Function `verification-runner-py`, runtime Python 3.12, entrypoint `main.py`;
- three preprovisioned identities: owner, editor, and viewer, all with empty session sets;
- the fixed product Function and Site targets already declared in the inventory.

The Task 10 cleanup/recovery delta is additive and still non-executing. A later
authorized readback must prove the v2 intent cleanup/execution fields,
`verification-recovery-checkpoint.v1` shape, closed audit transition set, and
private recovery job surface before any hosted recovery or cleanup can run. The
delta does not permit broad table columns, generic row IDs, provider defaults,
or inferred permissions.

The environment inventory alone deliberately does not define a provider
column/index layout. Task 5A now supplies a repository-local desired ABI in the
authenticated provider contract, but that desired ABI is not evidence of the
current cloud resources. Every live column type/size/default/required flag,
every index key/order/type, permissions, and the canonical schema readback
digest remain mandatory separately authorized inputs. They must not be inferred
from code, tests, an Appwrite default, or an existing table. Until live readback
matches the approved descriptor, setup and the hosted lane remain `BLOCKED`.

The controller owns acquisition, controller-side transitions, cleanup, and lease
close. The private runner has one delegated write path: it may commit only the
version-2 planned and version-3 inner-observed `primary-execution` snapshots
and their exact hash-chained events, projection, and lease head. The controller
must reconcile that exact two-event tail before adding the outer Execution ID in
version 4. No generic row mutation is permitted.

## Task 5A local TablesDB ABI baseline

The repository-local desired control ABI is exact:

| table | exact application columns | authority/readback note |
| --- | ---: | --- |
| `verification_leases` | 12 | exact full control descriptor |
| `verification_intents` | 27 | 34 physical authority keys after the seven TablesDB system keys are included |
| `verification_audit_events` | 11 | exact full control descriptor and 28-member transition enum |

An ordinary logical v2 intent projection has 25 keys. A recovery v2 projection
has 26. The only storage alias is
`cleanupRunnerExecutionRetentionExpiresAt` (logical) to
`cleanupRunnerExecutionRetentionAt` (physical); both names in one projection
are invalid. The audit transition/resource matrix has 17 exact rows: ordinary
intent lifecycle transitions retain their v1/v2 resource split, observation
transitions are exclusive to `primary-execution`, share-issue transitions are
exclusive to `primary-share`, and all five cleanup/recovery intent transitions
are exclusive to `primary-project`, `primary-graph`, and `primary-share`.

Task 5A also authenticates the required application-name subsets used in each
core product table: `projects` 11, `project-shares` 7,
`project-snapshots` 1, `project-artifacts` 19,
`project-artifact-versions` 18, and `project-artifact-references` 1. These are
exact contract-array cardinalities with `runtime-required-subset` coverage.
They are not claims that the physical product tables contain only those
columns, and they do not locally prove the types, sizes, indexes, defaults,
permissions, or additional product fields of those tables.

The desired local ABI additionally pins dense mutation ordinals `0..18`, the
project/graph/share resource order, each resource's owned-slot/member-template
order, 16 exact member binding/provider-kind tuples, and 19 exact provider
routes. These repository checks prevent cross-table or route substitution; they
still do not substitute for live provider schema readback.

Qualification fails closed above a 4.5 MiB (4,718,592-byte) provider-contract
parity-corpus file or a 4 MiB (4,194,304-byte) decoded payload. The physical
boundary also enforces the Appwrite 36-character ID ceiling, 128-character
run/resource ceilings, dependency order at most 100, signed-32-bit version
bounds, real Gregorian instants, and runtime-safe integer positions. Outer
millisecond UTC datetimes may arrive as `Z` or `+00:00` and normalize to `Z`;
an inner runner-slot retention timestamp must already be canonical `.sssZ`
because it is digest-bound.

The persisted aggregate phase is a parser-compatibility state, not cleanup
proof. Intents may retain an authenticated stable aggregate while their ledger
state moves through `cleaning` or `absent`; semantic completion comes only from
the ordered cleanup proof/execution/checkpoint chain. Recovery absence preserves
the predecessor aggregate. A public stable-present aggregate remains
deliberately `BLOCKED` until a trusted runtime supplies the raw identity and
permission preimages omitted from the safe projection.

Local GREEN therefore means only that repository bytes implement this desired
ABI and that the six core required-name subsets agree across the authenticated
contract and adapters. Appwrite Test still needs independent readback of the
complete current control and core table descriptors, including all types,
sizes, defaults, indexes, permissions, row-security state, extra columns, and
schema digests. No local result in this section is cloud setup, deployment,
hosted execution, or production evidence.


## Execution retention and observation readback

Before the execution scenario can run, protected setup must read back a closed
provider policy proving provider-managed retention, read-only observation, and a
positive maximum retention no greater than the repository limit of 86,400
seconds. The exact readback shape is
`appwrite-execution-observation-readback.v1`; its canonical digest and actual
`retentionMaxSeconds` value are carried through the branded setup attestation,
preflight handoff, lease capability, runner request, authoritative chain
reconstruction, lease close, and recovery context. A safe provider maximum from
1 through 86,400 seconds is accepted, and every version-3 expiry must be no later
than `createdAt + retentionMaxSeconds`; accepting 3,600 and later recording 3,601
seconds is a blocking mismatch. A static repository constant, inferred provider
default, copied qualification, write-capable cleanup path, missing value, or
overbound value does not qualify. Provider-retained executions are never deleted by fixture cleanup and
do not create fixture cleanup debt.

## Disjoint API keys

Provision and read back only these named keys and exact scopes:

- `APPWRITE_TEST_OPERATOR_API_KEY`: `execution.write`, `functions.read`, `functions.write`, `sites.read`, `sites.write`;
- `APPWRITE_TEST_FIXTURE_API_KEY`: `rows.read`, `rows.write`, `users.read`, `users.write`;
- `APPWRITE_TEST_RECOVERY_API_KEY`: `rows.read`, `rows.write`, `users.read`, `users.write`, stored only in a separate recovery environment/job.

No generic `APPWRITE_API_KEY`, production key, project-admin key, session key, or broader scope is allowed. The private runner receives only its separately documented least-privilege runtime variables and permissions. Its execute permission must be private to the trusted controller path.

## Protected setup binding artifact

The canonical provider setup contract and the hosted setup contract are
separate, independently digested and attested inputs. Their eight canonical
values are stored as files in one immutable seven-day GitHub Actions artifact,
not as GitHub variables or a single process environment block:

- `TEST_CLOUD_SETUP_READBACK_JSON`
- `TEST_CLOUD_SETUP_READBACK_DIGEST`
- `TEST_CLOUD_SETUP_ATTESTATION_JSON`
- `TEST_CLOUD_SETUP_ATTESTATION_DIGEST`
- `TEST_CLOUD_HOSTED_SETUP_READBACK_JSON`
- `TEST_CLOUD_HOSTED_SETUP_READBACK_DIGEST`
- `TEST_CLOUD_HOSTED_SETUP_ATTESTATION_JSON`
- `TEST_CLOUD_HOSTED_SETUP_ATTESTATION_DIGEST`

The artifact contains exactly those eight `<NAME>.txt` files plus
`evidence.json` and `binding-manifest.json`. The manifest binds every member
digest, controller revision, source revision, source workflow run ID/attempt,
runner revision, initial/ordinary mode, and—after first publication—the
controller artifact ID and raw ZIP digest. The protected verifier downloads
only the explicitly selected artifact, validates its raw ZIP digest and exact
ten-member set, rejects links/extras/noncanonical bytes, and materializes only
the eight binding files into a private runner directory.

Configure only these two small nonsecret environment variables in
`appwrite-test` and `controller-promotion`:

- `TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_ID`
- `TRUSTED_TEST_CLOUD_BINDING_ARTIFACT_DIGEST`

Do not copy the eight large values into GitHub variables. Do not collapse the
provider and hosted JSON roots into one binding. The protected publisher and
runner qualification may consume them only after the corresponding
independently read bytes, canonical digests, and attestations agree.

The provider pair remains bound to `test-cloud.setup-readback.v1`. The hosted
pair is independently bound to `test-cloud.hosted-setup-readback.v1` and its
attestation. Derive `executionObservationPolicyDigest` and
`primaryExecutionRetentionMaxSeconds` only from those independently read hosted
bytes; copying either field from provider setup bytes, local inventory, or a
caller-supplied value is a blocking mismatch.

There is one closed bootstrap exception before the first controller artifact
exists. `test-cloud.hosted-prepublication-readback.v1` proves the same exact
Appwrite Test resources, scopes, runner, GitHub App, empty identity sessions,
controller protections, and execution-observation policy, but omits
`controller.bundle` and `bootstrap`. Its `initialSeed` contains only the exact
source revision, exact controller revision, and the approved
`single-maintainer` mode. Placeholder artifact IDs or digests are invalid. The
publisher accepts this shape only with `initial_seed=true`; after the upload,
independent provider readback must replace it with the ordinary full hosted
shape before `Verify Test Cloud` can run.

## Identity and session readback

Read back owner/editor/viewer identity IDs and role fixtures without exposing IDs in source artifacts or evidence. Prove that all three preprovisioned identities have empty session sets before every run. Fixture creation is prohibited in the ordinary lane. Any unknown identity, nonempty session set, ambiguous cleanup, or unmatched intent persists debt and blocks the next lease.

## Controller prerequisites

Before setup can become eligible, read back:

- public, secret-free controller repository
  `Krowaccie/AppWriteWork-verification-control` and public A1 OCI package;
- GitHub Free profile: standard GitHub-hosted runners only, seven-day Actions
  artifact retention, and `workflow_dispatch`-only credentialed workflows;
- rulesets, CODEOWNERS, required reviewers, and self-review prevention;
- protected environments `appwrite-test` and `controller-promotion`;
- exact GitHub App installation and read-only source permissions;
- exact full-SHA controller tuple and immutable bundle digest;
- approved first bootstrap seed governed by the previous controller or the explicit first-seed trust ceremony;
- ordinary workflow concurrency `appwrite-test-verification`, `cancel-in-progress: false`, and no recovery key mapping.

## Offline validator

The only setup command authorized by this repository implementation is the dry, non-mutating validator:

`node scripts/verification/test-cloud-setup-check.mjs --offline --inventory dev/verification/environments/test-cloud.inventory.v1.json`

It must return `BLOCKED` until every exact inventory field, provider schema contract, schema readback digest, execution retention/read-only observation proof, cleanup/recovery schema delta, table/Function permission, API-key scope, identity empty-session proof, controller tuple, GitHub App, protected environment, ruleset, and bootstrap seed is supplied by readback. It must never create, update, delete, deploy, invoke, or recover a cloud resource.

## Evidence required after a later authorized setup

Capture a redacted immutable readback containing resource IDs already declared
nonsecret, schema and permission digests, key names/scopes without values,
identity-role digests without raw IDs, empty-session counts, cleanup/recovery
schema and checkpoint digests, controller tuple, workflow/ruleset/environment
IDs, first-seed record, timestamp, operator/reviewer identities, and the exact
authority reference. Independent review must compare this record to the
approved descriptor before any protected publisher use or test-cloud
execution.

The bootstrap readback starts as `PENDING_B1`. It becomes eligible for A2 only
after it is marked `COMPLETE_B1`, contains no `PENDING_USER` or
`PENDING_PROVIDER` sentinel, and records `MATCH` for every closed consistency
check. Those checks independently compare controller/source revisions,
artifact bindings, both setup binding families, hosted-byte derivation, exact
GitHub/Appwrite targets, the GitHub Free profile, the checked-in A1 platform
tuple, and the full
immutable `ghcr.io/...@sha256:<64-hex>` reference. Schema validity alone does
not establish those cross-field equalities.

B1/Appwrite Test activation does not authorize recovery or any production
operation. The separate production project `69eb4818000afa64a7fa`, production
Site `69eb4a020024c520642e`, and `production` branch remain explicitly pending
for a later, separately approved procedure. The current test-only closeout may
publish the credential-free source artifact and run the protected Appwrite Test
controller after the required source-`main` gate is satisfied.
