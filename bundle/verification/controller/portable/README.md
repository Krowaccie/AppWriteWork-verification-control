# Portable independent verifier preparation

This directory replaces Cloud-specific controller intake for locally prepared
portable verifier generations. All product audits are explicitly on demand.
Controller fixture validation can run on controller PR/push; it never fetches a
product repository, dispatches an audit or deploys a product.

## Export and review

Use Node 24.11.1. No npm package installation or Cloud credentials are required.
Prepare a new **nonexistent** owned output directory:

```text
node verification/controller/portable/cli.mjs export --source <absolute-repository> --output <absolute-new-bundle>
node <bundle>/verification/controller/portable/cli.mjs verify --bundle <bundle> --digest sha256:<reported-manifest-digest>
node <bundle>/verification/controller/portable/cli.mjs review-template --bundle <bundle> --digest sha256:<reported-manifest-digest> --output <external-new-pin.json>
```

`source-set.v1.json` is an explicit finite verifier-only export. Product sources,
private fixtures/configuration, node_modules and Git metadata are excluded. File
paths, sizes, digests, import closure, source revision and before/after source
bytes are checked. Symlinks, hardlinks, extra entries and common embedded secret
formats are rejected. The source identity distinguishes the base Git revision
from exported working-tree bytes; a dirty export is never described as the exact
contents of a commit. No archive extraction is necessary.

The template has `review.decision=PENDING` and cannot run a pinned audit. A human
or authorized independent reviewer must review the exact manifest/files, positive
and known-bad fixtures, record qualification digest/reference and explicitly
approve that pin. The pin is a local trust choice, **not** a signed attestation or
proof that a particular human reviewed it. Store it outside the product candidate.
Do not automatically update or approve a pin after a passing checker self-test.

Rebuild after every verifier/registry/retirement change and independently review
the new digest. P5 exports are provisional; final activation follows P6/P7 and
the exact P8 publication/readback procedure. This code never activates a remote pin.

For the separate controller repository, place the exact export under `bundle/`;
place the two reviewed templates from `verification/controller/workflows/` under
`.github/workflows/`. Review that outer publication packet separately. Configure
the reviewed digest (`PORTABLE_VERIFIER_BUNDLE_DIGEST`) and controller commit
(`TRUSTED_CONTROLLER_SHA`) before manually publishing. Do not copy the product.

## Explicit local invocation and current trust limit

Run the CLI from the verified bundle, using a fresh evidence directory outside
both candidate and verifier. Images must use immutable SHA-256 references:

```text
node <bundle>/verification/controller/portable/cli.mjs run --bundle <bundle> --pin <external-pin.json> --candidate <absolute-product> --output <new-external-evidence> --node-image node@sha256:<digest> --python-image python@sha256:<digest>
```

The fixed profile is `repository`; optional `--group` produces only a capability
shard. Candidate registries and hooks are never loaded into the outer trusted
runner. Ordinary Node/Python commands run in owned nonroot Linux containers with
read-only root, no capabilities/network/Docker socket and a single read-only
Git-filtered candidate snapshot mount. Ignored private configuration is excluded.
Working files/results live in container tmpfs; only bounded, validated flat test
observations are read by the trusted outer process. Candidate test observations
remain distinct from independently authored assertions. Created containers and
snapshots are removed; cleanup failure prevents acceptance.

Native Windows lacks a qualified restricted identity. The default whole-repository
scope also requires independently maintained assertions beyond candidate test
output. Default repository runtime output remains `BLOCKED`,
`independent=false`, even if contained ordinary suite observations pass. Local
development Docker qualification is separately reported. An integrity PASS never
means independent product acceptance, hosted qualification, publication, release
eligibility or deployed proof. The separately selected portable product fixture
uses the trusted operator and independent assertions described below.

For an independently implemented, read-only source/policy audit, use the explicit
static scope. It invokes no candidate code and needs no Docker or dependency cache:

```text
node <bundle>/verification/controller/portable/cli.mjs run --bundle <bundle> --pin <external-pin.json> --candidate <absolute-product> --output <new-external-evidence> --scope source-policy
```

This scope checks source identity/file boundaries, private environment files,
source ownership and preservation of pinned registry obligations. A valid input
can produce `PASS`, `independent=true`, `scope=source-policy`. Its report explicitly
sets `independentProductAcceptance=false` and `independentRuntimeAcceptance=false`.
Removing or changing pinned obligations fails; unowned runtime inputs block. The
default repository scope enumerates pending trusted runtime assertions and each
unsupported Docker/native capability by suite, rather than returning a fixed
generic verdict. Candidate-authored test success remains ancillary evidence.

## Reviewed Node dependency cache

Ordinary JavaScript checks can consume a separately prepared immutable cache.
Without one, dependency-free checks work and missing third-party dependencies are
reported as `TRUSTED_NODE_DEPENDENCY_CACHE_REQUIRED`.

```text
node <bundle>/verification/controller/portable/cli.mjs build-cache --bundle <bundle> --pin <external-pin.json> --candidate <absolute-product> --output <new-external-cache-directory> --base-image node@sha256:<reviewed-base-digest>
```

The fixed manifest input roots are the repository, web, MCP bridge, local runtime
and local protocol packages. Only their `package.json` and `package-lock.json`
files enter the build context; private `.npmrc`, product sources and script files
are excluded. Lifecycle declarations remain metadata and are never executed.
The trusted builder requires exact Node 24.11.1 and runs static `npm ci
--ignore-scripts --no-audit --no-fund` commands. Remote dependencies must have
integrity digests and use HTTPS `registry.npmjs.org`; the one known local protocol
link is supported. `--cache-roots root` selects a smaller explicit preparation.

`node-cache.json` records immutable image/base identities, input digests, builder
code digest and verifier generation. `node-cache-review.template.json` starts
PENDING. Review the descriptor, exact builder/generation, image and qualification
before separately approving the review record. An image label alone is never
approval. Cache verification rejects stale input bytes, a different generation,
unreviewed records and mismatched image IDs/labels. Review records remain explicit
local trust choices rather than signed human attestations.

Pass the reviewed documents to the on-demand runtime invocation:

```text
node <bundle>/verification/controller/portable/cli.mjs run --bundle <bundle> --pin <external-pin.json> --candidate <absolute-product> --output <new-external-evidence> --node-cache <external-cache/node-cache.json> --node-cache-review <external-approved-cache-review.json> --python-image python@sha256:<digest>
```

The runtime uses the immutable cache image offline with a read-only root. Trusted
link setup exposes installed modules to the scratch working copy and maps local
protocol links to the candidate copy. Cache packages remain read-only, and the
candidate still has no Docker socket or access to trusted reports/pins.

## Focused checks

```text
node --test verification/controller/portable/*.test.mjs
```

Fixtures reject weakened/stale/unreviewed pins, altered registry/files, private
exports, traversal, symlinks, missing imports, secrets and malformed observations.
Actual Linux boundary qualification must additionally prove source/evidence write
denial, no Docker socket/network, ignored-secret exclusion and owned cleanup on
success/failure. Native Windows/full-product containment is not inferred from
fixture tests.

## Local implementation evidence, 2026-10-18

The focused suite has 11 passing checks, zero failures/skips. A current Linux
Docker qualification ran three owned containers using immutable local image
`sha256:53a5db8c7ceb5a4de7601bd1d0e66cea54babde9597ee7a0ecc08c6cbb1c2073`.
The positive fixture asserted UID 1000, loopback-only interfaces, absent Docker
socket, exclusion of an ignored secret fixture, denied candidate/verifier writes,
zero effective capabilities and NoNewPrivs. A deliberate exit 7 propagated and a
Python/JUnit observation was read through the bounded flat tar parser. All three
containers and the filtered source snapshot were removed.

Exact local receipt:
`.local/portable-controller-docker/attempt-FD9Atq/result.json`.
Reproduction fixture:
`.local/portable-controller-qualification.mjs`.
This qualifies the ordinary-command boundary only; independent whole-product
acceptance remains BLOCKED. The source receipt is not included in public exports.

The observation test exposed that Docker archive APIs omitted tmpfs contents.
The implementation now reads a bounded tar from the running mount namespace,
validates it as data and removes the container afterward. Earlier attempts retain
their first-cause diagnostics; they are not successful qualification receipts.

### Hardening and cache qualification, 2026-10-19

The bounded observation parser now requires aligned complete headers/payloads,
zero padding and two terminal zero blocks. It rejects trailing data, malformed
fields/checksums, links, unexpected/nested/traversal names, duplicates and oversized
members/aggregates before any host write. Generic archive controls formerly owned
by the retired Cloud output validator are maintained in `bundle.test.mjs`.

Current actual cache fixture receipt:
`.local/portable-controller-cache/attempt-A0ia3s/result.json`.
The manifest-only root cache built from public immutable Node base
`node@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57`
is image `sha256:8017ee6a8a205e334941d31d410499b529558f0ecab4a3e0bb87265398678ca2`,
83,665,853 bytes. A contained fixture successfully loaded and used installed AJV,
proved dependency writes fail and checked that a malicious postinstall marker and
private `.npmrc` were absent. Cleanup passed. The descriptor remained PENDING;
its test review was explicitly fixture-only and did not activate a distributed
generation. Final publication requires rebuilding/reviewing the cache against the
final verifier digest and actual candidate lock inputs.

After path and runtime-probe hardening, the actual ordinary boundary reran with
three passing controls and cleanup PASS at
`.local/portable-controller-docker/attempt-Trvs1G/result.json`. This run probes the
actual contained Node 24.11.1/Python 3.12 runtimes and uses the strict TAR parser.
The latest cache-builder fixture receipt is
`.local/portable-controller-cache/attempt-CPZfSU/result.json`, with immutable image
`sha256:a625d8ede7b66b07b2e56c756a2e85ad04c6a98b03a1372e6d019e809bab917d`.

<!-- EXTEND: portable-trusted-product -->
## Trusted portable product fixture

The explicit `--scope portable-product` path is a separate local Docker audit;
it is never dispatched by CI, bundle publication or another audit. Run it from
the reviewed bundle with an external reviewed pin and fresh external evidence:

```text
node <bundle>/verification/controller/portable/cli.mjs run --bundle <bundle> --pin <external-pin.json> --candidate <absolute-product> --output <new-external-evidence> --scope portable-product
```

The finite bundle includes generic local operators and independent HTTP, SQL,
Temporal and browser assertions. It excludes the private frontend/backend product
sources. The original candidate digest, owned frozen Git snapshot and effective
build input digests are recorded separately. Candidate host JavaScript/Python
recipes are never imported or executed by the trusted operator.

Dependency preparation has network access but sees only validated public package
manifests/locks. Node lifecycle scripts are disabled; Python preparation accepts
pinned wheels only. Worker/web product builds use fixed verifier recipes with
`--network none`. Native Functions use the pinned staging recipe and hash-locked
predownloaded wheels with `--no-index`. Candidate native/Docker installer recipes
are explicitly outside this fixture's acceptance scope. The owned product network
is internal before candidate Functions are submitted, and its actual Docker
configuration is checked before acceptance.

The observer authenticates real synthetic users, exercises authoring/publication,
access denial, Storage ranges, queued execution and worker recovery, snapshots,
copy/restore and MCP. Actual PostgreSQL state and byte digests are checked by
trusted code. A pinned Temporal CLI reads the real service description/history;
immutable start input and completed result digest must match the observed run
and SQL terminal result. The trusted Playwright script then exercises login,
editing, publication, execution and result inspection in the built frontend,
with real CA verification and only localhost browser requests.

Candidate runtime containers receive neither the verifier pin nor trusted report
write mounts nor a Docker socket. Scoped PostgreSQL/bootstrap helpers see only
their required SQL credentials; executor/jobs secrets and operator API keys are
omitted. The trusted browser sees only the synthetic owner credentials, public
CA and fixture bindings. Its private output is parsed and bounded before the
outer verifier writes the final receipt. Cleanup removes owned containers,
volumes, networks and per-attempt image tags, then scrubs private source/secrets.
Shared Docker build caches are retained. Cleanup failure prevents PASS and marks
remaining private state as recovery-only, never publishable.

Cleanup checks a separately owned stopped sentinel, with exact immutable ID,
image and labels, before and after product cleanup; only the parent releases it
after survival readback. Every product container removal is restricted to the
validated owned ID set and excludes the sentinel. Missing or altered sentinel
identity and any foreign removal target prevent PASS. Global container inventory
uses only ID/name/labels without layer-size inspection. Missing foreign IDs and
new foreign inventory are recorded separately as observed drift; the audit does
not claim that unrelated provider-managed containers remained unchanged.

The fixture selects three non-overlapping explicit private IPv4 `/24` networks
after reading existing Docker IPAM subnets. This uses the portable operator's
`networkSubnets` contract and changes neither daemon pools nor foreign networks.
It handles a Docker Desktop engine whose default address pools are exhausted.
If no reviewed private range is free, setup fails with a named blocker.

Failed stages retain their redacted first cause in protected
`private-diagnostics/operator-error.json`, outside the installation source/secret
directory that cleanup scrubs. This diagnostic is local-only and must never be
published. Public receipts contain only its relative path and a finite code.

This product scope does not qualify candidate installer recipes, external
providers, native Windows isolation, the whole repository, release admission or
a deployed target. Windows independence needs a dedicated restricted principal,
ACL/network enforcement and a scoped SQL/Docker broker; a same-user process or
WRITE_RESTRICTED token cannot supply those controls.

The exact prep09 generation received independent read-only approval for owned
local Docker qualification only: all 69 exported checks passed with zero skips,
and bundle bytes were stable before and after testing. Its manifest is
`sha256:960d636bc302db8d1a3e9e9ad07bff3f4d9aa314eae46f3e7cbe30d2f4956f43`.
Its actual `source-policy` run against the owned immutable candidate03 passed
all 35 pinned obligations, source ownership and 5,327 regular files. Receipt:
`.local/portable-controller-source-policy-actual09/controller-result.json`.
This is independent static acceptance; runtime and product acceptance are false.

Subsequent narrow fixes normalize Docker Desktop drive aliases, use standard
Playwright module resolution and make the relocated native wrapper an explicit
non-executable source template. The CLI's static executor import remains bound
to the verified bundle by launcher-root equality, including a regression that
rejects a different launcher. These changes require a successor export and fresh
review; prep09 approval does not cover them. The trusted product path has not yet
completed actual Docker qualification. No generation is publicly activated.

The local P8 activation preparation inventories the exact proposed public tree,
replacement/deletion list, immutable pins and required readbacks. It includes no
product source, credentials or local-only approved pin. External publication,
remote main movement, protection/variable changes, artifact publication and the
first independent audit remain separate recorded operations. The audit remains
an explicit local invocation; no schedule or automatic dispatch is introduced.

Actual prep12 product attempt on 2026-10-19 is preserved at
`.local/portable-controller-product-actual12/controller-result.json`: source-policy
PASS (35 obligations, 5,339 regular files), trusted manifest-only dependency build
and offline worker build succeeded, then core startup failed before any service
container was created. Independent product acceptance is false. Owned cleanup,
fingerprinted sentinel survival/release, private-state scrub and image-tag
removal passed; unrelated inventory drift was reported separately.

A subsequent pinned generic startup reproduction, without candidate execution,
confirmed the daemon's first cause: all predefined address pools were fully
subnetted. Its receipt is
`.local/portable-controller-startup-diagnostic-e9bc8c4ba1/result.json`; cleanup and
sentinel release passed. Explicit collision-checked private subnet allocation and
protected diagnostic retention address these operator defects. Their successor
generation still requires independent review and actual Docker qualification.

Before the next product attempt, a renderer-derived regression confirmed that
the executor platform uses an exact `r0e-<project-hash>` container name rather
than the suffix used by its runtime children. Cleanup now includes that exact
name and additionally requires its own owner label, exact Compose project and
executor service. Creation-time, pre-existing-ID and exact-ID removal guards
remain required. Prep13 was not run or modified; this correction requires a
reviewed successor generation before actual product qualification.

Executor teardown can also remove an already validated runtime child. A failed
exact-ID removal is reconciled only by a successful Docker inventory query for
that full ID in the validated cohort. Empty results count as already absent,
separately from successful removals; present, unrelated, malformed or unavailable
results remain failures. Other independently validated container targets are
still attempted, the first cause is retained privately, and remaining task
children or job containers prevent cleanup from passing.

The actual standard operator reached 60 journey checks before exposing a second
observer assumption: snapshot restore remaps ordinary resource artifact IDs.
The trusted observer now resolves the unique published resource in the restored
project's exact root, requiring its original name, content digest, byte length
and stable state, then reads the stable alias and compares every byte. It rejects
incomplete inventories, duplicate or foreign resources, and changed bindings.
Prep15 was reviewed but not run; these observer corrections require their own
reviewed successor generation and fresh runtime evidence.

Actual prep16 failed before migration SQL, while opening the projected TLS CA.
Its original subprocess details were lost; two separately retained PostgreSQL
diagnostics narrowed the failure to the first connection's CA-file read. Failed
tools now retain bounded, redacted exit/output evidence outside scrubbed state,
including when the subsequent container inspection fails. Raw diagnostics stay
private and must never be included in a publication packet.

Projected tools now materialize fresh bytes for the four required CA/password
inputs instead of copying root-only Linux file metadata. Only the minimal
read-only projection has readable files and traversable directories; the
enclosing host-private directory remains private. Private CA keys, unrelated
credentials and operator write paths are excluded. A fixed programmatic
traceback diagnostic invokes the same migration main function; normal migration
and bootstrap commands retain their ordinary entry points.
After owned containers are absent, only the three directories recorded for
each projection regain host deletion permissions before private-state scrub;
directory identity and link checks still apply. Independent permission probes
use the pinned base interpreter without site loading. SQL/TLS assertions use
the pinned PostgreSQL client, never candidate-installed Python startup code.

Operator qualification is scoped: nonroot migration, trusted SQL/TLS readback,
permission controls and owned cleanup do not establish full product acceptance.
The separately observed post-restore artifact inventory HTTP503 remains a
product blocker. Required restored-inventory assertions remain in place; no
whole-product PASS or successful run of this successor is implied here.
