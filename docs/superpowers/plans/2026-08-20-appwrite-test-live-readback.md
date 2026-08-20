# Appwrite Test Live Readback Producer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce and deploy canonical, secret-free Appwrite Test setup bindings from live protected readback so the controller publisher and `Verify Test Cloud` can run against real test infrastructure.

**Architecture:** A read-only acquisition module obtains fixed Appwrite Test projections through disjoint operator and fixture credentials. A pure assembler creates and self-validates the eight setup bindings, and a manual protected workflow uploads only those bindings and sanitized evidence.

**Tech Stack:** Node.js 24.11.1, GitHub Actions `windows-2025`, Appwrite REST API, canonical JSON/SHA-256, Node test runner.

**Spec:** `docs/superpowers/specs/2026-08-20-appwrite-test-live-readback-design.md`

## Global Constraints

- Target only Appwrite Test project `69137c5d003952a36d4c` and Site `694579860016df0d2d3c` at `https://fra.cloud.appwrite.io/v1`.
- Never reference or mutate production project `69eb4818000afa64a7fa`, production Site `69eb4a020024c520642e`, or branch `production`.
- Map no recovery credential and perform no Appwrite mutation, deployment, execution, login, or session creation.
- Never emit credential values, raw runner-variable values, user IDs, user emails, passwords, or preference documents.
- Credential-bearing workflows remain `workflow_dispatch`-only and use pinned external actions.
- All input SHAs are exact 40-character lowercase hexadecimal values.

---

### Task 1: Pure binding assembler

**Files:**
- Create: `packages/verification-controller/src/appwrite-test-setup-bindings.mjs`
- Create: `packages/verification-controller/src/appwrite-test-setup-bindings.test.mjs`

**Interfaces:**
- Consumes: `createAppwriteTestSetupBindings({ controllerRevision, sourceRepositoryRevision, runnerRevision, initialSeed, liveProjection, browserRequestPolicy, nowEpochSeconds, controllerArtifact })`.
- Produces: `{ status: 'PASS', value: { bindings, evidence } }` or one safe `BLOCKED_*` diagnostic.

- [ ] Write a failing test with a valid fixed live projection and assert all eight canonical binding names, digests, initial prepublication schema, and validator PASS.
- [ ] Run `node --test packages/verification-controller/src/appwrite-test-setup-bindings.test.mjs` and confirm the module-not-found RED failure.
- [ ] Implement exact-object validation, canonical assembly, digest derivation, bounded validity windows, and self-validation through existing setup validators.
- [ ] Add failures for placeholders, synthetic hosts, production IDs, malformed SHA/digest, mismatched runner variables, nonzero sessions, and ordinary mode without an artifact tuple.
- [ ] Run the focused test and require zero failures.
- [ ] Commit the assembler and its tests with message `Add canonical Appwrite Test setup binding producer`.

### Task 2: Read-only Appwrite acquisition

**Files:**
- Create: `packages/verification-controller/src/appwrite-test-live-readback.mjs`
- Create: `packages/verification-controller/src/appwrite-test-live-readback.test.mjs`

**Interfaces:**
- Consumes: `readAppwriteTestLiveProjection({ inventory, operatorCredential, fixtureCredential, fetchImpl, clock })`.
- Produces: a sanitized projection accepted by Task 1; raw responses and secrets remain unreachable.

- [ ] Write failing transport tests proving no credential is read until the fixed endpoint/project/Site inventory is accepted.
- [ ] Add a fake Appwrite transport for exact `GET` responses covering Site, 36 Functions, 16 runner variables, three users, three zero-session sets, and the idle lease.
- [ ] Run the focused test and confirm RED because the acquisition module is absent.
- [ ] Implement a bounded strict response reader, separate credential handles, exact path allowlist, provider projections, and safe error mapping.
- [ ] Add negative tests for redirects, non-JSON, duplicate keys, overlong response, secret reflection, unknown Function, missing variable, secret variable, nonzero session, and non-idle lease.
- [ ] Assert the returned object contains only digests, fixed nonsecret resource IDs, counts, booleans, and sanitized configuration projections.
- [ ] Run the focused test and require zero failures.
- [ ] Commit with message `Add protected Appwrite Test live readback`.

### Task 3: Source-browser policy producer

**Files:**
- Create: `packages/verification-controller/src/appwrite-test-browser-policy.mjs`
- Create: `packages/verification-controller/src/appwrite-test-browser-policy.test.mjs`
- Modify: `packages/verification-controller/src/test-cloud-browser-artifact-set.mjs`

**Interfaces:**
- Consumes: exact source artifact members plus fixed Appwrite Test provider-contract descriptors.
- Produces: `test-cloud.browser-request-policy.v1` with 56 rows and a self-field-free canonical digest.

- [ ] Write a failing test that supplies an exact 25-member browser artifact set and expects 25 immutable asset rows plus 31 fixed Appwrite request rows.
- [ ] Export only the existing pure artifact-row projection needed by the producer; do not expose runtime brands or credential-bearing adapters.
- [ ] Implement exact Appwrite Test URL/header digest substitution from fixed inventory and provider contract.
- [ ] Add rejection tests for fixture hosts, production hosts/IDs, placeholder digests, wrong row count/order/profile, duplicate ordinals, and a mismatched policy digest.
- [ ] Run the focused test and the existing browser artifact-set tests; require zero failures.
- [ ] Commit with message `Generate exact Appwrite Test browser policy`.

### Task 4: Protected readback CLI and workflow

**Files:**
- Create: `packages/verification-controller/src/collect-appwrite-test-readback.mjs`
- Create: `packages/verification-controller/src/collect-appwrite-test-readback.test.mjs`
- Create: `.github/workflows/collect-appwrite-test-readback.yml`
- Create: `packages/verification-controller/workflows/collect-appwrite-test-readback.yml`
- Modify: `.github/workflows/controller-validation.yml`

**Interfaces:**
- CLI arguments: `--input <canonical-json> --source-policy <canonical-json> --output <new-directory>`.
- Workflow inputs: `trusted_controller_sha`, `source_repository_revision`, `initial_seed`, and `source_policy_artifact_id`.
- Artifact name: `appwrite-test-setup-readback-<controller-sha>-<source-sha>`.

- [ ] Write failing CLI tests for exact argument parsing, no overwrite, safe diagnostics, and the eight expected output files.
- [ ] Implement the CLI as composition of Tasks 1-3 with dependencies injected for tests.
- [ ] Write workflow-contract tests asserting manual-only trigger, `windows-2025`, `appwrite-test`, exact SHA guard, pinned checkout/setup-node/upload actions, two allowed secret names, and absence of recovery/production names.
- [ ] Add the manual workflow and extend controller validation to run all root/controller `*.test.mjs` files before accepting a PR.
- [ ] Run focused CLI/workflow tests and the complete controller test command; require zero failures.
- [ ] Commit with message `Add protected Appwrite Test readback workflow`.

### Task 5: Public controller PR and protected merge

**Files:**
- Modify only documentation or validation metadata required by review findings.

**Interfaces:**
- Produces: a signed full controller commit and a protected controller `main` merge SHA.

- [ ] Run `git diff --check`, secret-like filename scan, focused tests, full controller tests, and action-pin validation.
- [ ] Confirm the diff contains no secret values, production mutation path, recovery mapping, unpinned action, or nonmanual credentialed trigger.
- [ ] Commit remaining verified changes, push `codex/phase-b1-live-readback`, and open a public PR to controller `main`.
- [ ] Wait for `Controller validation`; inspect and fix failures on the branch until PASS.
- [ ] Perform exact diff review and merge only through the protected controller PR path.
- [ ] Read back the resulting 40-character controller `main` SHA and workflow IDs.

### Task 6: Generate live bindings and publish the controller bundle

**Files:**
- No source-controlled secret or binding-value files.

**Interfaces:**
- Consumes: exact merged controller SHA, exact source candidate SHA, source-policy artifact, existing Appwrite Test secrets.
- Produces: eight environment variables plus controller artifact ID/raw ZIP digest.

- [ ] Update `TRUSTED_CONTROLLER_SHA` in `appwrite-test` and `controller-promotion` to the new protected SHA.
- [ ] Dispatch the readback workflow in initial-seed mode and wait for PASS.
- [ ] Download the artifact by exact ID, validate its member set/digests locally, and set the eight binding variables without printing their values.
- [ ] Set `VERIFICATION_RUNNER_REVISION` to the exact runner source revision consumed by the proposal.
- [ ] Dispatch `Publish Controller Bundle` with `initial_seed=true`; fix branch/environment defects until PASS.
- [ ] Read back the exact artifact ID, name, workflow head SHA, direct-member set, materialized manifest, and raw ZIP SHA-256.
- [ ] Generate the ordinary hosted binding using that exact artifact tuple and replace only the hosted variable quartet.
- [ ] Set and read back `TRUSTED_CONTROLLER_ARTIFACT_ID` and `TRUSTED_CONTROLLER_BUNDLE_DIGEST`.

### Task 7: Source pin, hosted run, and closeout

**Files:**
- Modify the isolated AppWriteWork source candidate workflow pin and required governance documents.
- Do not modify the user's dirty source-main checkout.

**Interfaces:**
- Consumes: merged controller SHA/artifact tuple and final source candidate SHA.
- Produces: successful source `Verify Main`, successful controller `Verify Test Cloud`, and final closeout evidence.

- [ ] Update the source candidate's controller action pin and binding readback records; run the repository change-impact preflight and focused tests.
- [ ] Push the source branch and wait for PR `Verify Main` PASS while ignoring the out-of-scope production Site status.
- [ ] Freeze the exact source diff, refresh the CIR/fingerprint, and obtain the single required action-time approval for source `main` movement.
- [ ] Merge the source PR through GitHub, read back the exact `main` SHA, and require `Verify Main` artifact publication PASS.
- [ ] Dispatch `Verify Test Cloud` with exact source run ID/attempt/SHA and iterate on code or bindings until all six scenarios and cleanup evidence PASS.
- [ ] Run fresh local retained suites, `npm run build`, and two identical `post-test-deploy` impact checker passes.
- [ ] Mark the activation plan complete only after hosted PASS; record production as untouched and the production lane as separately pending.

