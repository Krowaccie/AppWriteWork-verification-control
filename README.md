# AppWriteWork Verification Control

Trusted verification controller for `Krowaccie/AppWriteWork`.

## Public secret-free policy

This repository is classified as `PUBLIC_SECRET_FREE`.

- Never commit credentials, API keys, private keys, passwords, tokens, production data, or user data.
- Credential-bearing workflows must be manual-only through `workflow_dispatch` and protected GitHub environments.
- Pull-request validation must remain secretless.
- Changes to controller code, actions, workflows, schemas, policies, manifests, and lockfiles require protected review.
- Direct pushes, force-pushes, and deletion of the default branch are prohibited after bootstrap protection is enabled.

This initial `main` branch contains governance only. The deterministic controller seed must arrive through the separately reviewed Phase B1 transfer and pull-request process.
