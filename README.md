# AppWriteWork portable verification controller

This public repository contains a finite, secret-free verifier generation for local on-demand audits. It contains no private product source.

The product repository and CI never dispatch this audit automatically. Controller validation checks only bundle integrity and verifier fixtures. Bundle publication is an explicit manual workflow and never approves a pin or starts an audit.

Prepared bundle manifest: `sha256:f700d8dc6682c6e7ac02166b6589e08c5480e81ff1cb64154f78b54a5dad8eba`. The approved P8 plan supplies authority for its stated publication steps; execution remains blocked on actual repository-access and required provider readbacks. No remote publication or activation has occurred. Operator instructions and limits are in [the bundled guide](bundle/verification/controller/portable/README.md).

Download and verify the exact reviewed bundle, retain an approved pin outside both product and bundle, and invoke its local CLI explicitly. Product runtime checks require the operator's local Docker. Appwrite Cloud is not required. Native Windows independence requires separately qualified restricted OS execution.

No workflow receives private product contents, product credentials or candidate artifacts. Historical Cloud and production workflows are retired from the proposed tree; Git history remains intact.

This generation passed 94 exported fixtures plus one workflow test with zero failures/skips and stable hashes. A prior generation passed the scoped nonroot migration and independent permission/SQL/TLS proof; independent review approved reuse because the actually exercised process helpers before collectTests, including executeCommand, and other proof inputs are byte-identical. The imported process.mjs file differs in collectTests, and executor failed-count handling differs; those paths were not exercised by the PostgreSQL proof. Executed manifest: `sha256:3e73c2a707c7648824cd3cec0a48efe51e31f32a26dd9ca4214548e8cc8aa7d3`; scoped receipt: `sha256:cc252188745f9303de6f1b001e9f54dff57895d176189e758a2c892bde313105`. No fresh product runtime audit of this generation is claimed. The successful scoped attempt had exact owned cleanup/readback PASS. An earlier failed SQL-client helper may have left an anonymous volume whose ownership cannot be proved; it was not deleted and all-owned absence is not claimed for that attempt. Independent product acceptance remains false; restored inventory HTTP503 and native Windows isolation are unresolved. Private candidate contents, credentials and runtime evidence are not published.
