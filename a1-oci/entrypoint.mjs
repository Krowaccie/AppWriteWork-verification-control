import { runHostedRuntime } from './host/hosted-runtime.mjs';

const result = await runHostedRuntime({
  environment: process.env,
  requestText: process.argv[2] ?? '',
});
const code = result.diagnostics[0]?.code ?? result.status;
process.stdout.write(`${result.status} ${code}\n`);
process.exitCode = result.status === 'PASS' ? 0 : 1;
