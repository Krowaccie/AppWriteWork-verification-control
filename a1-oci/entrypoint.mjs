import { runHostedRuntime } from './host/hosted-runtime.mjs';

const result = await runHostedRuntime({
  environment: process.env,
  requestText: process.argv[2] ?? '',
});
const code = result.diagnostics[0]?.code ?? result.status;
const exitCode = result.status === 'PASS' ? 0 : 1;
await new Promise((resolve, reject) => {
  process.stdout.write(`${result.status} ${code}\n`, (error) => error ? reject(error) : resolve());
});
process.exit(exitCode);
