import path from 'node:path';
import { pathToFileURL } from 'node:url';

const CONFIG_NAMES = Object.freeze(['tsconfig.app.json', 'tsconfig.node.json']);

function validWebRoot(value) {
  return typeof value === 'string'
    && value.startsWith('/')
    && !value.includes('\0')
    && !value.includes('\\')
    && path.posix.normalize(value) === value;
}

function diagnosticHost(typescript) {
  return {
    getCanonicalFileName: (fileName) => fileName,
    getCurrentDirectory: () => '/',
    getNewLine: () => '\n',
  };
}

export async function runTypecheck({
  typescript,
  webRoot,
  writeError = (text) => process.stderr.write(text),
} = {}) {
  if (!validWebRoot(webRoot) || typescript === null || typeof typescript !== 'object') return 2;
  const diagnostics = [];
  for (const configName of CONFIG_NAMES) {
    const configPath = path.posix.join(webRoot, configName);
    const source = typescript.readConfigFile(configPath, typescript.sys.readFile);
    if (source.error !== undefined) {
      diagnostics.push(source.error);
      continue;
    }
    const parsed = typescript.parseJsonConfigFileContent(
      source.config,
      typescript.sys,
      webRoot,
      { composite: false, incremental: false, noEmit: true },
      configPath,
    );
    delete parsed.options.tsBuildInfoFile;
    diagnostics.push(...parsed.errors);
    if (parsed.errors.length === 0) {
      const program = typescript.createProgram({
        options: parsed.options,
        rootNames: parsed.fileNames,
      });
      diagnostics.push(...typescript.getPreEmitDiagnostics(program));
    }
  }
  if (diagnostics.length === 0) return 0;
  writeError(typescript.formatDiagnostics(diagnostics, diagnosticHost(typescript)));
  return 1;
}

async function main() {
  if (process.argv.length !== 3 || !validWebRoot(process.argv[2])) return 2;
  const modulePath = path.posix.join(
    process.argv[2],
    'node_modules/typescript/lib/typescript.js',
  );
  const imported = await import(pathToFileURL(modulePath).href);
  return runTypecheck({
    typescript: imported.default ?? imported,
    webRoot: process.argv[2],
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}
