import assert from 'node:assert/strict';
import test from 'node:test';

import { runTypecheck } from '../host/typecheck-driver.mjs';

function fakeTypeScript(diagnostics = []) {
  const observedOptions = [];
  return {
    observedOptions,
    createProgram({ options }) {
      observedOptions.push(options);
      return Object.freeze({ options });
    },
    formatDiagnostics(values) {
      return values.map(({ messageText }) => messageText).join('\n');
    },
    getPreEmitDiagnostics() {
      return diagnostics;
    },
    parseJsonConfigFileContent(_config, _system, _root, overrides) {
      return {
        errors: [],
        fileNames: ['/work/launcher/source/src/web/src/main.tsx'],
        options: { ...overrides, tsBuildInfoFile: '/untrusted/source.tsbuildinfo' },
      };
    },
    readConfigFile() {
      return { config: {} };
    },
    sys: { readFile() {} },
  };
}

test('checks both fixed projects without incremental writes', async () => {
  const typescript = fakeTypeScript();
  assert.equal(await runTypecheck({
    typescript,
    webRoot: '/work/launcher/source/src/web',
  }), 0);
  assert.equal(typescript.observedOptions.length, 2);
  for (const options of typescript.observedOptions) {
    assert.equal(options.noEmit, true);
    assert.equal(options.incremental, false);
    assert.equal(options.composite, false);
    assert.equal(Object.hasOwn(options, 'tsBuildInfoFile'), false);
  }
});

test('fails on diagnostics and rejects non-POSIX roots', async () => {
  const typescript = fakeTypeScript([{ messageText: 'type failure' }]);
  let output = '';
  assert.equal(await runTypecheck({
    typescript,
    webRoot: '/work/launcher/source/src/web',
    writeError(text) { output += text; },
  }), 1);
  assert.equal(output, 'type failure\ntype failure');
  assert.equal(await runTypecheck({ typescript, webRoot: 'relative' }), 2);
});
