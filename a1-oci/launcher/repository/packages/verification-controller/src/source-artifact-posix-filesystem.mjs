import { bindPosixSourceArtifactKernelHost } from './source-artifact-posix-kernel-host.mjs';

const freeze = Object.freeze;

function kernelFrom(config) {
  const kernel = config?.platform === 'linux'
    ? bindPosixSourceArtifactKernelHost(config.kernelHost)
    : null;
  if (kernel === null) {
    throw new TypeError('Authenticated POSIX kernel host configuration is invalid.');
  }
  return kernel;
}

export function createPosixSourceArtifactSourceFilesystem(config) {
  const kernel = kernelFrom(config);
  return freeze({
    async exportArchive(rootHandle, archiveBytes, options, abortSignal) {
      return kernel.exportArchive(rootHandle, archiveBytes, options, abortSignal);
    },
    async makeImmutable(rootHandle, abortSignal) {
      return kernel.makeImmutable(rootHandle, abortSignal);
    },
    async rollbackExport(rootHandle, abortSignal) {
      return kernel.rollbackExport(rootHandle, abortSignal);
    },
  });
}

export function createPosixSourceArtifactOutputFilesystem(config) {
  const kernel = kernelFrom(config);
  return freeze({
    async writeMemberAtomically(rootHandle, relativePath, bytes, options, abortSignal) {
      return kernel.writeMemberAtomically(
        rootHandle,
        relativePath,
        bytes,
        options,
        abortSignal,
      );
    },
    async inspectTreeAtomically(rootHandle) {
      return kernel.inspectTreeAtomically(rootHandle);
    },
  });
}
