import { spawn } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const STATUSES = new Set([
  "exited",
  "timed-out",
  "spawn-failed",
  "containment-unavailable",
]);
const MAX_TIMEOUT_MS = 86_400_000;
const MAX_ARGUMENT_COUNT = 4_096;
const MAX_ARGUMENT_BYTES = 1_048_576;
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;
const MAX_OUTPUT_BYTES = 16_777_216;
const MAX_HELPER_ENVELOPE_BYTES = MAX_OUTPUT_BYTES * 6 + 65_536;
const WINDOWS_HELPER_GRACE_MS = 15_000;
const TRUSTED_WINDOWS_ROOT = "C:\\Windows";
const TRUSTED_POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const TRUSTED_COMSPEC = "C:\\Windows\\System32\\cmd.exe";

function frozenResult(status, fields = {}) {
  return Object.freeze({
    status,
    exitCode: null,
    signal: null,
    stdout: "",
    stderr: "",
    ...fields,
  });
}

function failure(error) {
  return frozenResult("containment-unavailable", { error: String(error) });
}

function readClosedOptions(options) {
  if (
    !options ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    (Object.getPrototypeOf(options) !== Object.prototype &&
      Object.getPrototypeOf(options) !== null) ||
    Object.getOwnPropertySymbols(options).length !== 0
  ) {
    throw new TypeError("options must be a plain data object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const allowed = new Set([
    "args",
    "cwd",
    "env",
    "executable",
    "maxOutputBytes",
    "timeoutMs",
  ]);
  for (const required of ["args", "cwd", "env", "executable", "timeoutMs"]) {
    if (!Object.hasOwn(descriptors, required)) {
      throw new TypeError("options must contain " + required);
    }
  }
  for (const [name, descriptor] of Object.entries(descriptors)) {
    if (
      !allowed.has(name) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw new TypeError("options must contain only closed data fields");
    }
  }
  return Object.fromEntries(
    Object.entries(descriptors).map(([name, descriptor]) => [name, descriptor.value]),
  );
}

function validateArguments(args) {
  if (!Array.isArray(args)) throw new TypeError("args must be an array");
  if (args.length > MAX_ARGUMENT_COUNT) {
    throw new RangeError(
      "args exceeds maximum bounded count " + MAX_ARGUMENT_COUNT,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(args);
  if (Object.getOwnPropertySymbols(args).length !== 0) {
    throw new TypeError("args must be a dense data array");
  }
  const expectedNames = new Set(["length"]);
  for (let index = 0; index < args.length; index += 1) {
    expectedNames.add(String(index));
  }
  const names = Object.getOwnPropertyNames(descriptors);
  if (
    names.length !== expectedNames.size ||
    names.some((name) => !expectedNames.has(name))
  ) {
    throw new TypeError("args must be a dense data array");
  }
  const values = [];
  let argumentBytes = 0;
  for (let index = 0; index < args.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "string" ||
      descriptor.value.includes("\0")
    ) {
      throw new TypeError("args must contain only NUL-free string data");
    }
    argumentBytes += Buffer.byteLength(descriptor.value, "utf8");
    if (argumentBytes > MAX_ARGUMENT_BYTES) {
      throw new RangeError(
        "args exceeds maximum bounded UTF-8 bytes " + MAX_ARGUMENT_BYTES,
      );
    }
    values.push(descriptor.value);
  }
  return values;
}

function validateOptions(options) {
  const fields = readClosedOptions(options);
  const { executable, args, cwd, env, timeoutMs } = fields;
  if (typeof executable !== "string" || !path.isAbsolute(executable)) {
    throw new TypeError("executable must be an absolute path");
  }
  if (executable.includes("\0")) throw new TypeError("executable must not contain NUL");
  if (typeof cwd !== "string" || !path.isAbsolute(cwd)) {
    throw new TypeError("cwd must be an absolute path");
  }
  if (cwd.includes("\0")) throw new TypeError("cwd must not contain NUL");
  const normalizedArgs = validateArguments(args);
  if (env === null || typeof env !== "object" || Array.isArray(env)) {
    throw new TypeError("env must be an explicit object");
  }
  const prototype = Object.getPrototypeOf(env);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    Object.getOwnPropertySymbols(env).length !== 0
  ) {
    throw new TypeError("env must be a plain data object");
  }
  const normalizedEnv = Object.create(null);
  const windowsNames = new Set();
  const envDescriptors = Object.getOwnPropertyDescriptors(env);
  for (const [name, descriptor] of Object.entries(envDescriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new TypeError("env must contain only enumerable data properties");
    }
    const value = descriptor.value;
    if (!name || name.includes("=") || name.includes("\0")) {
      throw new TypeError("env names must be non-empty and must not contain equals or NUL");
    }
    if (typeof value !== "string" || value.includes("\0")) {
      throw new TypeError("env values must be NUL-free strings");
    }
    if (process.platform === "win32") {
      const folded = name.toUpperCase();
      if (windowsNames.has(folded)) {
        throw new TypeError("env names must be unique ignoring case on Windows");
      }
      windowsNames.add(folded);
    }
    normalizedEnv[name] = value;
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive finite integer");
  }
  if (timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError("timeoutMs exceeds maximum bounded value " + MAX_TIMEOUT_MS);
  }
  const maxOutputBytes =
    fields.maxOutputBytes === undefined
      ? DEFAULT_MAX_OUTPUT_BYTES
      : fields.maxOutputBytes;
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new TypeError("maxOutputBytes must be a positive finite integer");
  }
  if (maxOutputBytes > MAX_OUTPUT_BYTES) {
    throw new RangeError(
      "maxOutputBytes exceeds maximum bounded value " + MAX_OUTPUT_BYTES,
    );
  }
  return {
    executable,
    args: normalizedArgs,
    cwd,
    env: normalizedEnv,
    timeoutMs,
    maxOutputBytes,
  };
}

function trustedWindowsLauncher() {
  try {
    const powershellInfo = lstatSync(TRUSTED_POWERSHELL);
    const commandInterpreterInfo = lstatSync(TRUSTED_COMSPEC);
    if (
      !powershellInfo.isFile() ||
      powershellInfo.isSymbolicLink() ||
      !commandInterpreterInfo.isFile() ||
      commandInterpreterInfo.isSymbolicLink()
    ) {
      return null;
    }
    const powershell = realpathSync.native(TRUSTED_POWERSHELL);
    const commandInterpreter = realpathSync.native(TRUSTED_COMSPEC);
    if (
      powershell.toUpperCase() !== TRUSTED_POWERSHELL.toUpperCase() ||
      commandInterpreter.toUpperCase() !== TRUSTED_COMSPEC.toUpperCase()
    ) {
      return null;
    }
    return {
      commandInterpreter,
      powershell,
      systemRoot: TRUSTED_WINDOWS_ROOT,
    };
  } catch {
    return null;
  }
}

function windowsTargetEnvironment(explicitEnvironment, systemRoot) {
  const result = Object.assign(Object.create(null), {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
  });
  for (const [name, value] of Object.entries(explicitEnvironment)) {
    const folded = name.toUpperCase();
    if (folded === "SYSTEMROOT" || folded === "WINDIR") {
      if (
        !path.win32.isAbsolute(value) ||
        path.win32.normalize(value).toUpperCase() !== systemRoot.toUpperCase()
      ) {
        throw new TypeError(
          name + " is launcher-owned and must match the trusted Windows system root",
        );
      }
      continue;
    }
    result[name] = value;
  }
  return result;
}

function windowsHelperEnvironment(launcher) {
  const result = {
    ComSpec: launcher.commandInterpreter,
    SystemRoot: launcher.systemRoot,
    WINDIR: launcher.systemRoot,
  };
  for (const expected of ["TEMP", "TMP"]) {
    const entry = Object.entries(process.env).find(
      ([name]) => name.toUpperCase() === expected,
    );
    if (typeof entry?.[1] === "string") result[expected] = entry[1];
  }
  return result;
}

function terminateHelper(helper) {
  if (helper.exitCode !== null || helper.signalCode !== null) return true;
  try {
    // On Windows ChildProcess.kill uses Node's retained process handle. A
    // numeric-PID fallback is forbidden because a reused PID could be foreign.
    return helper.kill();
  } catch {
    return false;
  }
}

function runWindows(request, launcher) {
  return new Promise((resolve) => {
    const helperPath = fileURLToPath(
      new URL("./process-containment-windows.ps1", import.meta.url),
    );
    let helper;
    try {
      helper = spawn(
        launcher.powershell,
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", helperPath],
        {
          cwd: path.dirname(helperPath),
          env: windowsHelperEnvironment(launcher),
          shell: false,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
    } catch (error) {
      resolve(failure(error));
      return;
    }

    const stdout = [];
    const stderr = [];
    const helperEnvelopeLimit = Math.min(
      MAX_HELPER_ENVELOPE_BYTES,
      request.maxOutputBytes * 6 + 65_536,
    );
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let helperOutputExceeded = false;
    let watchdogExpired = false;
    let helperTerminationFailed = false;
    let settled = false;
    const watchdog = setTimeout(() => {
      watchdogExpired = true;
      if (!terminateHelper(helper)) {
        helperTerminationFailed = true;
      }
    }, request.timeoutMs + WINDOWS_HELPER_GRACE_MS);

    helper.stdout.on("data", (chunk) => {
      if (helperOutputExceeded) return;
      if (stdoutBytes + chunk.length > helperEnvelopeLimit) {
        helperOutputExceeded = true;
        if (!terminateHelper(helper)) {
          helperTerminationFailed = true;
        }
        return;
      }
      stdout.push(Buffer.from(chunk));
      stdoutBytes += chunk.length;
    });
    helper.stderr.on("data", (chunk) => {
      if (stderrBytes >= DEFAULT_MAX_OUTPUT_BYTES) return;
      const retained = chunk.subarray(
        0,
        Math.min(chunk.length, DEFAULT_MAX_OUTPUT_BYTES - stderrBytes),
      );
      stderr.push(Buffer.from(retained));
      stderrBytes += retained.length;
    });
    helper.stdin.on("error", () => {
      // The close/error path below reports the fail-closed result.
    });
    helper.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      resolve(failure(error));
    });
    helper.once("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      if (helperOutputExceeded) {
        resolve(failure(
          "Windows containment helper output exceeded its bounded envelope" +
            (helperTerminationFailed
              ? "; retained-handle termination was not accepted before native failsafe exit"
              : ""),
        ));
        return;
      }
      if (watchdogExpired) {
        resolve(failure(
          "Windows containment helper exceeded its bounded watchdog" +
            (helperTerminationFailed
              ? "; retained-handle termination was not accepted before native failsafe exit"
              : ""),
        ));
        return;
      }
      if (code !== 0) {
        const detail = Buffer.concat(stderr).toString("utf8").trim();
        resolve(failure(
          detail
            ? "Windows containment helper failed: " + detail
            : "Windows containment helper failed",
        ));
        return;
      }
      const raw = Buffer.concat(stdout).toString("utf8").trim();
      try {
        const result = JSON.parse(raw);
        const resultKeys = result && typeof result === "object"
          ? Object.keys(result).sort()
          : [];
        if (
          !result ||
          Object.getPrototypeOf(result) !== Object.prototype ||
          resultKeys.join(",") !== "error,exitCode,signal,status,stderr,stdout" ||
          !STATUSES.has(result.status) ||
          typeof result.stdout !== "string" ||
          typeof result.stderr !== "string" ||
          result.signal !== null ||
          (result.error !== null && typeof result.error !== "string") ||
          Buffer.byteLength(result.stdout, "utf8") +
            Buffer.byteLength(result.stderr, "utf8") >
            request.maxOutputBytes ||
          (result.status === "exited"
            ? !Number.isInteger(result.exitCode)
            : result.exitCode !== null)
        ) {
          throw new Error("Windows containment helper returned an invalid result");
        }
        const fields = {
          exitCode: result.exitCode,
          signal: null,
          stdout: result.stdout,
          stderr: result.stderr,
        };
        if (typeof result.error === "string" && result.error) {
          fields.error = result.error;
        }
        resolve(frozenResult(result.status, fields));
      } catch {
        resolve(failure("Windows containment helper returned malformed output"));
      }
    });
    helper.stdin.end(JSON.stringify(request));
  });
}

export async function runContainedProcess(options) {
  const request = validateOptions(options);
  if (process.platform !== "win32") {
    return failure(
      "unsupported containment platform without a fail-closed process-tree primitive: " +
        process.platform,
    );
  }
  const launcher = trustedWindowsLauncher();
  if (!launcher) {
    return failure("trusted Windows containment launcher is unavailable");
  }
  request.env = windowsTargetEnvironment(request.env, launcher.systemRoot);
  return runWindows(request, launcher);
}
