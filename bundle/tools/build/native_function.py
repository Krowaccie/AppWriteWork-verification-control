"""Native Appwrite Python build. No Node, cloud access, or deployment credentials.

Root directory: repository root. Entrypoint: appwrite_function/main.py.
Build command: python tools/build/native_function.py build <logical-id>.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIRED = "platform/appwrite/desired-state/appwrite-desired-state.v1.json"
SHARED = "packages/backend-core-py/src/appwritework_backend"
RECIPE = "tools/build/native_function.py"
CATALOG_COMPONENTS = {"runs-create-py", "mcp-gateway-py", "salmora-authoring-py"}
# M7 is qualified locally before the shared deployment catalog is cut over.
LOCAL_COMPONENTS = {"salmora-devices-py": "services/local-device-api"}
IGNORED = {"tests", "__pycache__", ".pytest_cache", "node_modules", ".venv", "appwritework_backend"}


def source_bytes(path):
    # Every packaged input is text. Match Git's LF checkout on the Linux builder.
    return path.read_bytes().replace(b"\r\n", b"\n")


def assert_lock(root, source):
    requirements = safe_file(root, source + "/requirements.txt")
    lock = root / source / "requirements.lock"
    if not lock.is_file():
        raise ValueError("NATIVE_LOCK_MISSING")
    expected = "# requirements-sha256: " + hashlib.sha256(source_bytes(requirements)).hexdigest()
    if not safe_file(root, source + "/requirements.lock").read_text().startswith(expected + "\n"):
        raise ValueError("NATIVE_LOCK_STALE_REGENERATE")


def refresh_lock(logical_id, root=ROOT):
    source = recipe(logical_id, root)["sourcePath"]
    requirements = safe_file(root, source + "/requirements.txt")
    before = source_bytes(requirements)
    lock = requirements.with_suffix(".lock")
    subprocess.run(["uv", "pip", "compile", str(requirements), "--constraint",
                    str(root / "verification/core/runtime/python-local-requirements.lock"),
                    "--python-version", "3.12", "--python-platform", "linux", "--generate-hashes",
                    "--no-annotate", "--no-header", "--output-file", str(lock)], check=True)
    if before != source_bytes(requirements):
        raise ValueError("NATIVE_REQUIREMENTS_CHANGED_DURING_LOCK")
    digest = hashlib.sha256(before).hexdigest()
    lock.write_bytes(("# requirements-sha256: " + digest + "\n").encode() + source_bytes(lock))
    return {"logicalId": logical_id, "requirementsSha256": digest}


def safe_file(root, relative):
    path = root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("NATIVE_UNSAFE_FILE")
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("NATIVE_UNSAFE_PARENT")
    return path


def components(root=ROOT):
    return {item["logicalId"]: item for item in json.loads(safe_file(root, DESIRED).read_text())["functions"]}


def source_files(root, relative):
    base = root / relative
    if base.is_symlink() or not base.is_dir():
        raise ValueError("NATIVE_SOURCE_MISSING")
    result = []
    for path in sorted(base.rglob("*")):
        parts = path.relative_to(base).parts
        if any(part in IGNORED or part.startswith(".") for part in parts):
            continue
        if path.is_symlink():
            raise ValueError("NATIVE_SYMLINK")
        is_migration = relative == SHARED and parts[:-1] == ("sql", "migrations") and path.suffix == ".sql"
        if path.is_file() and (path.suffix in {".py", ".json"} or is_migration or path.name in {"requirements.txt", "requirements.lock"}):
            result.append(safe_file(root, path.relative_to(root).as_posix()))
    return result


def assert_catalog(root):
    manifest = json.loads(safe_file(root, "packages/catalog/manifest.json").read_text())
    bindings = json.loads(safe_file(root, "services/appwrite-functions/runs-create-py/runtime-bindings.json").read_text())["templates"]
    definitions = []
    for name in manifest["templates"]:
        definition = json.loads(safe_file(root, "packages/catalog/definitions/" + name).read_text())
        if definition["id"] in bindings:
            definition["runtime"] = bindings[definition["id"]]["runtime"]
        definitions.append(definition)
    bundled = json.loads(safe_file(root, "services/appwrite-functions/runs-create-py/catalog-bundle.json").read_text())
    if definitions != bundled:
        raise ValueError("NATIVE_CATALOG_STALE_RUN_NPM_BUNDLE_CATALOG")


def recipe(logical_id, root=ROOT):
    local = logical_id in LOCAL_COMPONENTS
    component = ({"runtime": "python-3.12", "sourcePath": LOCAL_COMPONENTS[logical_id], "entrypoint": "main.py"}
                 if local else components(root).get(logical_id))
    if not component or component["runtime"] != "python-3.12":
        raise ValueError("NATIVE_UNKNOWN_COMPONENT")
    source = component["sourcePath"]
    expected_source = LOCAL_COMPONENTS[logical_id] if local else "services/appwrite-functions/" + logical_id
    if source != expected_source or component["entrypoint"] != "main.py":
        raise ValueError("NATIVE_COMPONENT_LAYOUT")
    return {"logicalId": logical_id, "rootDirectory": "", "entrypoint": "appwrite_function/main.py",
            "commands": "python tools/build/native_function.py build " + logical_id,
            **({"localQualificationOnly": True} if local else {"branch": "main", "branches": ["main"]}),
            "paths": [source + "/**", "packages/backend-core-py/**", "tools/build/**", DESIRED,
                      *(["packages/catalog/**", "packages/contracts/**"] if logical_id in CATALOG_COMPONENTS else []),
                      *(["services/appwrite-functions/runs-create-py/catalog-bundle.json", "services/appwrite-functions/runs-create-py/runtime-bindings.json"] if logical_id in CATALOG_COMPONENTS - {"runs-create-py"} else []),
                      "!**/*.md", "!**/tests/**"], "sourcePath": source}


def inputs(logical_id, root=ROOT):
    config = recipe(logical_id, root)
    files = source_files(root, config["sourcePath"]) + source_files(root, SHARED)
    assert_lock(root, config["sourcePath"])
    files += [safe_file(root, RECIPE)]
    if logical_id not in LOCAL_COMPONENTS:
        files += [safe_file(root, DESIRED)]
    if logical_id in CATALOG_COMPONENTS:
        assert_catalog(root)
        files += source_files(root, "packages/catalog") + source_files(root, "packages/contracts")
        if logical_id in CATALOG_COMPONENTS - {"runs-create-py"}:
            files += [safe_file(root, "services/appwrite-functions/runs-create-py/" + name)
                      for name in ("catalog-bundle.json", "runtime-bindings.json")]
    return sorted(set(files))


def identity(logical_id, root=ROOT):
    hashes = {file.relative_to(root).as_posix(): hashlib.sha256(source_bytes(file)).hexdigest() for file in inputs(logical_id, root)}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schemaVersion": "native-function-build.v1", "logicalId": logical_id, "inputsSha256": digest, "files": hashes,
            **({"localQualificationOnly": True} if logical_id in LOCAL_COMPONENTS else {})}


def stage(logical_id, output, root=ROOT):
    config = recipe(logical_id, root)
    proof = identity(logical_id, root)
    # Refuse overwrite; never remove a pre-existing directory on a workstation.
    output.mkdir(parents=True, exist_ok=False)
    for prefix, target in [(config["sourcePath"], output), (SHARED, output / "appwritework_backend")]:
        for file in source_files(root, prefix):
            destination = target / file.relative_to(root / prefix)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source_bytes(file))
    if logical_id in CATALOG_COMPONENTS - {"runs-create-py"}:
        (output / "catalog-bundle.json").write_bytes(source_bytes(safe_file(root,
            "services/appwrite-functions/runs-create-py/catalog-bundle.json")))
    (output / "build-identity.json").write_text(json.dumps(proof, indent=2) + "\n")
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["mapping", "identity", "stage", "build", "lock"])
    parser.add_argument("component")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.operation == "mapping" and args.component in LOCAL_COMPONENTS:
        raise ValueError("NATIVE_LOCAL_COMPONENT_HAS_NO_GIT_DEPLOYMENT_MAPPING")
    if args.operation == "lock":
        result = refresh_lock(args.component)
    elif args.operation == "mapping":
        result = recipe(args.component)
    elif args.operation == "identity":
        result = identity(args.component)
    else:
        if args.operation == "build" and sys.version_info[:2] != (3, 12):
            raise ValueError("NATIVE_REQUIRES_PYTHON_312")
        output = args.output or ROOT / "appwrite_function"
        result = stage(args.component, output)
        if args.operation == "build":
            # Appwrite can truncate long build output. Emit this bounded native
            # input commitment before pip logs; the complete map stays packaged.
            print(json.dumps({
                "schemaVersion": "native-function-build-summary.v1",
                "logicalId": result["logicalId"],
                "inputsSha256": result["inputsSha256"],
            }, separators=(",", ":")), flush=True)
            subprocess.run([sys.executable, "-m", "pip", "install", "--require-hashes", "-r", str(output / "requirements.lock")], check=True)
            if args.component in {"runs-create-py", "runs-status-py", "runs-steps-py", "runs-detail-py",
                                  "runs-list-py", "runs-clear-py", "runs-cancel-py", "mcp-gateway-py"}:
                subprocess.run([sys.executable, "-c", "from appwritework_backend.execution.sql_public import PublicExecution"],
                               cwd=output, check=True)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
