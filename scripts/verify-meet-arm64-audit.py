#!/usr/bin/env python3
"""Independent release gate. Public output contains status and hashes only."""
import argparse
import hashlib
import json
from pathlib import Path

TARGETS = {"ggml", "ggml-base", "ggml-cpu", "whisper"}
SELF_TESTS = {"armv8-neon", "sve-rdvl", "sve2-eor3", "sme-zero",
              "sme-smstart", "sme-smstop", "i8mm", "bf16", "dotprod"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition):
    if not condition:
        raise ValueError("audit rejected")


def inside(path, root):
    require(path.is_absolute() and path.is_file() and not path.is_symlink())
    require(path.resolve().is_relative_to(root.resolve()))
    return path


def verify(build_root, scanner, build_start):
    require(build_start > 0)
    reports = list(build_root.glob("whisper-rs-sys-*/out/build/scai-meet-isa/Release/audit.json"))
    require(len(reports) == 1)
    report_path = reports[0]
    inside(report_path, build_root)
    require(report_path.stat().st_mtime >= build_start)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    scanner_hash = digest(scanner)
    require(report["status"] == "pass" and report["scanner_sha256"] == scanner_hash)
    require(report["policy"] == "ARMv8-A + FP/NEON; no ISA exceptions")
    require(report["violation_count"] == 0)
    tests = report["self_test"]
    require(len(tests) == len(SELF_TESTS) and {t["case"] for t in tests} == SELF_TESTS)
    for test in tests:
        rejected = test["case"] != "armv8-neon"
        require(test["expected_rejection"] is rejected and test["rejected"] is rejected)
    require(len(report["targets"]) == len(TARGETS))
    hashes = {}
    seen = set()
    for target in report["targets"]:
        manifest = inside(Path(target["manifest"]), build_root)
        name = manifest.name.removesuffix(".objects.txt")
        require(name in TARGETS and name not in hashes)
        require(manifest.parent.resolve() == report_path.parent.resolve())
        paths = [str(Path(line).resolve()) for line in manifest.read_text(encoding="utf-8").splitlines() if line]
        objects = target["objects"]
        require(paths and paths == [str(Path(obj["path"]).resolve()) for obj in objects])
        require(sum(obj["instruction_count"] for obj in objects) > 0)
        object_hashes = []
        for obj in objects:
            path = inside(Path(obj["path"]), build_root)
            require(path.suffix.lower() in (".obj", ".o") and path.resolve() not in seen)
            seen.add(path.resolve())
            require(obj["violations"] == [] and type(obj["instruction_count"]) is int and obj["instruction_count"] >= 0)
            actual = digest(path)
            require(obj["sha256"] == actual)
            object_hashes.append(actual)
        hashes[name] = hashlib.sha256("\n".join(object_hashes).encode()).hexdigest()
    require(set(hashes) == TARGETS)
    return {"status": "pass", "scanner_sha256": scanner_hash,
            "audit_sha256": digest(report_path), "targets_sha256": hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--build-start", type=int, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.build_root.resolve(), args.scanner, args.build_start)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        result = {"status": "fail"}
    result["verifier_sha256"] = digest(Path(__file__))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
