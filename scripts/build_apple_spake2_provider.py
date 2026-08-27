#!/usr/bin/env python3
"""Build the restricted Apple SPAKE2+ provider from a pinned pristine Botan archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/apple-botan-3.13.0.json"
WRAPPER = ROOT / "native/apple-spake2/AuroraACPSPAKE2.cpp"
HEADER_DIR = ROOT / "native/apple-spake2/include"
SMOKE = ROOT / "native/apple-spake2/tests/provider_smoke.cpp"
EPOCH = 946684800  # 2000-01-01 UTC


def run(arguments: list[str], *, cwd: Path | None = None, capture: bool = False) -> str:
    result = subprocess.run(arguments, cwd=cwd, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else ""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_pristine(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:xz") as bundle:
        root = destination.resolve()
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if root not in target.parents and target != root:
                raise SystemExit(f"unsafe archive member: {member.name}")
        bundle.extractall(destination, filter="data")
    candidates = [value for value in destination.iterdir() if value.is_dir()]
    if len(candidates) != 1:
        raise SystemExit("official archive did not contain exactly one source root")
    return candidates[0]


def canonical_manifest(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(value for value in root.rglob("*") if value.is_file()):
        entries.append({
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256(path),
        })
    return entries


def normalize(root: Path) -> None:
    for plist in root.rglob("Info.plist"):
        value = plistlib.loads(plist.read_bytes())
        if isinstance(value.get("AvailableLibraries"), list):
            value["AvailableLibraries"].sort(key=lambda item: item["LibraryIdentifier"])
        plist.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True))
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            raise SystemExit(f"packaged symlink forbidden: {path}")
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
    os.utime(root, (EPOCH, EPOCH))


def normalize_static_archive(path: Path) -> None:
    """Normalize BSD ar member timestamps, owners, groups, and modes in place."""
    value = bytearray(path.read_bytes())
    if value[:8] != b"!<arch>\n":
        raise SystemExit(f"not a static archive: {path}")
    offset = 8
    while offset < len(value):
        if offset + 60 > len(value) or value[offset + 58:offset + 60] != b"`\n":
            raise SystemExit(f"malformed static archive: {path} at {offset}")
        try:
            size = int(value[offset + 48:offset + 58].decode("ascii").strip())
        except ValueError as error:
            raise SystemExit(f"malformed member size in {path}") from error
        value[offset + 16:offset + 28] = b"0           "
        value[offset + 28:offset + 34] = b"0     "
        value[offset + 34:offset + 40] = b"0     "
        value[offset + 40:offset + 48] = b"100644  "
        offset += 60 + size
        if offset % 2:
            offset += 1
    path.write_bytes(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    args = parser.parse_args()

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    xcode = run(["xcodebuild", "-version"], capture=True).replace("\n", " / ")
    if xcode != config["toolchain"]["qualified_xcode"]:
        raise SystemExit(f"unqualified Xcode: expected {config['toolchain']['qualified_xcode']}, got {xcode}")
    expected_hash = config["botan"]["sha256"]
    actual_hash = sha256(args.source_archive)
    if actual_hash != expected_hash:
        raise SystemExit(f"Botan source hash mismatch: expected {expected_hash}, got {actual_hash}")
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")

    work = args.output / "work"
    source = extract_pristine(args.source_archive, work / "source")
    slices = args.output / "slices"
    products: list[tuple[dict[str, str], Path, Path]] = []
    compiler = run(["xcrun", "--find", "clang++"], capture=True)
    libtool = run(["xcrun", "--find", "libtool"], capture=True)

    for target in config["targets"]:
        target_id = target["id"]
        build_source = work / target_id
        shutil.copytree(source, build_source, copy_function=shutil.copy2)
        sdk_path = run(["xcrun", "--sdk", target["sdk"], "--show-sdk-path"], capture=True)
        sdk_version = run(["xcrun", "--sdk", target["sdk"], "--show-sdk-version"], capture=True)
        if sdk_version != target["sdk_version"]:
            raise SystemExit(f"{target_id}: expected SDK {target['sdk_version']}, got {sdk_version}")
        abi_flags = (
            f"-target {target['triple']} -isysroot {sdk_path} "
            f"-ffile-prefix-map={build_source}=/botan -fdebug-prefix-map={build_source}=/botan"
        )
        configure = [
            str(build_source / "configure.py"),
            *config["configure"]["flags"],
            f"--cc-bin={compiler}",
            f"--cc-abi-flags={abi_flags}",
            "--build-targets=static",
        ]
        run(configure, cwd=build_source, capture=True)
        build_config = json.loads((build_source / "build/build_config.json").read_text(encoding="utf-8"))
        actual_modules = sorted(build_config["mod_list"])
        expected_modules = sorted(config["module_closure"])
        if actual_modules != expected_modules:
            raise SystemExit(
                f"{target_id} Botan module drift:\nexpected={expected_modules}\nactual={actual_modules}"
            )
        if "pcurves_secp256r1" not in actual_modules:
            raise SystemExit(f"{target_id}: required pcurves_secp256r1 missing")
        run(["make", f"-j{args.jobs}", "libs"], cwd=build_source, capture=True)

        slice_dir = slices / target_id
        headers = slice_dir / "Headers"
        headers.mkdir(parents=True)
        shutil.copy2(HEADER_DIR / "AuroraACPSPAKE2.h", headers / "AuroraACPSPAKE2.h")
        wrapper_object = slice_dir / "AuroraACPSPAKE2.o"
        common_compile = [
            compiler, "-std=c++20", "-O2", "-fvisibility=hidden", "-fno-ident",
            "-ffile-prefix-map=" + str(build_source) + "=/botan",
            "-ffile-prefix-map=" + str(ROOT) + "=/aurora-acp",
            "-target", target["triple"], "-isysroot", sdk_path,
            "-I", str(HEADER_DIR),
            "-I", str(build_source / "build/include/public"),
            "-I", str(build_source / "build/include/internal"),
        ]
        run([*common_compile, "-c", str(WRAPPER), "-o", str(wrapper_object)])
        library = slice_dir / "libAuroraACPSPAKE2.a"
        run([libtool, "-static", "-o", str(library), str(wrapper_object), str(build_source / "libbotan-3.a")])
        normalize_static_archive(library)

        smoke_binary = slice_dir / "provider-smoke"
        run([*common_compile, str(SMOKE), str(library), "-o", str(smoke_binary)])
        if target["sdk"] == "macosx":
            run([str(smoke_binary)])
        products.append((target, library, headers))

    xcframework = args.output / "AuroraACPSPAKE2.xcframework"
    command = ["xcodebuild", "-create-xcframework"]
    for _, library, headers in products:
        command.extend(["-library", str(library), "-headers", str(headers)])
    command.extend(["-output", str(xcframework)])
    run(command, capture=True)
    normalize(xcframework)

    manifest = canonical_manifest(xcframework)
    manifest_path = args.output / "canonical-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.utime(manifest_path, (EPOCH, EPOCH))
    summary = {
        "schema_version": 1,
        "botan_version": config["botan"]["version"],
        "botan_source_sha256": actual_hash,
        "module_closure": config["module_closure"],
        "targets": [target["id"] for target, _, _ in products],
        "manifest_sha256": sha256(manifest_path),
        "functional_smoke": {
            "macos-arm64": "PASS",
            "ios-arm64": "COMPILE_LINK_PASS_RUNTIME_NOT_RUN",
            "ios-simulator-arm64": "COMPILE_LINK_PASS_RUNTIME_NOT_RUN",
        },
    }
    summary_path = args.output / "build-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.utime(summary_path, (EPOCH, EPOCH))
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
