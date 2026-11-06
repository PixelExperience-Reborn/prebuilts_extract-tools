#!/usr/bin/env python3
"""Source-only, non-executing audit of archived PE extract-tool prebuilts.

This gate must NEVER execute tools obtained from the unverified legacy tree.
"""
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

LEGACY_COMMIT = "7f976c19d8788f1c444c7db78a1080d7d4306b9d"
LEGACY_TREE = "d075fe2289fab010490e30f5f1454f88a74b793d"
EXPECTED_BLOBS = 33
EXPECTED_BYTES = 80_931_647
EXPECTED_BY_PREFIX = {
    "common": (3, 2_253_187),
    "darwin-x86": (20, 13_106_596),
    "linux-x86": (10, 65_571_864),
}
REQUIRED_BLOBS = {
    "common/smali/NOTICE": ("100644", "76ad9aa7d4cade15893b28ba91861c67fe002858"),
    "common/smali/baksmali.jar": ("100644", "a7cced3ea15c8db70b5f0451a176c6deab2b3cb6"),
    "common/smali/smali.jar": ("100644", "146778810942889f816e69a33206d53532328694"),
    "linux-x86/bin/ota_extractor": ("100755", "8935be135c86a0dddb16a7582857db6cb38d9163"),
    "linux-x86/bin/lpunpack": ("100755", "2bb34d5461104765b2c18cb3cdf8315ad764b04b"),
    "linux-x86/bin/simg2img": ("100755", "fc5fad734cf5c8729164ddcff5e5d62454f8daed"),
    "linux-x86/bin/patchelf-0_17_2": ("100755", "87c43f6d97170f6b7ebf62455be880d943d9c5ad"),
    "linux-x86/bin/qc_image_unpacker": ("100755", "2ea2fb4598dc6788d9ac3736ecb3bbb1b8ca0e73"),
    "linux-x86/bin/SigScan": ("100755", "68f9038c0576096bbbb7dc03f6f2fdda7478d9ef"),
    "linux-x86/bin/vdexExtractor": ("100755", "39684111315d7ba36734030537f12e65627f0f43"),
    "darwin-x86/bin/vdexExtractor": ("100755", "34b2ee1aa8cc209afcfa42c5629143e8d63a6e5e"),
}

def run_git(root, *args):
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True
    ).strip()

def require(condition, msg):
    if not condition:
        raise RuntimeError(msg)

def archived_tree(root):
    sha = run_git(root, "rev-parse", "refs/remotes/origin/seventeen")
    require(sha == LEGACY_COMMIT, f"legacy PE ref drifted: {sha}")
    tree_sha = run_git(root, "rev-parse", f"{sha}^{{tree}}")
    require(tree_sha == LEGACY_TREE, f"historic tool tree changed: {tree_sha}")

    # git object metadata only; do not execute/call --version on any binary.
    blob_lines = run_git(root, "ls-tree", "-r", "-l", sha).splitlines()
    blobs = {}
    groups = {prefix: [0, 0] for prefix in EXPECTED_BY_PREFIX}
    for line in blob_lines:
        meta, sep, path = line.partition("\t")
        require(sep == "\t", f"invalid tree line: {line!r}")
        fields = meta.split()
        require(len(fields) == 4, f"unexpected git entry: {line!r}")
        mode, kind, blob_sha, size = fields
        require(kind == "blob" and size.isdecimal(),
                f"non-file or unknown-length object: {line!r}")
        prefix = path.split("/", 1)[0]
        require(prefix in groups, f"unexpected root entry: {path}")
        require(path not in blobs, f"duplicate blob path: {path}")
        require(mode in {"100644", "100755"}, f"symlink or strange mode: {path}")
        blobs[path] = (mode, blob_sha, int(size))
        groups[prefix][0] += 1
        groups[prefix][1] += int(size)

    require(len(blobs) == EXPECTED_BLOBS,
            f"legacy blob count changed: {len(blobs)}")
    require(sum(z[2] for z in blobs.values()) == EXPECTED_BYTES,
            "legacy blob inventory byte count changed")
    require({k: tuple(v) for k, v in groups.items()} == EXPECTED_BY_PREFIX,
            f"legacy host platform inventory drifted: {groups}")
    for path, expected in REQUIRED_BLOBS.items():
        require(path in blobs and blobs[path][:2] == expected,
                f"required historic tool blob changed: {path}")
    require(not any(name.endswith((".mk", ".bp", ".sh", ".py"))
                    for name in blobs),
            "old repository unexpectedly contains build scripts/source")
    require("darwin-x86/bin/ota_extractor" not in blobs,
            "unexpected unreviewed Darwin OTA binary")
    print("PASS: exact PE binary archive commit/tree, 33 blobs / 80,931,647 bytes")
    print("PASS: audited Linux / Darwin / common inventories and 11 required SHA-1 blobs")
    print("SOURCE-ONLY: legacy binary payloads were NOT executed")

def manifest_graph(root):
    baseline = ET.parse(root / "aosp17_reference.xml").getroot()
    default = baseline.find("default")
    require(default is not None and
            default.get("remote") == "aosp" and
            default.get("revision") == "refs/tags/android-17.0.0_r1",
            "not the exact official Android17 baseline")
    paths = {
        p.get("path") or p.get("name"): p.get("name")
        for p in baseline.findall("project")
    }
    require("prebuilts/extract-tools" not in paths,
            "archived PE host tools imported into AOSP17 baseline")
    for path, official in {
        "prebuilts/build-tools": "platform/prebuilts/build-tools",
        "prebuilts/tools": "platform/prebuilts/tools",
        "system/tools/mkbootimg": "platform/system/tools/mkbootimg",
    }.items():
        require(paths.get(path) == official,
                f"official Android17 source owner changed: {path}")
    subprocess.run(
        [sys.executable, str(root / "tools/validate_aosp17_base_profiles.py")],
        cwd=root, check=True)
    entry = ET.parse(root / "default.xml").getroot()
    require(len(entry) == 1 and entry[0].tag == "include" and
            entry[0].get("name") == "aosp17_pe_p2_kernel_configs.xml",
            "latest manifest stage changed; re-audit inclusion")
    print("PASS: all reviewed Android17 profiles omit archived PE extract-tools")
    print("PASS: official build tools owner retained; no duplicate host tool imports")

def main():
    require(len(sys.argv) == 3,
            "usage: check_extract_tools_source.py PE_REPO_ROOT AOSP17_MANIFEST_ROOT")
    archive, manifest = (Path(x).resolve() for x in sys.argv[1:])
    require(archive.is_dir() and manifest.is_dir(), "missing checkout directory")
    archived_tree(archive)
    manifest_graph(manifest)
    print("PASS: extract-tools archival source-only gate")
    print("NOT TESTED: binary safety/provenance, ABI, vendor extraction, ROM build/boot")

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError,
            ValueError, ET.ParseError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
