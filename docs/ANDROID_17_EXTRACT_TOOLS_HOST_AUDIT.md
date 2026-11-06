# Android 17 source audit — archived `prebuilts/extract-tools` (matrix row 158)

## Decision (2026-11-06)

**Archive the old tools as a HOST-ONLY reference and do not import them into the Android 17 default source manifest.** Their presence is not required by the Android 17 platform build itself. A genuinely supported, reproducible vendor-blob extraction workflow is a separate prerequisite for building POCO F5 Pro / Redmi K60 (`mondrian`), and must be reviewed with the modern Python `tools/extract-utils` dependency at **matrix row 161**, without changing that row prematurely.

This is not a declaration that `ota_extractor`, `patchelf`, `lpunpack` or `simg2img` are universally unnecessary. They may be useful when extracting proprietary files from an OTA/dump, but the binary versions and invocation need independent provenance, supported host ABI, format and integrity tests.

## Reproducible source inventory

- Historical `seventeen` and `fourteen` have identical commit `7f976c19d8788f1c444c7db78a1080d7d4306b9d`, originally dated **2023-12-13**. The tip added a prebuilt `ota_extractor` reported as built from **Android 14.0.0 r17**.
- Exact archived root tree: `d075fe2289fab010490e30f5f1454f88a74b793d`.
- Git tree consists of **33 blobs**, **80,931,647 bytes** uncompressed (before Git object storage or checkout overhead).
- `linux-x86`: 10 executables, 65,571,864 bytes, including `ota_extractor` (36,167,008 B), `lpunpack`, `simg2img`, `SigScan`, `qc_image_unpacker`, `vdexExtractor`, `compact_dex_converter`, `patchelf-0_8`, `patchelf-0_9`, `patchelf-0_17_2`.
- `darwin-x86`: 20 blobs, 13,106,596 bytes: 4 executables and 16 historical runtime `.dylib` dependencies. There is **no Darwin `ota_extractor`** in this tree.
- `common`: 3 blobs, 2,253,187 bytes: `baksmali.jar`, `smali.jar` and `NOTICE`.
- There are **no** `Android.bp`, `Android.mk` or source/build scripts within the archived tree: these are already-built host utilities, not Android platform modules.

The archived executables/JARs were collected at different times (2019, 2021, 2022, 2023). The repository alone does **not** establish a full reproducible source/build chain, Linux ELF or Darwin compatibility with present-day hosts, updated OTA format support, malware/supply-chain integrity beyond immutable Git objects, or license/source disclosure for each binary. **Do not execute archived binaries in GitHub Actions just to probe `--version`.**

## Why they appeared in PixelExperience

The old PE `tools_extract-utils/extract_utils.sh` directly sets:

```bash
BINARIES_LOCATION="$ANDROID_ROOT"/prebuilts/extract-tools/${HOST}-x86/bin
SIMG2IMG="$BINARIES_LOCATION"/simg2img
LPUNPACK="$BINARIES_LOCATION"/lpunpack
OTA_EXTRACTOR="$BINARIES_LOCATION"/ota_extractor
SIGSCAN="$BINARIES_LOCATION"/SigScan
```

It also references three `patchelf` versions and the older `common/smali`, `vdexExtractor`, and `compact_dex_converter` tools. The archived `snippets/pixel-extras.xml` imported both this binary repo and `tools/extract-utils`; that Android14-era snippet is **not active** in our Android17 `default.xml`.

By contrast, the **read-only** modern `LF52406/mondrian_android_device_xiaomi_mondrian` and `LF52406/mondrian_android_device_xiaomi_sm8450-common` references on `lineage-24.0` use `extract-files.py` with `PYTHONPATH=../../../tools/extract-utils` and `ExtractUtils.device_with_common`/`ExtractUtils.device`. These are relevant architectural references, **not** permissions to merge LineageOS trees into an independent PE build. The Python helper's actual Android17 API, dependencies and blob-fixup behavior remain unvalidated and must be handled in order later.

## Android 17 effective graph

- AOSP17 reference manifest: `aosp17_reference.xml` at tag `android-17.0.0_r1`.
- The official source graph has no project path `prebuilts/extract-tools`. It does contain `prebuilts/build-tools` (`platform/prebuilts/build-tools`), `prebuilts/tools` (`platform/prebuilts/tools`), and `system/tools/mkbootimg` (`platform/system/tools/mkbootimg`). These are **not** automatically drop-in substitutes for every archived extraction binary.
- The active `default.xml` includes only the latest reviewed `aosp17_pe_p2_kernel_configs.xml`. No PE extract tools are synced by default.
- The manifest validator now rejects a newly inserted `prebuilts/extract-tools` source path/name at any of the 25 reviewed stages, with a negative regression test.
- The repo-local `audit/check_extract_tools_source.py` checks the historical Git tree identity, file counts/sizes/modes, selected blob SHAs, 25-stage manifest exclusion and official owner preservation **without running any historical executable**.
- GitHub Actions also runs eight preexisting + one newly added manifest negative regression tests and parses the active graph using the official `repo manifest` client.

## Acceptance gates for later work (row 161 / device integration)

1. Decide what Python extraction utilities and host dependencies the *new PE-Reborn* device/common stack actually needs; select one responsible owner for each utility.
2. Where tools are required, identify official/trusted upstream source revision, reproducible build route and license. Fetch exact pinned versions; do not blindly copy dated prebuilt binaries into the Android17 source graph.
3. Check and document host architectures, dynamic library dependencies, signed checksums, execution policy, and handling of untrusted OTA/dump input **before** enabling binary execution.
4. Using legal/test OTA and `super.img` inputs, validate `payload.bin` extraction, sparse / dynamic partitions, file hashes, and actual mondrian vendor blob fixups. Compare against a known-good artifact.
5. Separately pass `repo sync`, Soong/Make, blob module ownership, SELinux/VINTF, boot, Wi-Fi, camera, RIL and functional tests on actual hardware.

**Until those gates pass, do not claim Android 17 vendor extraction, full ROM compilation or device runtime compatibility.**

## Links

- Historical PE binary repository: https://github.com/PixelExperience-Reborn/prebuilts_extract-tools/tree/seventeen
- Historic OTA binary addition: https://github.com/PixelExperience-Reborn/prebuilts_extract-tools/commit/7f976c19d8788f1c444c7db78a1080d7d4306b9d
- Historic PE shell extraction helpers: https://github.com/PixelExperience-Reborn/tools_extract-utils/blob/seventeen/extract_utils.sh
- Official Android17 reviewed manifest: https://github.com/PixelExperience-Reborn/manifest/tree/port/a17-aosp17-manifest-20261102
- Reference modern device Python extractor (read-only): https://github.com/LF52406/mondrian_android_device_xiaomi_mondrian/blob/lineage-24.0/extract-files.py
- Reference modern common Python extractor (read-only): https://github.com/LF52406/mondrian_android_device_xiaomi_sm8450-common/blob/lineage-24.0/extract-files.py
- LineageOS documentation about modern Python blob extraction: https://github.com/LineageOS/lineage_wiki/blob/main/pages/internal/working_with_blobs.md

Scope: row 158 only. Both `seventeen` and the active Android17 `default.xml` preserve their original, separately controlled source ownership.
