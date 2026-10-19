# elf-sbom

ELF binary SBOM generator — produces **CycloneDX 1.6** and **SPDX 2.3** SBOMs from ELF binaries or directories.

## Features

- Dynamic dependency resolution (DT_NEEDED + RPATH/RUNPATH/`ld.so.conf`/`$ORIGIN`)
- Static library detection via symbol analysis (~80 patterns: OpenSSL, zlib, zstd, libcurl, sqlite3, lua…)
- Version extraction from `.rodata` strings, DWARF build paths, and Debian/RPM package names
- Package manager integration (dpkg / rpm / apk)
- Hints file for manual version and SPDX license overrides
- License detection (package manager + known-lib table + `.rodata` SPDX scan)
- Directory scan mode — recursive ELF discovery, deduplicated multi-graph output
- CycloneDX 1.6 (Cyberwatch-compatible), SPDX 2.3 tag-value, and human-readable text output
- Warnings for missing versions and licenses (text report + stderr for SBOM formats)

## Build

```bash
# Dependencies
apt install libelf-dev libdw-dev pkg-config   # Debian/Ubuntu
# or
dnf install elfutils-devel pkgconf-pkg-config  # Fedora/RHEL

make
```

## Usage

```
elf-sbom [OPTIONS] <elf-file | directory>

  -f, --format   text|cyclonedx|spdx    (default: text)
  -o, --output   <file>                 (default: stdout)
  -H, --hints    <file>                 static hints file
  -d, --depth    <n>                    max resolution depth (default: 64)
  -s, --no-system                       skip system libraries
  -p, --no-pkg                          skip package manager queries
  -O, --no-obj                          skip ET_REL object files
  -h, --help
```

### Examples

```bash
# CycloneDX SBOM for a single binary
elf-sbom -f cyclonedx /usr/bin/curl -o curl.cdx.json

# Scan an entire firmware directory
elf-sbom -f cyclonedx /path/to/rootfs/ -o firmware.cdx.json

# With a hints file (manual version/license overrides)
elf-sbom -H hints.txt -f cyclonedx /usr/bin/openssl
```

### Hints file format

```
# name  [version|-]  [license SPDX-expression...]
openssl   3.0.5       Apache-2.0
my_lib    -           LicenseRef-Proprietary
unknown_rtos
```

## Output formats

| Format | Notes |
|--------|-------|
| `text` | Human-readable report with version/license warnings |
| `cyclonedx` | CycloneDX 1.6 JSON — compatible with Cyberwatch and `sbom-tool validate` |
| `spdx` | SPDX 2.3 tag-value |
