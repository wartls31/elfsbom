#pragma once
#include <util/types.hpp>
#include <set>
#include <string>
#include <vector>

/*
 * Result of parsing a hints file.
 */
struct HintsFile {
    std::vector<StaticLibInfo> _libs;     /* positive hints  */
    std::set<std::string>      _excludes; /* false-positive suppressions */
};

/*
 * Load a user-provided static dependency hints file.
 *
 * ── Positive hint (name [version [license]])  ────────────────────────────
 *
 *   product                        name only   (version and license unknown)
 *   product  version               name + version
 *   product  version  license      name + version + SPDX expression
 *   product  -        license      name + license, version unknown ('-' placeholder)
 *   # comment                      ignored
 *   (blank line)                   ignored
 *
 * Example:
 *
 *   openssl  3.0.5   Apache-2.0
 *   zlib     1.2.11  Zlib
 *   my_lib   -       LicenseRef-Proprietary
 *   unknown_embedded_sdk
 *
 * All positive entries get method = "hint-file".
 *
 * ── Exclusion line (!name)  ──────────────────────────────────────────────
 *
 * A line starting with '!' marks a library as a false positive.  Entries
 * with that name produced by any automated detection method are suppressed
 * from the SBOM output.  This applies after all other detections have run,
 * so it overrides symbol-cluster, byte-sig, version-string, etc.
 *
 *   !opencv          # byte-sig or namespace hit was a false positive
 *   !snappy          # embedded test data triggered the byte pattern
 *
 * Exclusion lines must not carry a version or license field (the name is
 * the only token; the rest of the line is treated as a comment).
 *
 * ── Order ────────────────────────────────────────────────────────────────
 *
 * Positive hints and exclusions may be freely intermixed.  An exclusion
 * for a name that also appears as a positive hint causes that hint to be
 * suppressed along with any automatically detected entries.
 *
 * No package-manager or database lookup is performed.
 */
HintsFile load_hints_file(const std::string& path_);
