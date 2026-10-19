#pragma once
#include <util/types.hpp>

/*
 * Scan the read-only data sections (.rodata, .data.rel.ro, …) of an ELF
 * binary for embedded library version strings.
 *
 * Two extraction strategies are applied:
 *
 *   1. Prefix matching
 *      Known prefixes such as "OpenSSL ", "libcurl/", " inflate " are
 *      searched in every printable string found in .rodata.  The version
 *      number is extracted from the text that immediately follows.
 *
 *   2. Compound "name/version" format
 *      Many libraries embed a version banner of the form
 *        "libcurl/7.85.0 OpenSSL/3.0.5 zlib/1.2.11 nghttp2/1.51.0"
 *      A generic parser extracts all "word/X.Y.Z" pairs from such strings.
 *
 *   3. DWARF build paths
 *      Compilation-unit source paths such as
 *        "/build/openssl-3.0.5/ssl/ssl_lib.c"
 *      are parsed for the pattern "libname-X.Y.Z".
 *
 * Results are appended to `found`.  Duplicates (same name) are kept only
 * if the new entry has more information than the existing one.
 */
void scan_version_strings(const std::string& path_,
                           const std::vector<std::string>& cu_sources_,
                           std::vector<StaticLibInfo>& found_);
