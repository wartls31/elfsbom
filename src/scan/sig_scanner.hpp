#pragma once
#include <util/types.hpp>

#include <string>
#include <vector>

/*
 * Signature-based static library detection (binwalk / Detect-It-Easy style).
 *
 * Two complementary strategies are applied:
 *
 *   1. Byte-pattern scanning  (binwalk-style)
 *      Known magic byte sequences are searched in the ELF data sections
 *      (.rodata, .data, .data.rel.ro, …).  The presence of a format's
 *      magic header is strong evidence that the corresponding codec or
 *      library is statically linked.
 *      Method label: "byte-sig"
 *
 *   2. Symbol-cluster fingerprinting  (Detect-It-Easy / FLIRT-style)
 *      Each supported library is described by a set of characteristic
 *      exported symbol names.  When enough of those symbols are present
 *      in the binary's symbol table the library is declared detected.
 *      This works even for stripped builds where no version string survives.
 *      Method label: "symbol-cluster"
 *
 * Results are appended to found_.  Duplicates (same name) are kept only
 * if the new entry carries more information than the existing one.
 * Version is always empty for these detection methods; the caller may
 * attempt to fill it in via package-manager queries.
 */
void scan_signatures(const std::string&              path_,
                     std::vector<StaticLibInfo>&      found_);
