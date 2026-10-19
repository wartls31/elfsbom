#pragma once
#include <util/types.hpp>

#include <string>
#include <vector>

/*
  Signature-based static library detection (binwalk / Detect-It-Easy style).
 
  Two complementary strategies are applied:
 
    1. Byte-pattern scanning  (binwalk-style)
       Known magic byte sequences are searched in the ELF data sections (.rodata, .data, .data.rel.ro, …).  T
       Method label: "byte-sig"
 
    2. Symbol-cluster fingerprinting  (Detect-It-Easy / FLIRT-style)
       Each supported library is described by a set of characteristic exported symbol names.  When enough of those symbols are present
       in the binary's symbol table the library is declared detected.
       Method label: "symbol-cluster"
 */
void scan_signatures(const std::string& path_, std::vector<StaticLibInfo>&      found_);
