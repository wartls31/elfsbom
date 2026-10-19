#pragma once
#include <util/types.hpp>

/*
  Scan the read-only data sections (.rodata, .data.rel.ro, …) of an ELF binary for embedded library version strings.
 
    1. Prefix matchine
    2. Compound "name/version" format
    3. DWARF build paths
 */
void scan_version_strings(const std::string& path_, const std::vector<std::string>& cu_sources_, std::vector<StaticLibInfo>& found_);
