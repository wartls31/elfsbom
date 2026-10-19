#pragma once
#include <util/types.hpp>

/*
  Parse an ELF file and populate all fields of Component, including:
   - ELF header metadata (arch, type, ABI, PIE, stripped, has_debug)
   - .dynamic section  (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH)
   - .note.gnu.build-id
   - ._comment section
   - Symbol tables  → static library heuristics (symbol-prefix method)
   - .debug_info    → DWARF CU source paths
   - .rodata*       → embedded version strings (string_scanner)
 
  Returns false if the file is not a valid ELF or cannot be opened.
 */
bool parse_elf_file(const std::string& path_, Component& comp_);
