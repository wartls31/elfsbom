#pragma once
#include <string>
#include <vector>

/*
 * Recursively walk `dir` and return the absolute paths of all regular files
 * that are ELF executables or shared libraries.
 *
 * Detection is based on the ELF magic bytes (0x7f 'E' 'L' 'F') rather than
 * file extension, so files without a ".so" suffix are also found.
 *
 * skip_objects : when true, skip ELF relocatable files (ET_REL, e_type == 1),
 *                i.e. compiled object files (.o).  These are intermediate build
 *                artefacts — they contain no DT_NEEDED and are not deployed.
 *
 * Symlinks are followed; already-visited inodes are skipped to handle loops.
 */
std::vector<std::string> scan_elf_files(const std::string& dir_,  bool skip_objects_ = false);

/* Return true if the file at `path` starts with the ELF magic bytes. */
bool is_elf_file(const std::string& path_);
