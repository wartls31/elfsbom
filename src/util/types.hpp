#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

enum class ElfType { 
    Executable, 
    SharedLibrary,
    Unknown 
};

// A detected statically-linked library, with optional version and evidence.
struct StaticLibInfo {
    std::string _name;       // canonical name, e.g. "openssl"
    std::string _version;    // e.g. "3.0.5", empty if not detected
    std::string _method;     // "symbol" | "version-string" | "dwarf-path"
    std::string _license;    // SPDX expression, empty if unknown
};

/*
  Runtime configuration for static library detection.
 
  Level thresholds (map to method priorities from hint_priority()):
 
    off      (0)  - disable all static-lib detection
    strict   (1)  - hint-file(8), version-string(7), dwarf-path(6) only
    normal   (2)  - + symbol-defined(5), symbol-ref(4)
    extended (3)  - + symbol-cluster(3)  [C++ namespaces + FLIRT clusters]
    full     (4)  - + pkg-inferred(2), byte-sig(1)  (most aggressive)
 
  Default: extended 
 */
struct ScanConfig {
    enum class Level { Off = 0, 
                       Strict = 1,
                       Normal = 2,
                       Extended = 3,
                       Full = 4
                     };
    Level _level   = Level::Extended;
    std::set<std::string> _exclude; // lib names suppressed as false positives 
};

struct Component {
    /* Identity */
    std::string _path;       // absolute resolved path
    std::string _name;       // short name (SONAME or filename) 
    std::string _soname;     // DT_SONAME, empty if absent
    std::string _build_id;   // GNU build-id, hex-encoded

    /* ELF metadata */
    std::string _arch       = "";       // "x86_64", "aarch64", "arm", ...
    ElfType     _type       = ElfType::Unknown;
    std::string _abi_name   = "";
    bool        _stripped   = false;
    bool        _has_debug  = false;
    bool        _is_pie     = false;
    uint64_t    _size       = 0;

    /* Dynamic linking */
    std::vector<std::string> _needed;   // DT_NEEDED entries
    std::vector<std::string> _rpath;    // DT_RPATH entries
    std::vector<std::string> _runpath;  // DT_RUNPATH entries

    /* Build toolchain info from .comment */
    std::string _comment;

    /* Static analysis */
    std::vector<std::string>  _cu_sources;  // DWARF compilation unit paths
    std::vector<StaticLibInfo> _static_libs; // detected static dependencies

    /* Package manager info */
    std::string _pkg_name;
    std::string _pkg_version;
    std::string _license;      // SPDX expression or "NOASSERTION"

    /* Resolved dependency paths ("?libfoo.so.1" if unresolvable) */
    std::vector<std::string> _resolved_deps;
};

/* Dependency graph rooted at a single binary. */
struct DepGraph {
    std::string                      _root_path;
    std::map<std::string, Component> _components;      // path -> Component
    std::vector<std::string>         _discovery_order; // BFS insertion order
};

/*
 * Consolidated graph from a directory scan.
 * Roots are the ELF files found directly in the scanned tree.
 */
struct MultiGraph {
    std::string                          _scan_root;    // scanned directory
    std::vector<std::string>             _roots;        // files in scan_root
    std::map<std::string, Component>     _components;   // path -> Component
    std::vector<std::string>             _ordered;      // dedup BFS order
  
    /* Which root ELFs pull in each dependency */
    std::map<std::string, std::set<std::string>> _users; // dep -> {roots}
};
