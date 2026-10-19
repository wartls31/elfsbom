#include <util/os_detect.hpp>
#include <scan/resolver.hpp>
#include <scan/elf_parser.hpp>
#include <query/hints_file.hpp>
#include <query/license.hpp>

#include <query/pkg_query.hpp>
#include <out/sbom_writer.hpp>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>


static void usage(const char* prog_) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] <elf-file | directory>\n\n"
        "Analyse ELF binaries and emit a Software Bill of Materials (SBOM).\n\n"
        "  Single file : full transitive dynamic dependency graph\n"
        "  Directory   : all ELF files are analysed; dependencies are\n"
        "                deduplicated across all roots\n\n"
        "Options:\n"
        "  -f, --format <fmt>         text | cyclonedx | spdx  (default: text)\n"
        "  -o, --output <file>        output file              (default: stdout)\n"
        "  -H, --hints  <file>        static dependency hints file\n"
        "                             Positive hint:  product [version [license]]\n"
        "                             Exclusion:      !product\n"
        "  -d, --depth <n>            max recursion depth      (default: 64)\n"
        "  -s, --no-system            skip system libraries\n"
        "  -O, --no-obj               skip ELF object files (ET_REL, .o)\n"
        "      --static-level <lvl>   static lib detection aggressiveness:\n"
        "                               off      — disabled\n"
        "                               strict   — version strings + DWARF paths\n"
        "                               normal   — + symbol table analysis\n"
        "                               extended — + symbol clusters + C++ namespaces (default)\n"
        "                               full     — + byte patterns + pkg-manager versions\n"
        "  -x, --exclude-lib <name>   suppress a library from results (false positive);\n"
        "                             repeatable: -x opencv -x snappy\n"
        "  -h, --help                 print this help\n\n"
        "Examples:\n"
        "  %s /usr/bin/curl\n"
        "  %s -f cyclonedx -o sbom.json -H deps.hints ./my_program\n"
        "  %s -f spdx -o sbom.spdx --static-level=full --exclude-lib=opencv ./build/\n"
        "  %s -f text --static-level=strict -x libpng -x giflib ./binary\n",
        prog_, prog_, prog_, prog_, prog_);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Version inference from package names
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * Extract the upstream version from a Debian/RPM package version string.
 * Strips epoch ("1:") and Debian revision ("-0ubuntu…").
 *
 *   "3.0.13-0ubuntu3.9"       → "3.0.13"
 *   "1:1.3.dfsg-3.1ubuntu2.1" → "1.3"
 *   "2:6.3.0+dfsg-2ubuntu6.1" → "6.3.0"
 *   "1.59.0-1ubuntu0.2"       → "1.59.0"
 */
static std::string extract_upstream_version(const std::string& pkg_ver_) {
    const char* s = pkg_ver_.c_str();
    /* Skip epoch */
    const char* colon = strchr(s, ':');
    if (colon) {
        s = colon + 1;
    }
    /* Collect digits and dots only */
    std::string ver;
    while (*s && (isdigit((unsigned char)*s) || *s == '.')) {
        ver += *s++;
    }
    while (!ver.empty() && ver.back() == '.') {
        ver.pop_back();
    }
    return ver;
}

/*
 * Extract a version number from a Debian/Ubuntu package name.
 *
 * Conventions handled:
 *   libssl3        → "3"         simple suffix
 *   libssl1.1      → "1.1"       dotted suffix
 *   libcurl4t64    → "4"         "t64" ABI-transition suffix stripped
 *   libgnutls30t64 → "30"        same
 *   libz1g / zlib1g→ "1"         single-letter Debian artifact stripped
 *   libnghttp2-14  → "14"        dash-separated SOABI (prefer after last dash)
 *   libpng16-16    → "16"        same
 *   libpcre2-8-0   → "8"         char-width component after first dash
 *
 * Strategy:
 *   1. Strip known non-version suffixes (t64, g) from the END.
 *   2. If a '-' exists, take the digit cluster after the LAST '-'.
 *   3. Otherwise, scan backwards from the end for the trailing digit/dot run.
 */
static std::string version_from_pkg_name(const std::string& pkg_name_) {
    if (pkg_name_.empty()) {
        return {};
    }

    /* Step 1 – strip known Debian package name suffixes */
    static const char* const SUFFIXES[] = {
        "t64",  /* 64-bit time_t transition, e.g. libcurl4t64 */
        "g",    /* Debian artifact,          e.g. zlib1g      */
        nullptr
    };
    std::string s = pkg_name_;
    for (int i = 0; SUFFIXES[i]; i++) {
        size_t sl = strlen(SUFFIXES[i]);
        if (s.size() > sl && s.substr(s.size() - sl) == SUFFIXES[i]) {
            s = s.substr(0, s.size() - sl);
            break;
        }
    }

    /* Step 2 – prefer the digit cluster after the last '-' separator.
     * This correctly handles "libnghttp2-14" → "14", "libpng16-16" → "16". */
    size_t dash = s.rfind('-');
    if (dash != std::string::npos && dash + 1 < s.size()
        && isdigit((unsigned char)s[dash + 1])) {
        std::string after(s.c_str() + dash + 1);
        /* Collect digits and dots from the start */
        std::string ver;
        for (char c : after) {
            if (isdigit((unsigned char)c) || c == '.') {
                ver += c;
            } else {
                break;
            }
        }
        while (!ver.empty() && ver.back() == '.') {
            ver.pop_back();
        }
        if (!ver.empty()) {
            return ver;
        }
    }

    /* Step 3 – no dash: scan backward from end for trailing digit/dot run.
     * Handles "libssl3" → "3", "libssl1.1" → "1.1", "libgnutls30" → "30". */
    const char* p = s.c_str() + s.size();
    while (p > s.c_str() && (isdigit((unsigned char)*(p-1)) || *(p-1) == '.')) {
        p--;
    }

    /* Must start with a digit and not be preceded by '-' */
    if (!isdigit((unsigned char)*p)) {
        return {};
    }
    if (p > s.c_str() && *(p-1) == '-') {
        /* Preceded by dash → already handled in step 2, skip */
        return {};
    }

    std::string ver(p);
    while (!ver.empty() && ver.back() == '.') {
        ver.pop_back();
    }
    return ver.empty() ? "" : ver;
}

/*
 * Return true when a library name and a package name refer to the same
 * upstream project.
 *
 * Normalization: lowercase, strip leading "lib", strip trailing digits and
 * non-alpha characters.  Then check substring containment both ways.
 *
 * Examples:
 *   "openssl"  ↔ "libssl3"     → norm "openssl" ↔ "ssl"   → "openssl" ⊃ "ssl"  ✓
 *   "zlib"     ↔ "zlib1g"      → norm "zlib"    ↔ "zlib"  → equal               ✓
 *   "libcurl"  ↔ "libcurl4t64" → norm "curl"    ↔ "curl"  → equal               ✓
 *   "nghttp2"  ↔ "libnghttp2-14"→ norm "nghttp2" ↔ "nghttp2" → equal            ✓
 *   "gnutls"   ↔ "libgnutls30"  → norm "gnutls"  ↔ "gnutls"  → equal            ✓
 */
static bool lib_matches_pkg(const std::string& lib_name_,
                              const std::string& pkg_name_) {
    if (lib_name_.empty() || pkg_name_.empty()) {
        return false;
    }

    auto norm = [](const std::string& s) -> std::string {
        std::string r;
        for (char c : s) {
            r += (char)tolower((unsigned char)c);
        }
        if (r.size() >= 3 && r.substr(0, 3) == "lib") {
            r = r.substr(3);
        }
        /* Strip trailing non-alpha (digits, '-', '+', …) */
        size_t end = r.size();
        while (end > 0 && !isalpha((unsigned char)r[end-1])) {
            end--;
        }
        return r.substr(0, end);
    };

    const std::string ln = norm(lib_name_);
    const std::string pn = norm(pkg_name_);
    if (ln.empty() || pn.empty()) {
        return false;
    }

    return ln.find(pn) != std::string::npos ||
           pn.find(ln) != std::string::npos;
}

/*
 * Infer missing versions from package metadata.
 *
 * Pass 1 – Dynamic components with empty pkg_version but known pkg_name:
 *   Apply version_from_pkg_name() as a last resort.
 *
 * Pass 2 – Static libs with no detected version:
 *   a) Host ELF's own pkg_name/pkg_version, when the names match.
 *   b) Any resolved dynamic dependency whose name matches the static lib.
 *
 * Called after query_package_info() so that pkg_name / pkg_version are set.
 */
static void infer_versions_from_pkg(std::map<std::string, Component>& comps_) {
    for (auto& [path, comp] : comps_) {

        /* -- Pass 1: dynamic component with no version -- */
        if (comp._pkg_version.empty() && !comp._pkg_name.empty()) {
            comp._pkg_version = version_from_pkg_name(comp._pkg_name);
        }

        /* -- Pass 2: static libs -- */
        for (auto& sl : comp._static_libs) {
            if (!sl._version.empty()) {
                continue;
            }

            /* (a) Does the host ELF's package match this static lib? */
            if (!comp._pkg_name.empty() && lib_matches_pkg(sl._name, comp._pkg_name)) {
                if (!comp._pkg_version.empty()) {
                    sl._version = extract_upstream_version(comp._pkg_version);
                }
                if (sl._version.empty()) {
                    sl._version = version_from_pkg_name(comp._pkg_name);
                }
                /*
                 * A statically linked library is typically a custom build
                 * that does NOT match the system package: different configure
                 * flags, patches, or commit.  Tag the version as "pkg-inferred"
                 * so consumers know it is an approximation.
                 */
                if (!sl._version.empty()) {
                    sl._method = "pkg-inferred";
                }
            }

            if (!sl._version.empty()) {
                continue;
            }

            /* (b) Look at resolved dynamic dependencies */
            for (const auto& dep_path : comp._resolved_deps) {
                if (dep_path[0] == '?') {
                    continue;
                }
                auto it = comps_.find(dep_path);
                if (it == comps_.end()) {
                    continue;
                }
                const Component& dep = it->second;

                bool match = (!dep._pkg_name.empty()  && lib_matches_pkg(sl._name, dep._pkg_name))
                          || (!dep._name.empty()       && lib_matches_pkg(sl._name, dep._name))
                          || (!dep._soname.empty()     && lib_matches_pkg(sl._name, dep._soname));

                if (match) {
                    if (!dep._pkg_version.empty()) {
                        sl._version = extract_upstream_version(dep._pkg_version);
                    }
                    if (sl._version.empty() && !dep._pkg_name.empty()) {
                        sl._version = version_from_pkg_name(dep._pkg_name);
                    }
                    if (!sl._version.empty()) {
                        sl._method = "pkg-inferred";
                        break;
                    }
                }
            }
        }
    }
}

/* ── Hint-file licence fallback for components with no detected licence ─── */
/*
 * After normal license detection, some components may still have no licence.
 * This pass looks up each such component by name in the hints-file map and
 * assigns the hint licence, regardless of version.
 *
 * Matching order for dynamic components:
 *   1. pkg_name  (e.g. "libssl3" → hint "libssl3")
 *   2. name      (soname or filename, e.g. "libssl.so.3")
 *   3. _soname base (e.g. "libssl.so.3" → try "libssl")
 *
 * For static libs: exact name match on sl._name.
 */
static void apply_hint_license_fallback(
    std::map<std::string, Component>& comps_,
    const std::vector<StaticLibInfo>& hints_) {
    /* Build name → licence map (first entry with that name wins) */
    std::map<std::string, std::string> lic_map;
    for (const auto& h : hints_) {
        if (!h._license.empty() && !lic_map.count(h._name)) {
            lic_map[h._name] = h._license;
        }
    }

    if (lic_map.empty()) {
        return;
    }

    for (auto& [path, comp] : comps_) {
        /* Dynamic component */
        if (comp._license.empty()) {
            auto try_name = [&](const std::string& n) -> bool {
                if (n.empty()) {
                    return false;
                }
                auto it = lic_map.find(n);
                if (it != lic_map.end()) {
                    comp._license = it->second;
                    return true;
                }
                return false;
            };
            if (!try_name(comp._pkg_name) && !try_name(comp._name)
                                         && !try_name(comp._soname)) {
                /* Try soname base: "libssl.so.3" → "libssl" */
                if (!comp._soname.empty()) {
                    auto dot = comp._soname.find(".so.");
                    if (dot != std::string::npos) {
                        try_name(comp._soname.substr(0, dot));
                    }
                }
            }
        }
        /* Static libs */
        for (auto& sl : comp._static_libs) {
            if (sl._license.empty()) {
                auto it = lic_map.find(sl._name);
                if (it != lic_map.end()) {
                    sl._license = it->second;
                }
            }
        }
    }
}

/* ── Merge hint-file entries into a component's static_libs ─────────────── */
/*
 * Merge rules (key = name + version):
 *
 *   Same name + same version → merge: upgrade method if hint has higher priority.
 *
 *   Same name + hint has version + existing entry has NO version
 *     → upgrade the existing entry (the hint provides the version we lacked).
 *
 *   Same name + DIFFERENT non-empty versions
 *     → add as a new distinct entry (different version = different component).
 *
 *   New name → add.
 *
 * This ensures that openssl@3.0.5 (hint) and openssl@3.0.13 (auto-detected)
 * coexist as two separate SBOM components with distinct PURLs and CVE sets.
 */
static int hint_priority(const std::string& method_) {
    if (method_ == "hint-file")       return 8;
    if (method_ == "version-string")  return 7;
    if (method_ == "dwarf-path")      return 6;
    if (method_ == "symbol-defined")  return 5;
    if (method_ == "symbol-ref")      return 4;
    if (method_ == "symbol-cluster")  return 3;
    if (method_ == "pkg-inferred")    return 2;
    if (method_ == "byte-sig")        return 1;
    return 0;
}

/* ── Static-lib detection filter ────────────────────────────────────────── */

/*
 * Translate a ScanConfig::Level to the minimum method priority that passes.
 *
 * Priority scale (mirrors hint_priority / static_lib_priority):
 *   8  hint-file        7  version-string   6  dwarf-path
 *   5  symbol-defined   4  symbol-ref       3  symbol-cluster
 *   2  pkg-inferred     1  byte-sig
 *
 * Level thresholds:
 *   strict   → 6   (accepts 6, 7, 8)
 *   normal   → 4   (accepts 4–8)
 *   extended → 3   (accepts 3–8)
 *   full     → 1   (accepts all)
 */
static int scan_level_min_priority(ScanConfig::Level level_) {
    switch (level_) {
        case ScanConfig::Level::Off:      return 999;
        case ScanConfig::Level::Strict:   return 6;
        case ScanConfig::Level::Normal:   return 4;
        case ScanConfig::Level::Extended: return 3;
        case ScanConfig::Level::Full:     return 1;
    }
    return 1;
}

/*
 * Filter a component's static-lib list according to the scan configuration.
 *
 * An entry is removed when:
 *   (a) its name is in cfg_._exclude  — explicit false-positive suppression, OR
 *   (b) its detection method priority is below the configured level threshold.
 *
 * Exclusion (a) applies even to hint-file entries, allowing a hints file to
 * both add known libs AND suppress wrong auto-detections in the same file.
 * Level filtering (b) never removes hint-file entries at Strict or above,
 * since hint-file priority (8) is always ≥ 6.
 */
static void apply_scan_config(Component& comp_, const ScanConfig& cfg_) {
    /* Fast path: nothing to filter */
    if (cfg_._level == ScanConfig::Level::Full && cfg_._exclude.empty()) {
        return;
    }

    int min_p = scan_level_min_priority(cfg_._level);

    auto it = std::remove_if(
        comp_._static_libs.begin(), comp_._static_libs.end(),
        [&](const StaticLibInfo& sl_) {
            if (cfg_._exclude.count(sl_._name)) {
                return true;
            }
            return hint_priority(sl_._method) < min_p;
        });
    comp_._static_libs.erase(it, comp_._static_libs.end());
}

static void apply_hints(Component& comp_,
                         const std::vector<StaticLibInfo>& hints_) {
    for (const auto& h : hints_) {
        bool handled = false;

        for (auto& s : comp_._static_libs) {
            if (s._name != h._name) {
                continue;
            }

            /* Case 1: exact (name, version) match → merge method */
            if (s._version == h._version) {
                if (hint_priority(h._method) > hint_priority(s._method)) {
                    s._method = h._method;
                }
                handled = true;
                break;
            }

            /* Case 2: existing entry has no version and hint provides one
             *         → fill in the version (hint clarifies what we found) */
            if (s._version.empty() && !h._version.empty()) {
                s._version = h._version;
                s._method  = h._method;   /* hint-file = authoritative */
                handled = true;
                break;
            }

            /* Case 3: different non-empty versions → fall through, add new */
        }

        if (!handled) {
            comp_._static_libs.push_back(h);
        }
    }
}

int main(int argc_, char* argv_[]) {
    const char* format     = "text";
    const char* output     = nullptr;
    const char* hints_path = nullptr;
    int         max_depth  = 64;
    bool        no_system  = false;
    bool        no_pkg     = false;
    bool        no_obj     = false;
    ScanConfig  cfg;   /* default: Level::Extended, no exclusions */

    /* 'L' and 'x' are internal codes for long-only options */
    static const option LONG[] = {
        { "format",       required_argument, nullptr, 'f' },
        { "output",       required_argument, nullptr, 'o' },
        { "hints",        required_argument, nullptr, 'H' },
        { "depth",        required_argument, nullptr, 'd' },
        { "no-system",    no_argument,       nullptr, 's' },
        { "no-pkg",       no_argument,       nullptr, 'p' },
        { "no-obj",       no_argument,       nullptr, 'O' },
        { "static-level", required_argument, nullptr, 'L' },
        { "exclude-lib",  required_argument, nullptr, 'x' },
        { "help",         no_argument,       nullptr, 'h' },
        { nullptr, 0, nullptr, 0 }
    };

    int c;
    while ((c = getopt_long(argc_, argv_, "f:o:H:d:spOx:h", LONG, nullptr)) != -1) {
        switch (c) {
            case 'f': format     = optarg;       break;
            case 'o': output     = optarg;       break;
            case 'H': hints_path = optarg;       break;
            case 'd': max_depth  = atoi(optarg); break;
            case 's': no_system  = true;         break;
            case 'p': no_pkg     = true;         break;
            case 'O': no_obj     = true;         break;
            case 'x': cfg._exclude.insert(optarg); break;
            case 'L':
                if      (strcmp(optarg, "off")      == 0) { cfg._level = ScanConfig::Level::Off;      }
                else if (strcmp(optarg, "strict")   == 0) { cfg._level = ScanConfig::Level::Strict;   }
                else if (strcmp(optarg, "normal")   == 0) { cfg._level = ScanConfig::Level::Normal;   }
                else if (strcmp(optarg, "extended") == 0) { cfg._level = ScanConfig::Level::Extended; }
                else if (strcmp(optarg, "full")     == 0) { cfg._level = ScanConfig::Level::Full;     }
                else {
                    fprintf(stderr, "Error: unknown --static-level '%s'.\n"
                            "  Valid: off, strict, normal, extended, full\n", optarg);
                    return 1;
                }
                break;
            case 'h': usage(argv_[0]); return 0;
            default:  usage(argv_[0]); return 1;
        }
    }

    if (optind >= argc_) {
        fprintf(stderr, "Error: no input specified.\n");
        usage(argv_[0]);
        return 1;
    }

    /* Resolve input path */
    char resolved[PATH_MAX];
    if (!realpath(argv_[optind], resolved)) {
        perror(argv_[optind]);
        return 1;
    }

    /* Map format string */
    SbomFormat fmt;
    if      (strcmp(format, "text")      == 0) fmt = SbomFormat::Text;
    else if (strcmp(format, "cyclonedx") == 0 ||
             strcmp(format, "cdx")       == 0) fmt = SbomFormat::CycloneDX_JSON;
    else if (strcmp(format, "spdx")      == 0) fmt = SbomFormat::SPDX_TagValue;
    else {
        fprintf(stderr, "Error: unknown format '%s'.\n", format);
        return 1;
    }

    struct stat st;
    if (stat(resolved, &st) != 0) {
        perror(resolved);
        return 1;
    }

    /* Load hints file once (shared for all modes) */
    HintsFile hints;
    if (hints_path) {
        hints = load_hints_file(hints_path);
        /* Merge file-level exclusions into the scan config */
        for (const auto& ex : hints._excludes) {
            cfg._exclude.insert(ex);
        }
    }

    const std::string out_path = output ? output : "";

    /* ── Directory mode ─────────────────────────────────────────────────── */
    if (S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Mode: directory scan\nTarget: %s\n", resolved);

        Resolver resolver(resolved);
        resolver._include_system_libs = !no_system;
        resolver._skip_objects        = no_obj;
        resolver._max_depth           = max_depth;

        MultiGraph mg = resolver.analyze_directory(resolved);

        if (!no_pkg) {
            fprintf(stderr, "Querying package manager (%zu components)...\n",
                    mg._components.size());
            for (auto& [path, comp] : mg._components) {
                if (comp._pkg_name.empty()) {
                    query_package_info(comp);
                }
            }
        }

        /* Infer missing versions from package names and dynamic dep correlation */
        infer_versions_from_pkg(mg._components);

        /* License detection (package manager + known-lib table + binary scan) */
        {
            OsRelease os = read_os_release();
            for (auto& [path, comp] : mg._components) {
                detect_license(comp, os);
            }
        }
        /* Fallback: apply hint-file licence to components still without one */
        if (!hints._libs.empty()) {
            apply_hint_license_fallback(mg._components, hints._libs);
        }

        /* Apply positive hints to root components (those inside the scanned dir) */
        if (!hints._libs.empty()) {
            for (const auto& root_path : mg._roots) {
                auto it = mg._components.find(root_path);
                if (it != mg._components.end()) {
                    apply_hints(it->second, hints._libs);
                }
            }
        }

        /* Apply scan configuration: level filter + false-positive exclusions */
        for (auto& [path, comp] : mg._components) {
            apply_scan_config(comp, cfg);
        }

        fprintf(stderr, "Total: %zu component(s), %zu root(s).\n",
                mg._components.size(), mg._roots.size());

        write_sbom_multi(mg, fmt, out_path);
        return 0;
    }

    /* ── Single-file mode ───────────────────────────────────────────────── */
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a file or directory.\n", resolved);
        return 1;
    }

    fprintf(stderr, "Mode: single file\nAnalysing: %s\n", resolved);

    std::string root(resolved);
    size_t sl = root.rfind('/');
    std::string origin = (sl != std::string::npos) ? root.substr(0, sl) : ".";

    Resolver resolver(origin);
    resolver._include_system_libs = !no_system;
    resolver._skip_objects        = no_obj;
    resolver._max_depth           = max_depth;

    DepGraph graph;
    resolver.analyze(root, graph);

    if (!no_pkg) {
        fprintf(stderr, "Querying package manager...\n");
        for (auto& [path, comp] : graph._components) {
            if (comp._pkg_name.empty()) {
                query_package_info(comp);
            }
        }
    }

    /* Infer missing versions from package names and dynamic dep correlation */
    infer_versions_from_pkg(graph._components);

    /* License detection */
    {
        OsRelease os = read_os_release();
        for (auto& [path, comp] : graph._components) {
            detect_license(comp, os);
        }
    }
    /* Fallback: apply hint-file licence to components still without one */
    if (!hints._libs.empty()) {
        apply_hint_license_fallback(graph._components, hints._libs);
    }

    /* Apply positive hints to the root binary */
    if (!hints._libs.empty()) {
        auto it = graph._components.find(root);
        if (it != graph._components.end()) {
            apply_hints(it->second, hints._libs);
        }
    }

    /* Apply scan configuration: level filter + false-positive exclusions */
    for (auto& [path, comp] : graph._components) {
        apply_scan_config(comp, cfg);
    }

    fprintf(stderr, "Found %zu component(s).\n", graph._components.size());
    write_sbom(graph, fmt, out_path);
    return 0;
}
