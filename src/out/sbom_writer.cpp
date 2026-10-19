#include <out/sbom_writer.hpp>
#include <util/os_detect.hpp>
#include <query/purl.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <unistd.h>

static std::string json_esc(const std::string& s_) {
    std::string o;
    o.reserve(s_.size() + 8);

    for (unsigned char c : s_) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    char b[8];
                    snprintf(b, 8, "\\u%04x", c);
                    o += b;
                } else {
                    o += (char)c;
                }
        }
    }

    return o;
}

/* Write a single JSON property using fputs for the value (avoids % issues). */
static void jprop(FILE* fp_, int indent_, const char* key_, const std::string& val_, bool comma_ = true) {
    for (int i = 0; i < indent_; i++) {
        fputc(' ', fp_);
    }

    fprintf(fp_, "\"%s\": \"", key_);
    fputs(json_esc(val_).c_str(), fp_);
    fputs(comma_ ? "\",\n" : "\"\n", fp_);
}

static std::string utc_now() {
    time_t t = time(nullptr);
    char buf[32] = {0};
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return buf;
}

static std::string new_uuid() {
    unsigned int seed = (unsigned int)time(nullptr) ^ (unsigned int)getpid();
    unsigned char b[16];
    for (int i = 0; i < 16; i++) {
        b[i] = (unsigned char)(rand_r(&seed) & 0xff);
    }

    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    char buf[37];

    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
                                b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    return buf;
}

static const char* cdx_type(ElfType t_) {
    switch (t_) {
        case ElfType::Executable:    return "application";
        case ElfType::SharedLibrary: return "library";
        default:                     return "file";
    }
}

static std::map<std::string, int> make_idx(const std::vector<std::string>& order) {
    std::map<std::string, int> m;
    for (int i = 0; i < (int)order.size(); i++) {
        m[order[i]] = i;
    }

    return m;
}

static std::string num_ref(const std::string& path_, const std::map<std::string, int>& idx_) {
    auto it = idx_.find(path_);
    char buf[32] = {0};
    snprintf(buf, sizeof(buf), "comp-%d", it != idx_.end() ? it->second : -1);
    return buf;
}

static std::string spdx_ref(const std::string& path_, const std::map<std::string, int>& idx_) {
    auto it = idx_.find(path_);
    char buf[40] = {0};
    snprintf(buf, sizeof(buf), "SPDXRef-comp-%d", (it != idx_.end()) ? it->second : -1);
    return buf;
}

/* 
  CycloneDX 1.6 — component block writer
 
  Cyberwatch requirements (confirmed from official adapter):
    - bom-ref  = purl when available (enables PURL-based dep graph)
    - purl     = typed PURL for CVE matching (pkg:deb, pkg:rpm, pkg:generic…)
    - cpe      = CPE 2.3 when deterministic  (secondary matching)
    - name     = package-manager name preferred over soname
    - version  = package-manager version preferred
    - type     = "library" | "application" | "operating-system"
 */

static void write_cdx_component(FILE* fp_, const Component& c_, const std::string& ref_, const std::string& purl_, const std::string& cpe_) {
    /* Use package-manager name for CVE matching when available */
    const std::string& display_name = c_._pkg_name.empty() ? c_._name : c_._pkg_name;
    const std::string& version      = c_._pkg_version;

    fputs("    {\n", fp_);
    fprintf(fp_, "      \"type\":    \"%s\",\n", cdx_type(c_._type));
    fprintf(fp_, "      \"bom-ref\": \"");
    fputs(json_esc(ref_).c_str(), fp_);
    fputs("\",\n", fp_);

    jprop(fp_, 6, "name", display_name, true);

    if (!version.empty()) {
        jprop(fp_, 6, "version", version, true);
    }

    /* purl — primary field for Cyberwatch CVE matching */
    if (!purl_.empty()) {
        fputs("      \"purl\": \"", fp_);
        fputs(json_esc(purl_).c_str(), fp_);
        fputs("\",\n", fp_);
    }

    /* cpe — secondary matching field */
    if (!cpe_.empty()) {
        fputs("      \"cpe\": \"", fp_);
        fputs(json_esc(cpe_).c_str(), fp_);
        fputs("\",\n", fp_);
    }

    /* Build-ID as SHA-1 hash (closest approximation) */
    if (!c_._build_id.empty()) {
        fprintf(fp_,
            "      \"hashes\": [{ \"alg\": \"SHA-1\","
            " \"content\": \"%s\" }],\n", c_._build_id.c_str());
    }

    /* CycloneDX licenses array */
    if (!c_._license.empty()) {
        bool is_expr = ((c_._license.find(" OR ") != std::string::npos) ||
                        (c_._license.find(" AND ") != std::string::npos) ||
                        (c_._license.find(" WITH ") != std::string::npos));
        fputs("      \"licenses\": [{\n", fp_);
        if (is_expr) {
            fputs("        \"expression\": \"", fp_);
            fputs(json_esc(c_._license).c_str(), fp_);
            fputs("\"\n", fp_);
        } else {
            fputs("        \"license\": { \"id\": \"", fp_);
            fputs(json_esc(c_._license).c_str(), fp_);
            fputs("\" }\n", fp_);
        }
        fputs("      }],\n", fp_);
    }

    /* ELF-specific properties — always terminated by elf:dwarf_cu_count */
    fputs("      \"properties\": [\n", fp_);

    auto prop = [&](const char* key, const std::string& val, bool comma) {
        fprintf(fp_, "        { \"name\": \"%s\", \"value\": \"", key);
        fputs(json_esc(val).c_str(), fp_);
        fputs(comma ? "\" },\n" : "\" }\n", fp_);
    };

    prop("elf:path",     c_._path,                        true);
    prop("elf:arch",     c_._arch,                        true);
    prop("elf:stripped", c_._stripped ? "true" : "false", true);
    prop("elf:pie",      c_._is_pie   ? "true" : "false", true);

    if (!c_._comment.empty()) {
        prop("elf:comment", c_._comment.substr(0, 200), true);
    }

    /* One property per statically-detected library (version + method) */
    for (const auto& sl : c_._static_libs) {
        std::string key = "elf:static_lib:" + sl._name;
        std::string val = sl._version.empty() ? sl._method : (sl._version + " [" + sl._method + "]");
        prop(key.c_str(), val, true);
    }

    /* Terminator — always last, no trailing comma */
    prop("elf:dwarf_cu_count", std::to_string(c_._cu_sources.size()), false);

    fputs("      ]\n    }", fp_);
}

/* Write a static library as a standalone CycloneDX component. These only appear when the version is known (needed for CVE matching). */
static void write_cdx_static_lib(FILE* fp_,
                                   const StaticLibInfo& sl_,
                                   const std::string& parent_path_) {
    std::string purl = make_static_purl(sl_);
    std::string cpe  = make_cpe(sl_._name, sl_._version);
    if (purl.empty()) {
        return;   /* no version  */
    }

    fputs("    {\n", fp_);
    fputs("      \"type\":    \"library\",\n", fp_);
    fprintf(fp_, "      \"bom-ref\": \"");
    fputs(json_esc(purl).c_str(), fp_);
    fputs("\",\n", fp_);
    jprop(fp_, 6, "name",    sl_._name,    true);
    jprop(fp_, 6, "version", sl_._version, true);
    fprintf(fp_, "      \"purl\": \"");
    fputs(json_esc(purl).c_str(), fp_);
    fputs("\",\n", fp_);

    if (!cpe.empty()) {
        fprintf(fp_, "      \"cpe\": \"");
        fputs(json_esc(cpe).c_str(), fp_);
        fputs("\",\n", fp_);
    }

    if (!sl_._license.empty()) {
        bool is_expr = (sl_._license.find(" OR ")  != std::string::npos ||
                        sl_._license.find(" AND ") != std::string::npos);
        fputs("      \"licenses\": [{\n", fp_);
        if (is_expr) {
            fputs("        \"expression\": \"", fp_);
            fputs(json_esc(sl_._license).c_str(), fp_);
            fputs("\"\n", fp_);
        } else {
            fputs("        \"license\": { \"id\": \"", fp_);
            fputs(json_esc(sl_._license).c_str(), fp_);
            fputs("\" }\n", fp_);
        }
        fputs("      }],\n", fp_);
    }

    fputs("      \"properties\": [\n", fp_);
    fprintf(fp_, "        { \"name\": \"elf:link_type\",   \"value\": \"static\" },\n");
    fprintf(fp_, "        { \"name\": \"elf:detected_by\", \"value\": \"");
    fputs(json_esc(sl_._method).c_str(), fp_);
    fputs("\" },\n", fp_);
    fprintf(fp_, "        { \"name\": \"elf:found_in\",    \"value\": \"");
    fputs(json_esc(parent_path_).c_str(), fp_);
    fputs("\" }\n", fp_);
    fputs("      ]\n    }", fp_);
}

/* Write the OS component block (type: "operating-system"). */
static void write_cdx_os_component(FILE* fp_, const OsRelease& os_,
                                    const std::string& arch_) {
    fputs("    {\n", fp_);
    fputs("      \"bom-ref\": \"CycloneDXRef-OperatingSystem\",\n", fp_);
    fputs("      \"type\":    \"operating-system\",\n", fp_);

    const std::string& name = os_._pretty_name.empty() ? os_._id : os_._pretty_name;
    jprop(fp_, 6, "name", name, true);
    if (!os_._version_id.empty()) {
        jprop(fp_, 6, "version", os_._version_id, true);
    }

    fputs("      \"properties\": [\n", fp_);
    fprintf(fp_, "        { \"name\": \"OS_PRETTYNAME\", \"value\": \"");
    fputs(json_esc(name).c_str(), fp_);
    fputs("\" },\n", fp_);
    fprintf(fp_, "        { \"name\": \"ARCH\",          \"value\": \"");
    fputs(json_esc(arch_).c_str(), fp_);
    fputs("\" }\n", fp_);
    fputs("      ]\n    }", fp_);
}

static void write_cdx_header(FILE* fp_, const std::string& ts_, const std::string& uuid_, const std::string& device_name_, const std::string& device_version_) {
    fprintf(fp_,
        "{\n"
        "  \"bomFormat\":    \"CycloneDX\",\n"
        "  \"specVersion\":  \"1.6\",\n"
        "  \"serialNumber\": \"urn:uuid:%s\",\n"
        "  \"version\":      1,\n"
        "  \"metadata\": {\n"
        "    \"timestamp\": \"%s\",\n"
        /* CycloneDX 1.6 tools format uses a components array */
        "    \"tools\": {\n"
        "      \"components\": [{\n"
        "        \"type\":      \"application\",\n"
        "        \"publisher\": \"elf-sbom\",\n"
        "        \"name\":      \"elf-sbom\",\n"
        "        \"version\":   \"1.0\"\n"
        "      }]\n"
        "    },\n"
        /* The device element identifies the scanned machine */
        "    \"component\": {\n"
        "      \"bom-ref\": \"CycloneDXRef-device\",\n"
        "      \"type\":    \"device\",\n"
        "      \"name\":    \"%s\",\n"
        "      \"version\": \"%s\"\n"
        "    }\n"
        "  },\n",
        uuid_.c_str(), ts_.c_str(),
        json_esc(device_name_).c_str(),
        json_esc(device_version_).c_str());
}

using PurlMap = std::map<std::string, std::string>; 

static PurlMap build_purl_map(const std::vector<std::string>& order_, const std::map<std::string, Component>&, const OsRelease&) {
    PurlMap m;
    auto idx = make_idx(order_);
    for (const auto& path : order_) {
        m[path] = num_ref(path, idx);   /* comp-N always unique */
    }
    return m;
}

/*
  One entry = one (elf_path, StaticLibInfo) pair.
 
  Deduplication key: (elf_path, lib_name) = same library without version in two different ELF files produces 2 entries.  
  Same library seen multiple times inside the same ELF is collapsed to one.
*/
struct NoVersionEntry {
    std::string   elf_path;   /* absolute path of the containing ELF */
    StaticLibInfo lib;
};

static std::vector<NoVersionEntry> collect_no_version_libs(const std::vector<std::string>& order, const std::map<std::string, Component>& comps) {
    std::set<std::string> seen; /* key = elf_path + '\0' + lib_name */
    std::vector<NoVersionEntry> result;

    for (const auto& path : order) {
        for (const auto& sl : comps.at(path)._static_libs) {
            if (!sl._version.empty()) {
                continue;
            }
            std::string key = path + '\0' + sl._name;
            if (!seen.insert(key).second) {
                continue;
            }
            result.push_back({path, sl});
        }
    }
    return result;
}

static const char* basename_of(const std::string& p_) {
    auto pos = p_.rfind('/');
    return (pos == std::string::npos) ? p_.c_str() : p_.c_str() + pos + 1;
}

/*
  Emit version warnings.
    is_text = true  → write to fp (end of text report)
    is_text = false → write to stderr (during CycloneDX/SPDX generation)
 
  Each entry shows the ELF binary where the version-less lib was detected.
  If the same lib appears in two different ELFs, two lines are printed.
 */
static void emit_version_warnings(const std::vector<NoVersionEntry>& no_ver_, FILE* fp_, bool is_text_) {
    if (no_ver_.empty()) {
        return;
    }

    if (is_text_) {
        fputs("=======================================================\n"
              "       WARNINGS — libraries with unknown version\n"
              "=======================================================\n"
              "The following statically-detected libraries have no version information. They cannot be emitted as standalone SBOM components (no PURL/CPE → no CVE matching possible).\n\n", fp_);
        for (const auto& e : no_ver_) {
            fprintf(fp_, "  [!] %-25s  [%s]  in: %s",  e.lib._name.c_str(),
                                                       e.lib._method.c_str(),
                                                       e.elf_path.c_str());
            if (!e.lib._license.empty()) {
                fprintf(fp_, "  license: %s", e.lib._license.c_str());
            }
            fputc('\n', fp_);
        }
        fputc('\n', fp_);
    } else {
        for (const auto& e : no_ver_) {
            fprintf(stderr, "[WARN] static '%s' has no version detected by: %s, in: %s) - cannot be matched to CVEs\n", e.lib._name.c_str(),
                                                                                                                        e.lib._method.c_str(),
                                                                                                                        basename_of(e.elf_path));
        }
    }
}


/*
  A component (dynamic or static) for which no licence could be determined.
 */
struct LicenseGap {
    std::string _name;
    std::string _version;    // may be empty 
    bool        is_static;
    std::string _method;     // detection method, for static libs 
};

/*
  Collect every dynamic component and every static lib entry that has no licence
 */
static std::vector<LicenseGap> collect_license_gaps(const std::vector<std::string>& order, const std::map<std::string, Component>& comps) {
    std::set<std::string> seen;
    std::vector<LicenseGap> result;

    for (const auto& path : order) {
        const Component& c = comps.at(path);

        /* Dynamic component without licence */
        if (c._license.empty()) {
            std::string key = "d:" + c._name;
            if (seen.insert(key).second) {
                std::string ver = c._pkg_version.empty() ? c._soname : c._pkg_version;
                result.push_back({c._name, ver, false, ""});
            }
        }

        /* Static libs without licence */
        for (const auto& sl : c._static_libs) {
            if (sl._license.empty()) {
                std::string key = "s:" + sl._name + "@" + sl._version;
                if (seen.insert(key).second) {
                    result.push_back({sl._name, sl._version, true, sl._method});
                }
            }
        }
    }
    return result;
}

/*
  Emit licence-gap warnings.
    is_text = true  → write to fp (text report, end section)
    is_text = false → write to stderr (during SBOM generation)
 */
static void emit_license_warnings(const std::vector<LicenseGap>& gaps_,
                                   FILE* fp_, bool is_text_) {
    if (gaps_.empty()) {
        return;
    }

    if (is_text_) {
        fputs("=======================================================\n"
              "       WARNINGS — components with unknown license\n"
              "=======================================================\n"
       
              "The following components have no detectable license information.  Add them to the hints file to resolve:\n\n", fp_);
        for (const auto& g : gaps_) {
            if (g.is_static) {
                fprintf(fp_, "  [!] %-28s  (static, %s)%s\n", g._name.c_str(), 
                                                              g._method.c_str(),
                                                              g._version.empty() ? "" : (" v" + g._version).c_str());
            } else {
                fprintf(fp_, "  [!] %-28s  (dynamic)%s\n", g._name.c_str(),
                                                           g._version.empty() ? "" : (" " + g._version).c_str());
            }
        }
        fputc('\n', fp_);
    } else {
        for (const auto& g : gaps_) {
            if (g.is_static) {
                fprintf(stderr,  "[WARN] static '%s'%s has no license  - add to hints file with license field\n", g._name.c_str(),
                                                                                                                  g._version.empty() ? "" : (" v" + g._version).c_str());
            } else {
                fprintf(stderr, "[WARN] '%s'%s has no license information\n", g._name.c_str(),
                                                                              g._version.empty() ? "" : (" " + g._version).c_str());
            }
        }
    }
}

static void print_component(FILE* fp_, const Component& c_,  const char* tag_, const std::set<std::string>* users_ = nullptr) {
    fprintf(fp_, "%s %s", tag_, c_._name.c_str());
    if (!c_._pkg_version.empty()) {
        fprintf(fp_, "  (%s)", c_._pkg_version.c_str());
    }
    fputc('\n', fp_);

    fprintf(fp_, "    path     : "); fputs(c_._path.c_str(), fp_); fputc('\n', fp_);
    fprintf(fp_, "    arch     : %s\n", c_._arch.c_str());
    fprintf(fp_, "    type     : %s%s\n", c_._type == ElfType::Executable    ? "executable"     :
                                          c_._type == ElfType::SharedLibrary ? "shared-library" : "unknown",
                                          c_._is_pie ? " (PIE)" : "");
            
    fprintf(fp_, "    stripped : %s   debug : %s\n",  c_._stripped ? "yes" : "no", c_._has_debug ? "yes" : "no");

    if (!c_._build_id.empty()) {
        fprintf(fp_, "    build-id : %s\n", c_._build_id.c_str());
    }
    if (!c_._pkg_name.empty()) {
        fprintf(fp_, "    package  : %s %s\n", c_._pkg_name.c_str(), c_._pkg_version.c_str());
    }
    if (!c_._license.empty()) {
        fprintf(fp_, "    license  : %s\n", c_._license.c_str());
    }
    if (!c_._comment.empty()) {
        fputs("    compiler : ", fp_);
        fputs(c_._comment.substr(0, 120).c_str(), fp_);
        fputc('\n', fp_);
    }
    if (!c_._needed.empty()) {
        fputs("    dyn-deps :", fp_);
        for (const auto& n : c_._needed) {
            fputc(' ', fp_);
            fputs(n.c_str(), fp_);
        }
        fputc('\n', fp_);
    }

    bool any_unres = false;
    for (const auto& d : c_._resolved_deps) {
        if (d[0] == '?') {
            any_unres = true;
            break;
        }
    }

    if (any_unres) {
        fputs("    MISSING  :", fp_);
        for (const auto& d : c_._resolved_deps) {
            if (d[0] == '?') {
                fputc(' ', fp_);
                fputs(d.c_str() + 1, fp_);
            }
        }
        fputc('\n', fp_);
    }

    if (!c_._static_libs.empty()) {
        fputs("    static   :", fp_);
        for (const auto& sl : c_._static_libs) {
            fprintf(fp_, "\n      %-20s", sl._name.c_str());
            if (!sl._version.empty()) {
                fprintf(fp_, "  v%-12s", sl._version.c_str());
            } else {
                fputs("  (version unknown) ", fp_);
            }
            fprintf(fp_, "  [%s]", sl._method.c_str());
          
            if (!sl._license.empty()) {
                fprintf(fp_, "  %s", sl._license.c_str());
            }
        }
        fputc('\n', fp_);
    }
    if (!c_._cu_sources.empty()) {
        fprintf(fp_, "    dwarf-cu : %zu unit%s", c_._cu_sources.size(), c_._cu_sources.size() > 1 ? "s" : "");
       
                if (c_._cu_sources.size() > 3) {
            fputs(", first 3 shown", fp_);
        }
        fputc('\n', fp_);
        size_t shown = 0;
        for (const auto& src : c_._cu_sources) {
            if (shown++ >= 3) {
                fputs("      ...\n", fp_);
                break;
            }
            fputs("      ", fp_);
            fputs(src.c_str(), fp_);
            fputc('\n', fp_);
        }
    }

    if (users_ && !users_->empty()) {
        fputs("    used-by  :", fp_);
        for (const auto& u : *users_) {
            fputc(' ', fp_);
            size_t sl2 = u.rfind('/');
            fputs((sl2 != std::string::npos ? u.substr(sl2+1) : u).c_str(), fp_);
        }
        fputc('\n', fp_);
    }
    fputc('\n', fp_);
}

static void write_text_single(const DepGraph& g_, FILE* fp_) {
    fprintf(fp_, "=======================================================\n"
                 "  ELF SBOM (single file)  —  elf-sbom 1.0\n"
                 "=======================================================\n"
                 "Generated  : %s\n"
                 "Root       : %s\n"
                 "Components : %zu\n\n", utc_now().c_str(), g_._root_path.c_str(), g_._components.size());

    for (const auto& path : g_._discovery_order) {
        const Component& c = g_._components.at(path);
        print_component(fp_, c, (path == g_._root_path) ? "> [ROOT]" : "  [DEP] ");
    }

    /* Warnings for static libs whose version could not be determined */
    auto no_ver = collect_no_version_libs(g_._discovery_order, g_._components);
    emit_version_warnings(no_ver, fp_, true);
    emit_license_warnings( collect_license_gaps(g_._discovery_order, g_._components), fp_, true);
}


/*
  Detection method priority (used to keep the most reliable entry).
  Priority (descending):   hint-file > version-string > dwarf-path > symbol-defined > symbol-ref
 
  Priority scale (higher = more authoritative):
    8  hint-file      — explicit user/vendor annotation
    7  version-string — literal version found in the binary
    6  dwarf-path     — build-system path in DWARF debug info
    5  symbol-defined — exported symbol matching library's public API
    4  symbol-ref     — referenced symbol (may be weak / plt stub)
    3  symbol-cluster — characteristic symbol set (DIE/FLIRT style)
    2  pkg-inferred   — version inferred from system package manager
                        (unreliable: static libs are often custom builds)
    1  byte-sig       — magic byte pattern found in data section
*/
static int static_lib_priority(const std::string& method_) {
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

/*
  Collect static lib entries from all components, deduplicated by (name, version) — NOT by name alone.
*/
static std::vector<StaticLibInfo> collect_best_static_libs(const std::vector<std::string>& order, const std::map<std::string, Component>& comps) {
    /* Key: {name, version} — "" version = "unknown", merged per name */
    using Key = std::pair<std::string, std::string>;
    std::map<Key, StaticLibInfo> best;

    for (const auto& path : order) {
        const Component& c = comps.at(path);
       
        for (const auto& sl : c._static_libs) {
            Key k{sl._name, sl._version};
            auto it = best.find(k);
          
            if (it == best.end()) {
                best[k] = sl;
            } else if (static_lib_priority(sl._method) > static_lib_priority(it->second._method)) {
                it->second = sl;
            }
        }
    }

    /* Collect in first-seen order */
    std::vector<StaticLibInfo> result;
    std::set<Key> seen;
    for (const auto& path : order) {
        for (const auto& sl : comps.at(path)._static_libs) {
            Key k{sl._name, sl._version};
            if (!seen.insert(k).second) {
                continue;
            }
            
            auto it = best.find(k);
            if (it != best.end()) {
                result.push_back(it->second);
            }
        }
    }
    return result;
}

static void write_cdx_single(const DepGraph& g_, FILE* fp_) {
    OsRelease os = read_os_release();
    std::string arch = sys_arch();
    std::string host = sys_hostname();
    std::string ts   = utc_now();
    std::string uuid = new_uuid();

    write_cdx_header(fp_, ts, uuid, host, ts);

    /* Pre-compute PURLs (used both as bom-ref and in dependsOn) */
    PurlMap pmap = build_purl_map(g_._discovery_order, g_._components, os);

    /* Collect best static lib per name across all components */
    auto best_static = collect_best_static_libs(g_._discovery_order, g_._components);

    fputs("  \"components\": [\n", fp_);

    /* OS component first */
    write_cdx_os_component(fp_, os, arch);

    /* Dynamic components */
    for (const auto& path : g_._discovery_order) {
        const Component& c      = g_._components.at(path);
        const std::string& ref  = pmap.at(path);
        std::string purl = make_purl(c, os);
       
        /* CPE from package name (best effort) */
        std::string cpe  = c._pkg_name.empty() ? make_cpe(c._name, c._pkg_version) : make_cpe(c._pkg_name, c._pkg_version);

        fputs(",\n", fp_);
        write_cdx_component(fp_, c, ref, purl, cpe);
    }

    /* Static lib components — one per canonical name, best version wins.
     * Entries without a version are recorded in properties only,
     * not as standalone components (no PURL → no CVE match possible). */
    for (const auto& sl : best_static) {
        std::string sp = make_static_purl(sl);
        if (sp.empty()) {
            continue;   /* skip version-less entries */
        }
        fputs(",\n", fp_);
        write_cdx_static_lib(fp_, sl, g_._root_path);
    }

    fputs("\n  ],\n  \"dependencies\": [\n", fp_);

    /* OS has no deps */
    fputs("    { \"ref\": \"CycloneDXRef-OperatingSystem\", \"dependsOn\": [] }", fp_);

    for (const auto& path : g_._discovery_order) {
        const Component& c    = g_._components.at(path);
        const std::string& ref = pmap.at(path);
        fputs(",\n", fp_);
        fprintf(fp_, "    { \"ref\": \"%s\", \"dependsOn\": [",  json_esc(ref).c_str());

        bool fd = true;
        std::set<std::string> seen_deps; /* dedup: same path → same PURL */
        for (const auto& dep : c._resolved_deps) {
            if (dep[0] == '?') {
                continue;
            }

            auto it = pmap.find(dep);
            if (it == pmap.end()) {
                continue;
            }

            if (!seen_deps.insert(it->second).second) {
                continue;
            }

            if (!fd) {
                fputs(", ", fp_);
            }

            fprintf(fp_, "\"%s\"", json_esc(it->second).c_str());
            fd = false;
        }
        fputs("] }", fp_);
    }

    fputs("\n  ]\n}\n", fp_);
    emit_version_warnings(collect_no_version_libs(g_._discovery_order, g_._components), stderr, false);
    emit_license_warnings(collect_license_gaps(g_._discovery_order, g_._components), stderr, false);
}

/* 
 Single-file — SPDX 2.3 Tag-Value
*/
static void write_spdx_single(const DepGraph& g_, FILE* fp_) {
    auto idx = make_idx(g_._discovery_order);
    size_t sl = g_._root_path.rfind('/');
    std::string docname = (sl != std::string::npos)? g_._root_path.substr(sl + 1) : g_._root_path;

    fprintf(fp_,
        "SPDXVersion: SPDX-2.3\n"
        "DataLicense: CC0-1.0\n"
        "SPDXID: SPDXRef-DOCUMENT\n"
        "DocumentName: elf-sbom-%s\n"
        "DocumentNamespace: https://spdx.org/spdxdocs/elf-sbom-%s\n"
        "Creator: Tool: elf-sbom-1.0\n"
        "Created: %s\n\n", docname.c_str(), new_uuid().c_str(), utc_now().c_str());

    OsRelease os = read_os_release();
    /* SPDXRef-DOCUMENT DESCRIBES the root package (recommended §2.7) */
    if (!g_._discovery_order.empty()) {
        fprintf(fp_, "Relationship: SPDXRef-DOCUMENT DESCRIBES %s\n\n", spdx_ref(g_._root_path, idx).c_str());
    }
    for (const auto& path : g_._discovery_order) {
        const Component& c = g_._components.at(path);

        fprintf(fp_, "PackageName: "); fputs(c._name.c_str(), fp_); fputc('\n', fp_);
        fprintf(fp_, "SPDXID: %s\n", spdx_ref(path, idx).c_str());
    
        if (!c._pkg_version.empty()) {
            fprintf(fp_, "PackageVersion: %s\n", c._pkg_version.c_str());
        }

        fputs("PackageDownloadLocation: NOASSERTION\nFilesAnalyzed: false\n", fp_);
       
        /* Required SPDX 2.3 fields (§3.7, §3.8, §3.17) */
        if (!c._license.empty()) {
            fprintf(fp_, "PackageLicenseConcluded: %s\n", c._license.c_str());
            fprintf(fp_, "PackageLicenseDeclared: %s\n",  c._license.c_str());
        } else {
            fputs("PackageLicenseConcluded: NOASSERTION\n", fp_);
            fputs("PackageLicenseDeclared: NOASSERTION\n", fp_);
        }
      
        fputs("PackageCopyrightText: NOASSERTION\n", fp_);
     
        if (!c._build_id.empty()) {
            fprintf(fp_, "PackageChecksum: SHA1: %s\n", c._build_id.c_str());
        }
     
        std::string purl = make_purl(c, os);
        if (!purl.empty()) {
            fprintf(fp_, "ExternalRef: PACKAGE-MANAGER purl %s\n", purl.c_str());
        }
   
        fputs("PackageComment: <text>arch=", fp_);
        fputs(c._arch.c_str(), fp_);
        fputs(" path=", fp_); fputs(c._path.c_str(), fp_);
        fprintf(fp_, " stripped=%s", c._stripped ? "yes" : "no");
    
        if (!c._static_libs.empty()) {
            fputs(" static_libs=", fp_);
            bool f = true;
            for (const auto& s : c._static_libs) {
                if (!f) {
                    fputc(',', fp_);
                }
                fputs(s._name.c_str(), fp_);
                if (!s._version.empty()) {
                    fprintf(fp_, "@%s", s._version.c_str());
                }
                f = false;
            }
        }
        fputs("</text>\n\n", fp_);
    }

    for (const auto& path : g_._discovery_order) {
        const Component& c = g_._components.at(path);
        for (const auto& dep : c._resolved_deps) {
            if (dep[0] == '?') {
                fprintf(fp_, "Relationship: %s DYNAMIC_LINK SPDXRef-NOASSERTION\n",
                        spdx_ref(path, idx).c_str());
            } else {
                fprintf(fp_, "Relationship: %s DYNAMIC_LINK %s\n",
                        spdx_ref(path, idx).c_str(), spdx_ref(dep, idx).c_str());
            }
        }
    }

    emit_version_warnings( collect_no_version_libs(g_._discovery_order, g_._components), stderr, false);
    emit_license_warnings( collect_license_gaps(g_._discovery_order, g_._components), stderr, false);
}

static void write_text_multi(const MultiGraph& mg_, FILE* fp_) {
    std::set<std::string> root_set(mg_._roots.begin(), mg_._roots.end());
    size_t n_deps = 0;
    for (const auto& p : mg_._ordered) {
        if (!root_set.count(p)) {
            n_deps++;
        }
    }

    fprintf(fp_,
        "=======================================================\n"
        "      ELF SBOM (directory scan)  —  elf-sbom 1.0\n"
        "=======================================================\n"
        "Generated    : %s\n"
        "Scanned dir  : %s\n"
        "Root ELFs    : %zu\n"
        "Dependencies : %zu  (deduplicated)\n"
        "Total        : %zu\n\n", utc_now().c_str(), mg_._scan_root.c_str(), mg_._roots.size(), n_deps, mg_._components.size());

    for (const auto& path : mg_._ordered) {
        const Component& c = mg_._components.at(path);
        bool is_root = root_set.count(path) > 0;
        const std::set<std::string>* users_ptr = is_root ? nullptr : (mg_._users.count(path) ? &mg_._users.at(path) : nullptr);
        print_component(fp_, c, is_root ? "> [ROOT]" : "  [DEP] ", users_ptr);
    }

    auto no_ver = collect_no_version_libs(mg_._ordered, mg_._components);
    emit_version_warnings(no_ver, fp_, true);
    emit_license_warnings(collect_license_gaps(mg_._ordered, mg_._components), fp_, true);
}

static void write_cdx_multi(const MultiGraph& mg_, FILE* fp_) {
    OsRelease os = read_os_release();
    std::string arch = sys_arch();
    std::string host = sys_hostname();
    std::string ts = utc_now();
    std::string uuid = new_uuid();

    write_cdx_header(fp_, ts, uuid, host, ts);

    PurlMap pmap = build_purl_map(mg_._ordered, mg_._components, os);

    /* Collect best static lib per name across all root components */
    auto best_static = collect_best_static_libs(mg_._ordered, mg_._components);

    fputs("  \"components\": [\n", fp_);
    write_cdx_os_component(fp_, os, arch);

    for (const auto& path : mg_._ordered) {
        const Component& c = mg_._components.at(path);
        const std::string& ref = pmap.at(path);
        std::string purl = make_purl(c, os);
        std::string cpe  = c._pkg_name.empty() ? make_cpe(c._name, c._pkg_version) : make_cpe(c._pkg_name, c._pkg_version);
        fputs(",\n", fp_);
        write_cdx_component(fp_, c, ref, purl, cpe);
    }

    /* Static lib components — one per canonical name, best version wins. Entries without a version are recorded in properties only. */
    for (const auto& sl : best_static) {
        std::string sp = make_static_purl(sl);
        if (sp.empty()) {
            continue;   /* skip version-less entries */
        }
        fputs(",\n", fp_);
        write_cdx_static_lib(fp_, sl, mg_._scan_root);
    }

    fputs("\n  ],\n  \"dependencies\": [\n", fp_);
    fputs("    { \"ref\": \"CycloneDXRef-OperatingSystem\", \"dependsOn\": [] }", fp_);

    for (const auto& path : mg_._ordered) {
        const Component& c    = mg_._components.at(path);
        const std::string& ref = pmap.at(path);

        fputs(",\n", fp_);
        fprintf(fp_, "    { \"ref\": \"%s\", \"dependsOn\": [", json_esc(ref).c_str());

        bool fd = true;
        std::set<std::string> seen_deps; /* dedup: same path → same PURL */
        for (const auto& dep : c._resolved_deps) {
            if (dep[0] == '?') {
                continue;
            }
     
            auto it = pmap.find(dep);
            if (it == pmap.end()) {
                continue;
            }
     
            if (!seen_deps.insert(it->second).second) {
                continue;
            }
     
            if (!fd) {
                fputs(", ", fp_);
            }
            fprintf(fp_, "\"%s\"", json_esc(it->second).c_str());
            fd = false;
        }
        fputs("] }", fp_);
    }

    fputs("\n  ]\n}\n", fp_);
    emit_version_warnings( collect_no_version_libs(mg_._ordered, mg_._components), stderr, false);
    emit_license_warnings( collect_license_gaps(mg_._ordered, mg_._components), stderr, false);
}

static void write_spdx_multi(const MultiGraph& mg_, FILE* fp_) {
    auto idx = make_idx(mg_._ordered);
    size_t sl = mg_._scan_root.rfind('/');
    std::string docname = (sl != std::string::npos)? mg_._scan_root.substr(sl + 1) : mg_._scan_root;

    fprintf(fp_,
        "SPDXVersion: SPDX-2.3\n"
        "DataLicense: CC0-1.0\n"
        "SPDXID: SPDXRef-DOCUMENT\n"
        "DocumentName: elf-sbom-%s\n"
        "DocumentNamespace: https://spdx.org/spdxdocs/elf-sbom-%s\n"
        "Creator: Tool: elf-sbom-1.0\n"
        "Created: %s\n\n", docname.c_str(), new_uuid().c_str(), utc_now().c_str());

    OsRelease os = read_os_release();
    /* SPDXRef-DOCUMENT DESCRIBES all root packages */
    for (const auto& root : mg_._roots) {
        fprintf(fp_, "Relationship: SPDXRef-DOCUMENT DESCRIBES %s\n", spdx_ref(root, idx).c_str());
    }
    fputc('\n', fp_);
    for (const auto& path : mg_._ordered) {
        const Component& c = mg_._components.at(path);
        fprintf(fp_, "PackageName: "); fputs(c._name.c_str(), fp_); fputc('\n', fp_);
        fprintf(fp_, "SPDXID: %s\n", spdx_ref(path, idx).c_str());
       
        if (!c._pkg_version.empty()) {
            fprintf(fp_, "PackageVersion: %s\n", c._pkg_version.c_str());
        }
        fputs("PackageDownloadLocation: NOASSERTION\nFilesAnalyzed: false\n", fp_);

        /* Required SPDX 2.3 fields (§3.7, §3.8, §3.17) */
        if (!c._license.empty()) {
            fprintf(fp_, "PackageLicenseConcluded: %s\n", c._license.c_str());
            fprintf(fp_, "PackageLicenseDeclared: %s\n",  c._license.c_str());
        } else {
            fputs("PackageLicenseConcluded: NOASSERTION\n", fp_);
            fputs("PackageLicenseDeclared: NOASSERTION\n", fp_);
        }

        fputs("PackageCopyrightText: NOASSERTION\n", fp_);

        if (!c._build_id.empty()) {
            fprintf(fp_, "PackageChecksum: SHA1: %s\n", c._build_id.c_str());
        }

        std::string purl = make_purl(c, os);
        if (!purl.empty()) {
            fprintf(fp_, "ExternalRef: PACKAGE-MANAGER purl %s\n", purl.c_str());
        }

        fputs("PackageComment: <text>arch=", fp_);
        fputs(c._arch.c_str(), fp_);
        fputs(" path=", fp_); fputs(c._path.c_str(), fp_);
        fprintf(fp_, " stripped=%s", c._stripped ? "yes" : "no");

        if (!c._static_libs.empty()) {
            fputs(" static_libs=", fp_);
            bool f = true;
            for (const auto& s : c._static_libs) {
                if (!f) {
                    fputc(',', fp_);
                }
                fputs(s._name.c_str(), fp_);
                if (!s._version.empty()) {
                    fprintf(fp_, "@%s", s._version.c_str());
                }
                f = false;
            }
        }
        fputs("</text>\n\n", fp_);
    }

    for (const auto& path : mg_._ordered) {
        const Component& c = mg_._components.at(path);
        for (const auto& dep : c._resolved_deps) {
            if (dep[0] == '?') {
                fprintf(fp_, "Relationship: %s DYNAMIC_LINK SPDXRef-NOASSERTION\n", spdx_ref(path, idx).c_str());
            } else {
                fprintf(fp_, "Relationship: %s DYNAMIC_LINK %s\n", spdx_ref(path, idx).c_str(), spdx_ref(dep, idx).c_str());
            }
        }
    }
    emit_version_warnings(collect_no_version_libs(mg_._ordered, mg_._components), stderr, false);
    emit_license_warnings(collect_license_gaps(mg_._ordered, mg_._components), stderr, false);
}

static FILE* open_output(const std::string& output_) {
    if (!output_.empty() && output_ != "-") {
        FILE* fp = fopen(output_.c_str(), "w");
        if (!fp) {
            fprintf(stderr, "Error: cannot open output: %s\n", output_.c_str());
        }
        return fp;
    }
    return stdout;
}

void write_sbom(const DepGraph& g_, SbomFormat fmt_, const std::string& output_) {
    FILE* fp = open_output(output_);
    if (!fp) {
        return;
    }

    switch (fmt_) {
        case SbomFormat::Text:           write_text_single(g_, fp); break;
        case SbomFormat::CycloneDX_JSON: write_cdx_single(g_,  fp); break;
        case SbomFormat::SPDX_TagValue:  write_spdx_single(g_, fp); break;
    }

    if (fp != stdout) {
        fclose(fp);
    }
}

void write_sbom_multi(const MultiGraph& mg_, SbomFormat fmt_,
                       const std::string& output_) {
    FILE* fp = open_output(output_);
    if (!fp) {
        return;
    }

    switch (fmt_) {
        case SbomFormat::Text:           write_text_multi(mg_, fp); break;
        case SbomFormat::CycloneDX_JSON: write_cdx_multi(mg_,  fp); break;
        case SbomFormat::SPDX_TagValue:  write_spdx_multi(mg_, fp); break;
    }

    if (fp != stdout) {
        fclose(fp);
    }
}
