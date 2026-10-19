#include <scan/resolver.hpp>
#include <scan/elf_parser.hpp>
#include <scan/elf_scanner.hpp>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Utilities ──────────────────────────────────────────────────────────── */

static bool is_regular_file(const std::string& p_) {
    struct stat st;
    return stat(p_.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

static std::string realpath_of(const std::string& p_) {
    char buf[PATH_MAX];
    return realpath(p_.c_str(), buf) ? std::string(buf) : p_;
}

static std::string dir_of(const std::string& p_) {
    size_t pos = p_.rfind('/');
    if (pos == std::string::npos) {
        return ".";
    }
    if (pos == 0) {
        return "/";
    }
    return p_.substr(0, pos);
}

static std::vector<std::string> split_colon(const char* s_) {
    std::vector<std::string> v;
    if (!s_ || !*s_) {
        return v;
    }
    const char* start = s_;
    for (const char* p = s_; ; p++) {
        if (*p == ':' || *p == '\0') {
            if (p > start) {
                v.emplace_back(start, p);
            }
            if (*p == '\0') {
                break;
            }
            start = p + 1;
        }
    }
    return v;
}

static void rtrim(char* s_) {
    size_t n = strlen(s_);
    while (n > 0 && (s_[n-1] == '\n' || s_[n-1] == '\r' || s_[n-1] == ' ')) {
        n--;
        s_[n] = '\0';
    }
}

/* ── Constructor ────────────────────────────────────────────────────────── */

Resolver::Resolver(const std::string& origin_dir) : origin_dir_(origin_dir) {
    if (const char* ldp = getenv("LD_LIBRARY_PATH")) {
        ld_env_paths_ = split_colon(ldp);
    }

    load_ld_conf("/etc/ld.so.conf");

    default_paths_ = {
        "/lib",           "/lib64",
        "/usr/lib",       "/usr/lib64",
        "/usr/local/lib", "/usr/local/lib64",
        "/lib/x86_64-linux-gnu",    "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",   "/usr/lib/aarch64-linux-gnu",
        "/lib/arm-linux-gnueabihf", "/usr/lib/arm-linux-gnueabihf",
        "/lib/i386-linux-gnu",      "/usr/lib/i386-linux-gnu",
    };
}

/* ── /etc/ld.so.conf parser ─────────────────────────────────────────────── */

void Resolver::load_ld_conf(const std::string& file_) {
    FILE* f = fopen(file_.c_str(), "r");
    if (!f) {
        return;
    }

    char line[PATH_MAX];
    while (fgets(line, sizeof(line), f)) {
        rtrim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        if (strncmp(line, "include ", 8) == 0) {
            char* pattern = line + 8;
            std::string dir  = dir_of(pattern);
            const char* base = pattern + dir.size() + (dir == "/" ? 0 : 1);
            std::string pfx(base);
            if (!pfx.empty() && pfx.back() == '*') {
                pfx.pop_back();
            }

            DIR* dp = opendir(dir.c_str());
            if (!dp) {
                continue;
            }
            struct dirent* de;
            while ((de = readdir(dp)) != nullptr) {
                if (de->d_name[0] == '.') {
                    continue;
                }
                if (pfx.empty() || strncmp(de->d_name, pfx.c_str(), pfx.size()) == 0) {
                    load_ld_conf(dir + "/" + de->d_name);
                }
            }
            closedir(dp);
        } else {
            conf_paths_.emplace_back(line);
        }
    }
    fclose(f);
}

/* ── $ORIGIN expansion ──────────────────────────────────────────────────── */

std::string Resolver::expand_origin(const std::string& entry_,
                                     const std::string& origin_) const {
    const std::string tok = "$ORIGIN";
    std::string r = entry_;
    size_t pos;
    while ((pos = r.find(tok)) != std::string::npos) {
        r.replace(pos, tok.size(), origin_);
    }
    return r;
}

/* ── Library lookup ─────────────────────────────────────────────────────── */

std::string Resolver::find_library(const std::string& libname_,
                                    const std::vector<std::string>& rpath_,
                                    const std::vector<std::string>& runpath_) const {
    std::vector<std::string> search;
    search.reserve(64);

    if (runpath_.empty()) {
        for (const auto& p : rpath_) {
            search.push_back(expand_origin(p, origin_dir_));
        }
    }

    for (const auto& p : ld_env_paths_) {
        search.push_back(p);
    }
    for (const auto& p : runpath_) {
        search.push_back(expand_origin(p, origin_dir_));
    }
    for (const auto& p : conf_paths_) {
        search.push_back(p);
    }
    for (const auto& p : default_paths_) {
        search.push_back(p);
    }

    for (const auto& dir : search) {
        std::string full = dir + "/" + libname_;
        if (is_regular_file(full)) {
            return realpath_of(full);
        }
    }
    return {};
}

/* ── Recursive graph builder ────────────────────────────────────────────── */

void Resolver::recurse(const std::string& path_,
                        DepGraph& graph_,
                        std::set<std::string>& visited_,
                        int depth_) {
    if (depth_ > _max_depth) {
        return;
    }
    if (!visited_.insert(path_).second) {
        return;
    }

    Component comp;
    if (!parse_elf_file(path_, comp)) {
        fprintf(stderr, "[warn] ELF parse failed: %s\n", path_.c_str());
        return;
    }

    std::string here = dir_of(path_);
    for (const auto& lib : comp._needed) {
        /* Use the per-file origin for $ORIGIN expansion */
        std::vector<std::string> rp_expanded;
        std::vector<std::string> rnp_expanded;
        for (const auto& p : comp._rpath) {
            rp_expanded.push_back(expand_origin(p, here));
        }
        for (const auto& p : comp._runpath) {
            rnp_expanded.push_back(expand_origin(p, here));
        }

        std::string resolved = find_library(lib, rp_expanded, rnp_expanded);
        comp._resolved_deps.push_back(resolved.empty() ? ("?" + lib) : resolved);
    }

    graph_._components[path_] = std::move(comp);
    graph_._discovery_order.push_back(path_);

    for (const auto& dep : graph_._components[path_]._resolved_deps) {
        if (dep[0] != '?') {
            recurse(dep, graph_, visited_, depth_ + 1);
        }
    }
}

void Resolver::analyze(const std::string& root_path_, DepGraph& graph_) {
    graph_._root_path = root_path_;
    std::set<std::string> visited;
    recurse(root_path_, graph_, visited, 0);
}

/* ── Directory batch analysis ───────────────────────────────────────────── */
/*
 * 1. Scan the directory tree for ELF files.
 * 2. Analyse each one individually.
 * 3. Merge all DepGraphs into a MultiGraph, deduplicating by absolute path.
 * 4. Track which roots use each dependency (MultiGraph::users).
 */
MultiGraph Resolver::analyze_directory(const std::string& dir_) {
    MultiGraph mg;
    mg._scan_root = dir_;

    auto elf_files = scan_elf_files(dir_, _skip_objects);
    if (elf_files.empty()) {
        fprintf(stderr, "[warn] no ELF files found in: %s\n", dir_.c_str());
        return mg;
    }

    fprintf(stderr, "Found %zu ELF file(s) in %s\n",
            elf_files.size(), dir_.c_str());

    /* Process each root ELF */
    for (const auto& elf : elf_files) {
        fprintf(stderr, "  analysing %s\n", elf.c_str());

        DepGraph dg;
        analyze(elf, dg);

        mg._roots.push_back(elf);

        /* Merge components — first-write wins for deduplication */
        for (const auto& path : dg._discovery_order) {
            if (!mg._components.count(path)) {
                mg._components[path] = dg._components.at(path);
                mg._ordered.push_back(path);
            }
            /* Track which root needs this component */
            if (path != elf) {
                mg._users[path].insert(elf);
            }
        }
    }

    return mg;
}
