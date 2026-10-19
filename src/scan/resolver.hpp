#pragma once
#include <util/types.hpp>
#include <set>

/*
  Resolves ELF library dependencies following the Linux dynamic linker search order (per ld.so(8)):
    1. RPATH (only when RUNPATH is absent)
    2. LD_LIBRARY_PATH
    3. RUNPATH
    4. /etc/ld.so.conf  (and included fragments)
    5. Default paths: /lib, /usr/lib, multiarch variants
*/
class Resolver {
    public:
        // origin_dir: directory of the root binary; used to expand $ORIGIN
        explicit Resolver(const std::string& origin_dir_);

        // Resolve "libfoo.so.1" to its absolute path; returns "" if not found
        std::string find_library(const std::string& libname_, const std::vector<std::string>& rpath_, const std::vector<std::string>& runpath_) const;

        // Analyse all transitive dependencies of a single ELF file
        void analyze(const std::string& root_path_, DepGraph& graph_);

        // Scan dir for ELF files, analyse each one, merge all dependency graphs into a single deduplicated MultiGraph.
        MultiGraph analyze_directory(const std::string& dir_);

    public:
        bool _include_system_libs;
        bool _skip_objects; 
        int32_t  _max_depth;

    protected:
        std::string _origin_dir;
        std::vector<std::string> ld_env_paths_;
        std::vector<std::string> conf_paths_;
        std::vector<std::string> default_paths_;

        void load_ld_conf(const std::string& file_);
        std::string expand_origin(const std::string& p_, const std::string& origin_) const;
        void recurse(const std::string& path_, DepGraph& graph_, std::set<std::string>& visited_,int32_t depth_);
    };
