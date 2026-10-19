#pragma once
#include <util/types.hpp>
#include <set>
#include <string>
#include <vector>


struct HintsFile {
    std::vector<StaticLibInfo> _libs;  // positive hints
    std::set<std::string> _excludes;   // false-positive suppressions 
};

/*
  Load a user-provided static dependency hints file.
 
    product                        name only   (version and license unknown)
    product  version               name + version
    product  version  license      name + version + SPDX expression
    product  -        license      name + license, version unknown ('-' placeholder)
    # comment                      ignored
    (blank line)                   ignored
 
  Example:
 
    openssl  3.0.5   Apache-2.0
    zlib     1.2.11  Zlib
    my_lib   -       LicenseRef-Proprietary
    unknown_embedded_sdk
 
  All positive entries get method = "hint-file".
 
  A line starting with '!' marks a library as a false positive. 
*/
HintsFile load_hints_file(const std::string& path_);
