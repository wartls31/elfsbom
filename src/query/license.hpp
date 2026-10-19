#pragma once
#include <util/types.hpp>

struct OsRelease;

/*
  Detect and fill comp.license (and the ._license field of each static lib)
  from the following sources, in priority order:
 
    1. Package manager
         DEB  : parse /usr/share/doc/<pkg>/copyright for SPDX-License-Identifier:" (REUSE) or "License:" (DEP-5)
         RPM  : rpm -q --queryformat '%{LICENSE}'
         APK  : apk info <pkg>  (grep for license field)
 
    2. Known-library table
         Static mapping  canonical_name → SPDX expression.
         Version-aware: openssl >= 3.0 → Apache-2.0, older → LicenseRef-OpenSSL.
 
    3. Binary string scan (.rodata)
         Look for embedded "SPDX-License-Identifier: <expr>" strings
         placed by REUSE-compliant build systems.
 */
void detect_license(Component& comp_, const OsRelease& os_);

std::string known_lib_spdx(const std::string& name_, const std::string& version_ = {});
