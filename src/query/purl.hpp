#pragma once
#include <util/types.hpp>

struct OsRelease;

/*
  Generate a Package URL (PURL) for a dynamically-linked component.
 
  Priority:
    1. pkg:deb / pkg:rpm / pkg:apk  when pkg_name + pkg_version are known.
    2. pkg:generic/{soname}@{version}  when version can be inferred from the
       soname (e.g. libssl.so.3 → version hint "3").
    3. Empty string if insufficient information.
 
  PURL spec: https://github.com/package-url/purl-spec
*/
std::string make_purl(const Component& c_, const OsRelease& os_);

/*
  Generate a PURL for a statically-linked library identified by string/symbol scanner.
    - With version  : pkg:generic/{name}@{version}
    - Without version: empty string
 */
std::string make_static_purl(const StaticLibInfo& sl_);

/*
  Generate a CPE 2.3 string for a known library.
  CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
*/
std::string make_cpe(const std::string& canonical_name_, const std::string& version_);
