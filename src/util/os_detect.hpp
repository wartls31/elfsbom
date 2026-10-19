#pragma once
#include <string>

/*
  Information parsed from /etc/os-release, /etc/debian_version, etc.
  Used to build correct package-type PURLs (pkg:deb, pkg:rpm, pkg:apk).
 */
struct OsRelease {
    std::string _id;                // "ubuntu", "debian", "fedora", "alpine"
    std::string _id_like;           //  e.g. "debian" when id="ubuntu"
    std::string _pretty_name;       //  "Ubuntu 22.04.3 LTS" 
    std::string _version_id;        // "22.04", "11", "37"
    std::string _version_codename;  // "jammy", "bullseye" 
};

/* Package manager family deduced from os-release. */
enum class PkgFamily { 
    Deb,
    Rpm,
    Apk,
    Unknown 
};

OsRelease read_os_release();
PkgFamily pkg_family(const OsRelease& os_);
std::string sys_arch();
std::string sys_hostname();
