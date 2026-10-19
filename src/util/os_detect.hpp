#pragma once
#include <string>

/*
 * Information parsed from /etc/os-release, /etc/debian_version, etc.
 * Used to build correct package-type PURLs (pkg:deb, pkg:rpm, pkg:apk).
 */
struct OsRelease {
    std::string _id;           /* "ubuntu", "debian", "fedora", "alpine", … */
    std::string _id_like;      /* e.g. "debian" when id="ubuntu"            */
    std::string _pretty_name;  /* "Ubuntu 22.04.3 LTS"                      */
    std::string _version_id;   /* "22.04", "11", "37"                       */
    std::string _version_codename; /* "jammy", "bullseye"                   */
};

/* Package manager family deduced from os-release. */
enum class PkgFamily { Deb, Rpm, Apk, Unknown };

/* Read /etc/os-release (libc fopen/fgets only). */
OsRelease read_os_release();

/* Derive pkg family from OsRelease::id / id_like. */
PkgFamily pkg_family(const OsRelease& os_);

/* System architecture string via uname(2) syscall, e.g. "x86_64". */
std::string sys_arch();

/* Hostname via gethostname(2). */
std::string sys_hostname();
