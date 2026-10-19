#include <util/os_detect.hpp>

#include <cstdio>
#include <cstring>
#include <sys/utsname.h>
#include <unistd.h>

/* ── /etc/os-release parser ─────────────────────────────────────────────── */
/*
 * Handles both quoted ("Ubuntu 22.04") and unquoted (ubuntu) values,
 * and ignores comments and blank lines.
 */
OsRelease read_os_release() {
    OsRelease info;

    FILE* f = fopen("/etc/os-release", "r");
    if (!f) {
        f = fopen("/usr/lib/os-release", "r"); /* fallback */
    }
    if (!f) {
        return info;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        char* nl = strpbrk(line, "\r\n");
        if (nl) {
            *nl = '\0';
        }

        /* Skip blanks and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char* eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';

        const char* key = line;
        char*       val = eq + 1;

        /* Strip surrounding double-quotes */
        size_t vlen = strlen(val);
        if (vlen >= 2 && val[0] == '"' && val[vlen - 1] == '"') {
            val[vlen - 1] = '\0';
            val++;
        }

        if (strcmp(key, "ID") == 0) {
            info._id = val;
        } else if (strcmp(key, "ID_LIKE") == 0) {
            info._id_like = val;
        } else if (strcmp(key, "PRETTY_NAME") == 0) {
            info._pretty_name = val;
        } else if (strcmp(key, "VERSION_ID") == 0) {
            info._version_id = val;
        } else if (strcmp(key, "VERSION_CODENAME") == 0) {
            info._version_codename = val;
        }
    }
    fclose(f);
    return info;
}

/* ── Package family classification ──────────────────────────────────────── */

PkgFamily pkg_family(const OsRelease& os_) {
    /* Check both id and id_like for family membership */
    const std::string combined = os_._id + " " + os_._id_like;

    auto has = [&](const char* s) {
        return combined.find(s) != std::string::npos;
    };

    if (has("debian") || 
        has("ubuntu") || 
        has("raspbian") ||
        has("kali") || 
        has("mint") || 
        has("pop")) {
        return PkgFamily::Deb;
    }

    if (has("fedora") ||
        has("rhel") || 
        has("centos") ||
        has("rocky") ||   
        has("alma") || 
        has("suse") ||
        has("opensuse")|| 
        has("oracle")) {
        return PkgFamily::Rpm;
    }

    if (has("alpine")) {
        return PkgFamily::Apk;
    }

    return PkgFamily::Unknown;
}

/* ── System architecture ─────────────────────────────────────────────────── */

std::string sys_arch() {
    struct utsname u;
    if (uname(&u) == 0) {
        return u.machine;
    }
    return "unknown";
}

/* ── Hostname ────────────────────────────────────────────────────────────── */

std::string sys_hostname() {
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) {
        return buf;
    }
    return "unknown";
}
