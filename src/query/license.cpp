#include <query/license.hpp>
#include <util/os_detect.hpp>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

/* ── Utilities ──────────────────────────────────────────────────────────── */

static std::string run_cmd(const char* cmd_) {
    FILE* p = popen(cmd_, "r");
    if (!p) {
        return {};
    }
    std::string out;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) {
        out += buf;
    }
    pclose(p);
    while (!out.empty() && (unsigned char)out.back() <= ' ') {
        out.pop_back();
    }
    return out;
}

static const char* ltrim(const char* s_) {
    while (*s_ == ' ' || *s_ == '\t') {
        s_++;
    }
    return s_;
}

static void rtrim(std::string& s_) {
    while (!s_.empty() && (unsigned char)s_.back() <= ' ') {
        s_.pop_back();
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Known-library → SPDX expression table
 *
 * SPDX license identifiers: https://spdx.org/licenses/
 * ════════════════════════════════════════════════════════════════════════════ */

struct LicEntry {
    const char* _name;
    const char* _spdx;
};

static const LicEntry LIC_TABLE[] = {
    /* Cryptography / TLS */
    {"botan",         "BSD-2-Clause"             },
    {"gnutls",        "LGPL-2.1-or-later"        },
    {"libgcrypt",     "LGPL-2.1-or-later"        },
    {"libsodium",     "ISC"                      },
    {"libressl",      "ISC"                      },
    {"mbedtls",       "Apache-2.0"               },
    /* openssl: version-sensitive — handled separately below */
    {"wolfssl",       "GPL-2.0-or-later"         },
    /* HTTP / networking */
    {"brotli",        "MIT"                      },
    {"libcurl",       "curl"                     },  /* curl (SPDX id: curl) */
    {"nghttp2",       "MIT"                      },
    {"libssh",        "LGPL-2.1-or-later"        },
    {"libssh2",       "BSD-3-Clause"             },
    /* Compression */
    {"bzip2",         "bzip2-1.0.6"              },
    {"liblzma",       "LGPL-2.1-or-later"        },
    {"lz4",           "BSD-2-Clause"             },
    {"zlib",          "Zlib"                     },
    {"zstd",          "BSD-3-Clause"             },
    /* Databases */
    {"libpq",         "PostgreSQL"               },
    {"sqlite3",       "blessing"                 },  /* public domain */
    /* XML / parsing */
    {"expat",         "MIT"                      },
    {"json-c",        "MIT"                      },
    {"cjson",         "MIT"                      },
    {"libyaml",       "MIT"                      },
    {"libxml2",       "MIT"                      },
    {"libxslt",       "MIT"                      },
    /* Images */
    {"libjpeg",       "LicenseRef-IJG"           },
    {"libpng",        "libpng"                   },  /* libpng license */
    {"libtiff",       "libtiff"                  },
    {"libwebp",       "BSD-3-Clause"             },
    /* Regex */
    {"libpcre",       "BSD-3-Clause"             },
    {"libpcre2",      "BSD-3-Clause"             },
    /* Event loops */
    {"libevent",      "BSD-3-Clause"             },
    {"libuv",         "MIT"                      },
    /* Serialisation */
    {"nanopb",        "Zlib"                     },
    {"flatbuffers",   "Apache-2.0"               },
    {"protobuf",      "BSD-3-Clause"             },
    /* Misc */
    {"apr",           "Apache-2.0"               },
    {"libcap",        "BSD-3-Clause OR GPL-2.0-only"},
    {"libuuid",       "BSD-3-Clause"             },
    {"lua",           "MIT"                      },
    {"readline",      "GPL-3.0-or-later"         },
    {nullptr, nullptr}
};

std::string known_lib_spdx(const std::string& name_, const std::string& version_) {
    /*
     * OpenSSL changed license from its own "OpenSSL" license to Apache-2.0
     * starting with version 3.0.0 (released 2021-09-07).
     */
    if (name_ == "openssl" || name_ == "libssl" || name_ == "libcrypto") {
        if (!version_.empty()) {
            int major = atoi(version_.c_str());
            return major >= 3 ? "Apache-2.0" : "LicenseRef-OpenSSL";
        }
        return "Apache-2.0";  /* default to current */
    }

    for (const LicEntry* e = LIC_TABLE; e->_name; e++) {
        if (name_ == e->_name) {
            return e->_spdx;
        }
    }

    return {};
}

/* ════════════════════════════════════════════════════════════════════════════
 * Source 1 — Package manager queries
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * DEB: parse /usr/share/doc/<pkg>/copyright.
 * Looks for:
 *   "SPDX-License-Identifier: <expr>"  (REUSE-style, highest priority)
 *   "License: <expr>"                   (DEP-5 machine-readable format)
 *
 * Only scans the first 8 KB to keep it fast; the license header is always
 * near the top of the copyright file.
 */
static std::string deb_copyright_license(const std::string& pkg_name_) {
    std::string path = "/usr/share/doc/" + pkg_name_ + "/copyright";
    FILE* f = fopen(path.c_str(), "r");
    if (!f) {
        return {};
    }

    char line[512];
    std::string result;
    size_t bytes_read = 0;
    const size_t MAX_BYTES = 8192;

    while (bytes_read < MAX_BYTES && fgets(line, sizeof(line), f)) {
        bytes_read += strlen(line);

        /* REUSE-style: SPDX-License-Identifier anywhere on the line */
        const char* spdx = strstr(line, "SPDX-License-Identifier:");
        if (spdx) {
            spdx += strlen("SPDX-License-Identifier:");
            result = ltrim(spdx);
            rtrim(result);
            break;
        }

        /* DEP-5: License: at the start of a line (header section) */
        if (strncmp(line, "License:", 8) == 0) {
            const char* val = ltrim(line + 8);
            result = val;
            rtrim(result);
            /* DEP-5 license field may have the expression on the first "word"
             * followed by verbose text.  Keep only the first token-cluster
             * (no embedded spaces in a proper SPDX expression, except for
             * " OR ", " AND " — so stop at the first bare space after
             * a version-like pattern). */
            /* Actually SPDX expressions CAN contain spaces, e.g.
             * "GPL-2.0-only WITH Classpath-exception-2.0"
             * Just take the whole trimmed value. */
            break;
        }
    }
    fclose(f);
    return result;
}

static std::string rpm_license(const std::string& pkg_name_) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "rpm -q --queryformat '%%{LICENSE}' '%s' 2>/dev/null",
        pkg_name_.c_str());
    return run_cmd(cmd);
}

static std::string apk_license(const std::string& pkg_name_) {
    /* apk info pkg_name outputs multi-line; license is on a "License: XXX" line */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "apk info '%s' 2>/dev/null | grep -i '^license' | head -1"
        " | sed 's/^[Ll]icense:[[:space:]]*//'",
        pkg_name_.c_str());
    return run_cmd(cmd);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Source 3 — Binary string scan (.rodata / .data.rel.ro)
 *
 * Some projects compiled with REUSE-compliant tooling embed
 * "SPDX-License-Identifier: <expr>" strings in their read-only data.
 * We scan up to MAX_SCAN_BYTES of each matching section.
 * ════════════════════════════════════════════════════════════════════════════ */

static const size_t MAX_SCAN_BYTES = 65536; /* 64 KB per section */

static std::string scan_binary_spdx(const std::string& path_) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return {};
    }

    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return {};
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return {};
    }

    size_t shstrndx = 0;
    elf_getshdrstrndx(elf, &shstrndx);

    std::string result;
    static const char TARGET[] = "SPDX-License-Identifier:";
    static const size_t TLEN   = sizeof(TARGET) - 1;

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr && result.empty()) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }
        if (shdr.sh_type != SHT_PROGBITS) {
            continue;
        }
        if (!(shdr.sh_flags & SHF_ALLOC)) {
            continue;
        }
        if (shdr.sh_flags & SHF_EXECINSTR) {
            continue;
        }

        const char* sname = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (!sname) {
            continue;
        }
        if (strncmp(sname, ".rodata", 7) != 0 &&
            strcmp(sname,  ".data.rel.ro") != 0) {
            continue;
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data || !data->d_buf) {
            continue;
        }

        const char* buf  = (const char*)data->d_buf;
        size_t       size = data->d_size < MAX_SCAN_BYTES
                            ? data->d_size : MAX_SCAN_BYTES;

        /* Simple Boyer-Moore-Horspool-like scan */
        for (size_t i = 0; i + TLEN < size; i++) {
            if (memcmp(buf + i, TARGET, TLEN) != 0) {
                continue;
            }

            const char* val = buf + i + TLEN;
            while (*val == ' ' || *val == '\t') {
                val++;
            }

            /* Extract until end-of-string / non-printable */
            std::string expr;
            while (*val && (isprint((unsigned char)*val) || *val == ' ')
                   && expr.size() < 128) {
                expr += *val++;
            }

            rtrim(expr);
            if (!expr.empty()) {
                result = expr;
                break;
            }
        }
    }

    elf_end(elf);
    close(fd);
    return result;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public interface
 * ════════════════════════════════════════════════════════════════════════════ */

void detect_license(Component& comp_, const OsRelease& os_) {
    /* ── Dynamic component license ───────────────────────────────────────── */
    if (comp_._license.empty() && !comp_._pkg_name.empty()) {
        PkgFamily fam = pkg_family(os_);
        switch (fam) {
            case PkgFamily::Deb:
                comp_._license = deb_copyright_license(comp_._pkg_name);
                break;
            case PkgFamily::Rpm:
                comp_._license = rpm_license(comp_._pkg_name);
                break;
            case PkgFamily::Apk:
                comp_._license = apk_license(comp_._pkg_name);
                break;
            default:
                break;
        }
    }

    /* Fall back: known-library mapping using canonical name + version */
    if (comp_._license.empty()) {
        /* Try soname-derived canonical name (e.g. "libssl.so.3" → "libssl") */
        std::string cname = comp_._name;
        auto dot = cname.find(".so.");
        if (dot != std::string::npos) {
            cname = cname.substr(0, dot);
        }
        comp_._license = known_lib_spdx(cname, comp_._pkg_version);
    }

    /* Fall back: scan binary for embedded SPDX identifier */
    if (comp_._license.empty() && !comp_._path.empty()) {
        comp_._license = scan_binary_spdx(comp_._path);
    }

    /* ── Static lib licenses ─────────────────────────────────────────────── */
    for (auto& sl : comp_._static_libs) {
        if (!sl._license.empty()) {
            continue;
        }
        sl._license = known_lib_spdx(sl._name, sl._version);
    }
}
