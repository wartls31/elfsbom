#include <query/purl.hpp>
#include <util/os_detect.hpp>

#include <cctype>
#include <cstdio>
#include <cstring>

/* ── URL percent-encoding (PURL requires encoded names) ─────────────────── */
/*
 * Only encode characters that are not PURL-safe.
 * Letters, digits, '-', '_', '.', '~' are safe (RFC 3986 unreserved).
 * The '@' and '/' are structural in PURL and must NOT be encoded here.
 */
static std::string purl_encode(const std::string& s_) {
    std::string out;
    out.reserve(s_.size() + 8);
    for (unsigned char c : s_) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += (char)c;
        } else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

/* ── PURL for a dynamically-linked component ────────────────────────────── */

std::string make_purl(const Component& c_, const OsRelease& os_) {
    /* Prefer package manager name over soname for CVE matching */
    const std::string& name = c_._pkg_name.empty() ? c_._name : c_._pkg_name;

    if (name.empty()) {
        return {};
    }

    /* Case 1: Known package manager name + version → typed PURL */
    if (!c_._pkg_name.empty() && !c_._pkg_version.empty()) {
        char buf[512];
        PkgFamily fam = pkg_family(os_);

        switch (fam) {
            case PkgFamily::Deb:
                /* pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10 */
                snprintf(buf, sizeof(buf), "pkg:deb/%s/%s@%s",
                         purl_encode(os_._id).c_str(),
                         purl_encode(c_._pkg_name).c_str(),
                         purl_encode(c_._pkg_version).c_str());
                return buf;

            case PkgFamily::Rpm:
                /* pkg:rpm/rhel/openssl-libs@3.0.7-18.el9_2 */
                snprintf(buf, sizeof(buf), "pkg:rpm/%s/%s@%s",
                         purl_encode(os_._id).c_str(),
                         purl_encode(c_._pkg_name).c_str(),
                         purl_encode(c_._pkg_version).c_str());
                return buf;

            case PkgFamily::Apk:
                /* pkg:apk/alpine/openssl@3.0.7-r0 */
                snprintf(buf, sizeof(buf), "pkg:apk/alpine/%s@%s",
                         purl_encode(c_._pkg_name).c_str(),
                         purl_encode(c_._pkg_version).c_str());
                return buf;

            default:
                /* pkg:generic/name@version */
                snprintf(buf, sizeof(buf), "pkg:generic/%s@%s",
                         purl_encode(c_._pkg_name).c_str(),
                         purl_encode(c_._pkg_version).c_str());
                return buf;
        }
    }

    /* Case 2: No package manager info — try to derive version from SONAME.
     * E.g. "libssl.so.3" → pkg:generic/libssl@3  (stripped canonical name).
     * We do NOT emit a PURL without a version: it would match all versions. */
    if (!c_._soname.empty()) {
        /* Find ".so." separator to split base name and version */
        const char* so_sep = strstr(c_._soname.c_str(), ".so.");
        if (so_sep) {
            std::string base(c_._soname.c_str(), so_sep); /* e.g. "libssl"   */
            std::string ver(so_sep + 4);                  /* e.g. "3"        */
            /* Accept only when ver starts with a digit and is short */
            if (!ver.empty() && ver.size() <= 10 && isdigit((unsigned char)ver[0])) {
                char buf[256];
                snprintf(buf, sizeof(buf), "pkg:generic/%s@%s",
                         purl_encode(base).c_str(),
                         purl_encode(ver).c_str());
                return buf;
            }
        }
    }

    return {};  /* insufficient information */
}

/* ── PURL for a statically-linked library ───────────────────────────────── */

std::string make_static_purl(const StaticLibInfo& sl_) {
    if (sl_._name.empty() || sl_._version.empty()) {
        return {};
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "pkg:generic/%s@%s",
             purl_encode(sl_._name).c_str(),
             purl_encode(sl_._version).c_str());
    return buf;
}

/* ── CPE 2.3 generation ─────────────────────────────────────────────────── */
/*
 * NVD CPE vendor/product mappings for common C/C++ libraries.
 * These must exactly match the CPE dictionary in the NVD:
 *   https://nvd.nist.gov/products/cpe/search
 *
 * Format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
 */
struct CpeEntry {
    const char* _name;
    const char* _vendor;
    const char* _product;
};

static const CpeEntry CPE_TABLE[] = {
    /* TLS / Crypto */
    {"openssl",   "openssl",         "openssl"       },
    {"libressl",  "openbsd",         "libressl"      },
    {"gnutls",    "gnu",             "gnutls"        },
    {"mbedtls",   "arm",             "mbed_tls"      },
    {"libgcrypt", "gnupg",           "libgcrypt"     },
    /* HTTP / network */
    {"libcurl",   "haxx",            "libcurl"       },
    {"nghttp2",   "nghttp2",         "nghttp2"       },
    {"libssh2",   "libssh2",         "libssh2"       },
    {"libssh",    "libssh",          "libssh"        },
    /* Compression */
    {"zlib",      "zlib",            "zlib"          },
    {"zstd",      "facebook",        "zstandard"     },
    {"lz4",       "lz4_project",     "lz4"           },
    {"liblzma",   "tukaani",         "xz"            },
    {"bzip2",     "bzip",            "bzip2"         },
    {"brotli",    "google",          "brotli"        },
    /* Databases */
    {"sqlite3",   "sqlite",          "sqlite"        },
    {"libpq",     "postgresql",      "postgresql"    },
    /* XML / parsing */
    {"libxml2",   "xmlsoft",         "libxml2"       },
    {"expat",     "libexpat",        "expat"         },
    {"libyaml",   "pyyaml",          "libyaml"       },
    /* Images */
    {"libpng",    "libpng",          "libpng"        },
    {"libjpeg",   "ijg",             "libjpeg"       },
    {"libwebp",   "webmproject",     "libwebp"       },
    {"libtiff",   "libtiff",         "libtiff"       },
    /* Regex */
    {"libpcre",   "pcre",            "pcre"          },
    {"libpcre2",  "pcre",            "pcre2"         },
    /* Event loops */
    {"libuv",     "libuv",           "libuv"         },
    {"libevent",  "libevent_project","libevent"      },
    /* Other */
    {"lua",       "lua",             "lua"           },
    {"libvorbis", "xiph",            "libvorbis"     },
    {nullptr, nullptr, nullptr}
};

std::string make_cpe(const std::string& canonical_name_,
                      const std::string& version_) {
    if (version_.empty()) {
        return {};
    }

    for (const CpeEntry* e = CPE_TABLE; e->_name; e++) {
        if (canonical_name_ == e->_name) {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
                     e->_vendor, e->_product, version_.c_str());
            return buf;
        }
    }
    return {};
}
