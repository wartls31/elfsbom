#include <scan/string_scanner.hpp>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

/* ── Version token extraction ────────────────────────────────────────────── */
/*
 * From a string like "3.0.5 5 Jul 2022" or "1.2.11 Copyright…"
 * extract just the leading version number: "3.0.5", "1.2.11".
 *
 * Rules:
 *  - Skip leading spaces.
 *  - First character must be a digit.
 *  - Accept digits, dots, and trailing alpha (e.g. "1.2.3a").
 *  - Result must contain at least one dot.
 *  - Strip trailing dots.
 */
static std::string extract_version(const char* s_) {
    while (*s_ == ' ' || *s_ == '\t') {
        s_++;
    }
    if (!isdigit((unsigned char)*s_)) {
        return {};
    }

    const char* start = s_;
    while (*s_) {
        if (isdigit((unsigned char)*s_)) {
            s_++;
        } else if (*s_ == '.' && s_ > start && isdigit((unsigned char)*(s_+1))) {
            /* Accept dot only when followed by a digit */
            s_++;
        } else if (isalpha((unsigned char)*s_) && s_ > start) {
            /* Allow a short alphabetic suffix (e.g. "1.2.3a", "1.1.1q")
             * but reject long words like "background", "release", "beta". */
            size_t alpha_len = 0;
            const char* tmp = s_;
            while (isalpha((unsigned char)*tmp)) {
                alpha_len++;
                tmp++;
            }
            if (alpha_len <= 2) {
                s_ = tmp;  /* "a", "q", "rc" are OK */
            } else {
                break;     /* "beta", "background" → stop */
            }
        } else {
            break;
        }
    }

    std::string v(start, s_);
    /* Require at least one dot flanked by digits on both sides */
    bool valid = false;
    for (size_t i = 1; i + 1 < v.size(); i++) {
        if (v[i] == '.' && isdigit((unsigned char)v[i-1])
                        && isdigit((unsigned char)v[i+1])) {
            valid = true;
            break;
        }
    }
    if (!valid) {
        return {};
    }

    while (!v.empty() && v.back() == '.') {
        v.pop_back();
    }
    return v;
}

/* ── Prefix-based pattern table ─────────────────────────────────────────── */
/*
 * Each entry maps a string literal that a library embeds in its .rodata to
 * the canonical library name.  The version number follows immediately after
 * the prefix (possibly after a leading space, handled by extract_version).
 */
struct PrefixPat { const char* pfx; const char* lib; };

static const PrefixPat PREFIX_PATS[] = {
    /* TLS / crypto */
    {"OpenSSL ",              "openssl"},
    {"LibreSSL ",             "libressl"},
    {"GnuTLS ",               "gnutls"},
    {"Botan ",                "botan"},
    {"mbedTLS ",              "mbedtls"},
    /* HTTP / network */
    {"libcurl/",              "libcurl"},
    {"nghttp2/",              "nghttp2"},
    {"libssh2/",              "libssh2"},
    {"libssh/",               "libssh"},
    /* Compression
     * zlib embeds: " inflate 1.2.11 Copyright 1995-2017 Mark Adler "
     *          and: "deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly" */
    {" inflate ",             "zlib"},
    {"deflate ",              "zlib"},
    {"zlib/",                 "zlib"},
    /* ZSTD embeds "*** Zstandard ERR_getErrorName ..." in some builds,
     * but more reliably: the version string from ZSTD_versionString() */
    {"zstd ",                 "zstd"},
    {"brotli/",               "brotli"},
    {"LZ4 ",                  "lz4"},
    /* Databases */
    {"SQLite version ",       "sqlite3"},
    /* Images */
    {"libpng version ",       "libpng"},
    /* XML */
    {"Expat ",                "expat"},
    /* Regex */
    {"PCRE version ",         "pcre"},
    {"PCRE2 ",                "pcre2"},
    /* Event loops */
    {"libuv/",                "libuv"},
    /* Scripting */
    {"Lua ",                  "lua"},
    /* Audio */
    {"libvorbis ",            "libvorbis"},
    {"libFLAC ",              "libflac"},
    /* LLVM / Clang toolchain — version strings embedded by llvm::sys::getVersion() */
    {"LLVM version ",         "llvm"},
    {"clang version ",        "clang"},
    {"LLD ",                  "lld"},
    /* Cryptography */
    {"libsodium ",            "libsodium"},
    {"Nettle ",               "nettle"},
    /* Hash / serialisation */
    {"xxHash ",               "xxhash"},
    /* Compression */
    {"Snappy ",               "snappy"},
    /* Databases */
    {"LevelDB version ",      "leveldb"},
    {"RocksDB version ",      "rocksdb"},
    {"LMDB ",                 "lmdb"},
    /* Memory allocators */
    {"jemalloc-",             "jemalloc"},
    {"tcmalloc ",             "tcmalloc"},
    /* Computer vision */
    {"OpenCV ",               "opencv"},
    /* Networking */
    {"c-ares/",               "c-ares"},
    /* Serialisation / interchange */
    {"FlatBuffers version ",  "flatbuffers"},
    {"Protocol Buffers ",     "protobuf"},
    /* gRPC embeds its version via "grpc." build tags */
    {"grpc.version ",         "grpc"},
    /* Test framework (survives in debug builds) */
    {"googletest-",           "googletest"},
    {nullptr, nullptr}
};

/* ── Compound "word/X.Y.Z" parser ────────────────────────────────────────── */
/*
 * Parse strings such as:
 *   "libcurl/7.85.0 OpenSSL/3.0.5 zlib/1.2.11 nghttp2/1.51.0 brotli/1.0.9"
 *
 * For every occurrence of a '/' preceded by an all-ASCII word and followed
 * by a version number, we record the (word, version) pair.
 * Only names with at least 2 characters are kept to filter noise.
 */
static void parse_compound(const char* str_, size_t len_,
                             std::map<std::string, std::string>& out_) {
    const char* end = str_ + len_;
    const char* p   = str_;

    while (p < end) {
        const char* slash = (const char*)memchr(p, '/', (size_t)(end - p));
        if (!slash) {
            break;
        }

        /* Walk backwards to find the start of the word before '/' */
        const char* w = slash;
        while (w > str_ &&
               (isalnum((unsigned char)*(w - 1)) ||
                *(w - 1) == '-' || *(w - 1) == '_')) {
            w--;
        }

        if (w < slash && isalpha((unsigned char)*w)) {
            std::string name(w, slash);
            std::string ver = extract_version(slash + 1);

            if (!ver.empty() && name.size() >= 3) {
                /*
                 * Reject all-uppercase tokens: they are protocol identifiers
                 * (HTTP, RTSP, FTP, TLS, …), not library names.
                 * Library names always contain at least one lowercase letter.
                 */
                bool all_upper = true;
                for (char ch : name) {
                    if (islower((unsigned char)ch)) {
                        all_upper = false;
                        break;
                    }
                }

                if (!all_upper) {
                    out_.emplace(name, ver);   /* first occurrence wins */
                }
            }
        }
        p = slash + 1;
    }
}

/* ── DWARF build-path parser ─────────────────────────────────────────────── */
/*
 * Parse CU source paths like:
 *   "/build/openssl-3.0.5/ssl/ssl_lib.c"   → {openssl, 3.0.5, dwarf-path}
 *   "/tmp/curl-7.85.0/lib/url.c"            → {curl, 7.85.0,   dwarf-path}
 *   "/usr/src/zlib-1.2.11/deflate.c"        → {zlib, 1.2.11,   dwarf-path}
 *
 * The pattern is: a path component of the form "NAME-X.Y.Z" where NAME is
 * alphabetic and X.Y.Z looks like a version number.
 */
static void extract_dwarf_versions(const std::vector<std::string>& cu_sources_,
                                    std::map<std::string, std::string>& out_) {
    for (const auto& src : cu_sources_) {
        const char* p = src.c_str();
        while (*p) {
            /* Look for '-' followed by a digit (version separator) */
            if (*p == '-' && p > src.c_str() && isdigit((unsigned char)*(p + 1))) {
                /* Walk back to find the library name */
                const char* name_end   = p;
                const char* name_start = p - 1;
                while (name_start > src.c_str() &&
                       (isalnum((unsigned char)*name_start) ||
                        *name_start == '_')) {
                    name_start--;
                }
                /* name_start might point before an alphanumeric, advance */
                if (!isalpha((unsigned char)*name_start)) {
                    name_start++;
                }

                if (name_start < name_end && isalpha((unsigned char)*name_start)) {
                    std::string name(name_start, name_end);
                    std::string ver = extract_version(p + 1);
                    /* Version must end at '/' or end-of-path-component */
                    if (!ver.empty()) {
                        out_.emplace(name, ver);
                    }
                }
            }
            p++;
        }
    }
}

/* ── Merge helper ────────────────────────────────────────────────────────── */
/*
 * Insert or upgrade an entry in the result vector.
 * An entry with a version is always preferred over one without.
 * Among entries with versions, the first insertion wins.
 */
static void merge_result(std::vector<StaticLibInfo>& found_,
                          const std::string& name_,
                          const std::string& version_,
                          const std::string& method_) {
    for (auto& e : found_) {
        if (e._name == name_) {
            /* Upgrade: replace method/version if we now have a version */
            if (e._version.empty() && !version_.empty()) {
                e._version = version_;
                e._method  = method_;
            }
            return;
        }
    }
    found_.push_back({name_, version_, method_, ""});
}

/* ── ELF .rodata section scanner ─────────────────────────────────────────── */

static void scan_elf_sections(const std::string& path_,
                               std::map<std::string, std::string>& detected_) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return;
    }

    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return;
    }

    size_t shstrndx = 0;
    elf_getshdrstrndx(elf, &shstrndx);

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        /* Only scan allocated, non-executable data sections */
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

        /*
         * Target sections:
         *   .rodata          — main string constant pool
         *   .rodata.str*     — GCC merged string subsections
         *   .data.rel.ro     — const data requiring relocation
         */
        bool scan_this =
            strncmp(sname, ".rodata",      7) == 0 ||
            strcmp (sname, ".data.rel.ro") == 0;
        if (!scan_this) {
            continue;
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data || !data->d_buf || data->d_size == 0) {
            continue;
        }

        const char* buf  = (const char*)data->d_buf;
        size_t       size = data->d_size;

        /* Walk the section byte by byte, extracting printable strings. */
        size_t i = 0;
        while (i < size) {
            /* Skip non-printable bytes */
            if (!isprint((unsigned char)buf[i])) {
                i++;
                continue;
            }

            /* Find end of this printable run */
            size_t start = i;
            while (i < size && buf[i] != '\0' &&
                   (isprint((unsigned char)buf[i]) || buf[i] == '\t')) {
                i++;
            }

            size_t slen = i - start;
            if (slen < 5) {
                if (i < size && buf[i] == '\0') {
                    i++;
                }
                continue;
            }
            const char* s = buf + start;

            /* 1 — Prefix-based matching */
            for (const PrefixPat* pp = PREFIX_PATS; pp->pfx; pp++) {
                size_t plen = strlen(pp->pfx);
                if (slen >= plen && memcmp(s, pp->pfx, plen) == 0) {
                    std::string ver = extract_version(s + plen);
                    if (!ver.empty()) {
                        auto it = detected_.find(pp->lib);
                        /* Keep first hit, or upgrade empty → versioned */
                        if (it == detected_.end() || it->second.empty()) {
                            detected_[pp->lib] = ver;
                        }
                    }
                }
            }

            /* 2 — Compound "word/X.Y.Z" scan (min length heuristic) */
            if (slen >= 12 && memchr(s, '/', slen)) {
                parse_compound(s, slen, detected_);
            }

            if (i < size && buf[i] == '\0') {
                i++;
            }
        }
    }

    elf_end(elf);
    close(fd);
}

/* ── Public interface ────────────────────────────────────────────────────── */

void scan_version_strings(const std::string& path_,
                           const std::vector<std::string>& cu_sources_,
                           std::vector<StaticLibInfo>& found_) {
    /* -- Strategy 1 & 2: .rodata scanning --------------------------------- */
    std::map<std::string, std::string> from_rodata;
    scan_elf_sections(path_, from_rodata);

    for (const auto& [lib, ver] : from_rodata) {
        merge_result(found_, lib, ver, "version-string");
    }

    /* -- Strategy 3: DWARF build-path parsing ----------------------------- */
    std::map<std::string, std::string> from_dwarf;
    extract_dwarf_versions(cu_sources_, from_dwarf);

    for (const auto& [lib, ver] : from_dwarf) {
        merge_result(found_, lib, ver, "dwarf-path");
    }
}
