#include <scan/elf_parser.hpp>
#include <scan/sig_scanner.hpp>
#include <scan/string_scanner.hpp>

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <gelf.h>
#include <libelf.h>


static const char* arch_name(uint16_t m_) {
    switch (m_) {
        case EM_386:     return "x86";
        case EM_X86_64:  return "x86_64";
        case EM_ARM:     return "arm";
        case EM_AARCH64: return "aarch64";
        case EM_MIPS:    return "mips";
        case EM_PPC:     return "powerpc";
        case EM_PPC64:   return "powerpc64";
        case EM_S390:    return "s390x";
        case EM_RISCV:   return "riscv64";
        default:         return "unknown";
    }
}

static const char* abi_name(unsigned char osabi_) {
    switch (osabi_) {
        case ELFOSABI_NONE:    return "System V";
        case ELFOSABI_GNU:     return "GNU/Linux";
        case ELFOSABI_FREEBSD: return "FreeBSD";
        case ELFOSABI_NETBSD:  return "NetBSD";
        case ELFOSABI_OPENBSD: return "OpenBSD";
        default:               return "Unknown";
    }
}

static std::string bytes_to_hex(const unsigned char* data_, size_t len_) {
    std::string out(len_ * 2, '\0');
    for (size_t i = 0; i < len_; i++) {
        snprintf(&out[i * 2], 3, "%02x", (unsigned)data_[i]);
    }
    return out;
}

static std::vector<std::string> split_colon(const char* s_) {
    std::vector<std::string> v;
    if (!s_ || !*s_) {
        return v;
    }
    const char* start = s_;
    for (const char* p = s_; ; p++) {
        if (*p == ':' || *p == '\0') {
            if (p > start) {
                v.emplace_back(start, p);
            }
            if (*p == '\0') {
                break;
            }
            start = p + 1;
        }
    }
    return v;
}

/* 
 * Static library detection via symbol analysis
 *
 * Two evidence levels:
 *
 *   "symbol-defined"  (HIGH confidence)
 *      A symbol matching the pattern has st_shndx != SHN_UNDEF, meaning the
 *      function body is PRESENT in this binary -> clear sign of static linking.
 *
 *   "symbol-ref"  (MEDIUM confidence)
 *      The symbol appears in the dynamic symbol table as SHN_UNDEF (an unresolved external reference). 
 *      Combined with the absence of a matching DT_NEEDED entry it suggests static linking, but could also
 *      be a lazy binding that gets resolved elsewhere.
 */

struct LibHint {
    const char* _prefix;
    const char* _name;
};

static const LibHint HINTS[] = {
    /* ── OpenSSL / LibreSSL ── */
    {"EVP_",          "openssl"},   {"SSL_",         "openssl"},
    {"TLS_",          "openssl"},   {"BIO_",         "openssl"},
    {"RSA_",          "openssl"},   {"DSA_",         "openssl"},
    {"DH_",           "openssl"},   {"EC_",          "openssl"},
    {"ECDH_",         "openssl"},   {"ECDSA_",       "openssl"},
    {"AES_",          "openssl"},   {"SHA_",         "openssl"},
    {"SHA1_",         "openssl"},   {"SHA256_",      "openssl"},
    {"SHA512_",       "openssl"},   {"MD5_",         "openssl"},
    {"HMAC_",         "openssl"},   {"X509_",        "openssl"},
    {"ASN1_",         "openssl"},   {"BN_",          "openssl"},
    {"CMS_",          "openssl"},   {"OCSP_",        "openssl"},
    {"PEM_",          "openssl"},   {"PKCS7_",       "openssl"},
    {"PKCS12_",       "openssl"},   {"OPENSSL_",     "openssl"},
    {"CRYPTO_",       "openssl"},   {"ERR_get_",     "openssl"},
    /* ── WolfSSL / wolfCrypt ── */
    {"wolfSSL_",      "wolfssl"},   {"wc_",          "wolfssl"},
    {"wolfCrypt",     "wolfssl"},
    /* ── mbedTLS ── */
    {"mbedtls_",      "mbedtls"},
    /* ── GnuTLS ── */
    {"gnutls_",       "gnutls"},
    /* ── libgcrypt ── */
    {"gcry_",         "libgcrypt"},
    /* ── libsodium ── */
    {"crypto_box",    "libsodium"}, {"crypto_sign",  "libsodium"},
    {"crypto_hash",   "libsodium"}, {"randombytes_", "libsodium"},
    {"sodium_",       "libsodium"},
    /* ── Compression ── */
    {"deflate",       "zlib"},      {"inflate",      "zlib"},
    {"compress2",     "zlib"},      {"uncompress",   "zlib"},
    {"crc32",         "zlib"},      {"adler32",      "zlib"},
    {"gzopen",        "zlib"},      {"gzwrite",      "zlib"},
    {"ZSTD_",         "zstd"},      {"LZ4_",         "lz4"},
    {"LZ4F_",         "lz4"},       {"lzma_",        "liblzma"},
    {"BZ2_",          "bzip2"},     {"BrotliDecoder", "brotli"},
    {"BrotliEncoder", "brotli"},
    /* ── Networking ── */
    {"curl_",         "libcurl"},   {"Curl_",        "libcurl"},
    {"nghttp2_",      "nghttp2"},   {"ssh2_",        "libssh2"},
    {"ssh_",          "libssh"},
    /* ── Databases ── */
    {"sqlite3_",      "sqlite3"},   {"PQconnect",    "libpq"},
    {"PQexec",        "libpq"},     {"mysql_",       "libmysqlclient"},
    {"mongoc_",       "libmongoc"},
    /* ── XML / Parsing ── */
    {"xmlParse",      "libxml2"},   {"xmlDoc",       "libxml2"},
    {"xmlXPath",      "libxml2"},   {"xmlSAX",       "libxml2"},
    {"XML_Parse",     "expat"},     {"XML_Create",   "expat"},
    {"xslt",          "libxslt"},
    /* ── JSON ── */
    {"json_object",   "json-c"},    {"json_tokener", "json-c"},
    {"cJSON_",        "cjson"},     {"yyjson_",      "yyjson"},
    {"rapidjson",     "rapidjson"}, {"yaml_",        "libyaml"},
    /* ── Images ── */
    {"png_",          "libpng"},    {"jpeg_",        "libjpeg"},
    {"TIFF",          "libtiff"},   {"webp_",        "libwebp"},
    /* ── Regex ── */
    {"pcre_",         "libpcre"},   {"pcre2_",       "libpcre2"},
    /* ── Event loops ── */
    {"uv_",           "libuv"},     {"event_",       "libevent"},
    {"ev_",           "libev"},
    /* ── Serialization ── */
    {"pb_init",       "nanopb"},    {"pb_encode",    "nanopb"},
    {"pb_decode",     "nanopb"},
    {"flatbuffers",   "flatbuffers"},
    /* ── Logging ── */
    {"spdlog",        "spdlog"},
    /* ── UUID ── */
    {"uuid_generate", "libuuid"},
    /* ── Capabilities / ACLs ── */
    {"cap_get_",      "libcap"},    {"acl_get_",     "libacl"},
    /* ── APR ── */
    {"apr_",          "apr"},
    /* ── C++ stdlib detection ── */
    {"boost::",       "boost"},     {"absl::",       "abseil"},
    {"Eigen::",       "eigen"},
    /* ── Misc ── */
    {"readline_",     "readline"},  {"lua_",         "lua"},
    {"lauxlib_",      "lua"},
    {nullptr, nullptr}
};

/*
 * Match symbols from two sets against the HINTS table and populate
 * comp._static_libs with the findings, avoiding duplication with
 * already-known dynamic dependencies.
 *
 * defined_syms : symbols with st_shndx != SHN_UNDEF  → strong evidence
 * undef_syms   : symbols with SHN_UNDEF (no matching DT_NEEDED) → medium
 */
static void detect_from_symbols(const std::set<std::string>& defined_syms_,
                                  const std::set<std::string>& undef_syms_,
                                  const std::vector<std::string>& dyn_needed_,
                                  std::vector<StaticLibInfo>& out_) {
    /* lib_name → method : prefer "symbol-defined" over "symbol-ref" */
    std::map<std::string, std::string> found;

    /* Pass 1 – defined symbols (high confidence) */
    for (const auto& sym : defined_syms_) {
        for (const LibHint* h = HINTS; h->_prefix; h++) {
            if (sym.compare(0, strlen(h->_prefix), h->_prefix) == 0) {
                found.emplace(h->_name, "symbol-defined");  /* emplace = keep first */
            }
        }
    }

    /* Pass 2 – imported symbols (only when no DT_NEEDED match) */
    for (const auto& sym : undef_syms_) {
        for (const LibHint* h = HINTS; h->_prefix; h++) {
            if (sym.compare(0, strlen(h->_prefix), h->_prefix) != 0) {
                continue;
            }

            /* If the lib already shows up in DT_NEEDED, this is a normal
             * dynamic reference — not evidence of static linking. */
            bool in_needed = false;
            for (const auto& d : dyn_needed_) {
                if (d.find(h->_name) != std::string::npos) {
                    in_needed = true;
                    break;
                }
            }
            if (!in_needed) {
                found.emplace(h->_name, "symbol-ref");
            }
        }
    }

    /* Emit: skip libs already covered by a dynamic dependency */
    for (const auto& [lib, method] : found) {
        bool dyn = false;
        for (const auto& d : dyn_needed_) {
            if (d.find(lib) != std::string::npos) {
                dyn = true;
                break;
            }
        }
        if (dyn) {
            continue;
        }

        bool dup = false;
        for (const auto& e : out_) {
            if (e._name == lib) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            out_.push_back({lib, "", method, ""});
        }
    }
}

static void read_dwarf_sources(const std::string& path_,
                                std::vector<std::string>& sources_) {
    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return;
    }
    Dwarf* dw = dwarf_begin(fd, DWARF_C_READ);
    if (!dw) {
        close(fd);
        return;
    }

    Dwarf_Off off = 0;
    Dwarf_Off next_off;
    size_t hdr_sz;
    while (dwarf_nextcu(dw, off, &next_off, &hdr_sz,
                         nullptr, nullptr, nullptr) == 0) {
        Dwarf_Die die;
        if (!dwarf_offdie(dw, off + hdr_sz, &die)) {
            off = next_off;
            continue;
        }
        Dwarf_Attribute attr;
        const char* name     = nullptr;
        const char* comp_dir = nullptr;
        if (dwarf_attr(&die, DW_AT_name,     &attr)) {
            name     = dwarf_formstring(&attr);
        }
        if (dwarf_attr(&die, DW_AT_comp_dir, &attr)) {
            comp_dir = dwarf_formstring(&attr);
        }
        if (name) {
            std::string src = (name[0] != '/' && comp_dir)
                              ? (std::string(comp_dir) + "/" + name)
                              : name;
            sources_.push_back(std::move(src));
        }
        off = next_off;
    }
    dwarf_end(dw);
    close(fd);
}

bool parse_elf_file(const std::string& path_, Component& comp_) {
    comp_._path = path_;

    struct stat st;
    if (stat(path_.c_str(), &st) == 0) {
        comp_._size = (uint64_t)st.st_size;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        return false;
    }

    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return false;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return false;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        elf_end(elf);
        close(fd);
        return false;
    }

    comp_._arch     = arch_name(ehdr.e_machine);
    comp_._abi_name = abi_name(ehdr.e_ident[EI_OSABI]);

    switch (ehdr.e_type) {
        case ET_EXEC:
            comp_._type   = ElfType::Executable;
            comp_._is_pie = false;
            break;
        case ET_DYN:
            comp_._type   = ElfType::SharedLibrary;
            comp_._is_pie = true;
            break;
        default:
            comp_._type = ElfType::Unknown;
    }

    size_t shstrndx = 0;
    elf_getshdrstrndx(elf, &shstrndx);

    bool has_symtab    = false;
    bool has_debug_sec = false;

    /*
     * defined_syms : non-UNDEF global/weak symbols found in .symtab
     *                → strong evidence of static code if they match HINTS
     * undef_syms   : SHN_UNDEF symbols in .dynsym (external references)
     *                → only used as evidence when NOT in DT_NEEDED
     */
    std::set<std::string> defined_syms;
    std::set<std::string> undef_syms;

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }
        const char* sname = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (!sname) {
            continue;
        }

        /* .dynamic */
        if (shdr.sh_type == SHT_DYNAMIC) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }
            size_t n = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < n; i++) {
                GElf_Dyn dyn;
                gelf_getdyn(data, i, &dyn);
                if (dyn.d_tag == DT_NULL) {
                    break;
                }
                const char* s = nullptr;
                switch (dyn.d_tag) {
                    case DT_NEEDED:
                        s = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                        if (s) {
                            comp_._needed.push_back(s);
                        }
                        break;
                    case DT_SONAME:
                        s = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                        if (s) {
                            comp_._soname = s;
                            comp_._type   = ElfType::SharedLibrary;
                        }
                        break;
                    case DT_RPATH:
                        s = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                        if (s) {
                            comp_._rpath = split_colon(s);
                        }
                        break;
                    case DT_RUNPATH:
                        s = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                        if (s) {
                            comp_._runpath = split_colon(s);
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        /* Notes – GNU Build ID */
        else if (shdr.sh_type == SHT_NOTE) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }
            size_t    off = 0;
            GElf_Nhdr nhdr;
            size_t    noff;
            size_t    doff;
            while ((off = gelf_getnote(data, off, &nhdr, &noff, &doff)) > 0) {
                const char* nn = (const char*)data->d_buf + noff;
                if (nhdr.n_namesz >= 4 && memcmp(nn, "GNU\0", 4) == 0
                    && nhdr.n_type == 3 && comp_._build_id.empty()) {
                    comp_._build_id = bytes_to_hex(
                        (const unsigned char*)data->d_buf + doff,
                        nhdr.n_descsz);
                }
            }
        }

        /*
         * Symbol tables.
         *
         * .symtab  — full symbol table (may be absent if stripped).
         *            We collect DEFINED globals/weaks → defined_syms.
         *
         * .dynsym  — exported/imported dynamic symbols.
         *            SHN_UNDEF entries are imports → undef_syms.
         *            Defined entries also go to defined_syms (handles PIE).
         */
        else if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            if (shdr.sh_type == SHT_SYMTAB) {
                has_symtab = true;
            }

            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }
            size_t n = shdr.sh_size / shdr.sh_entsize;

            for (size_t i = 1; i < n; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                if (sym.st_name == 0) {
                    continue;
                }
                if (GELF_ST_BIND(sym.st_info) == STB_LOCAL) {
                    continue;
                }
                const char* sn = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!sn || !*sn || strlen(sn) <= 3) {
                    continue;
                }

                if (sym.st_shndx == SHN_UNDEF) {
                    undef_syms.insert(sn);     /* imported */
                } else {
                    defined_syms.insert(sn);   /* locally defined */
                }
            }
        }

        /* ._comment */
        else if (strcmp(sname, "._comment") == 0) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data || !data->d_buf) {
                continue;
            }
            const char* buf = (const char*)data->d_buf;
            bool first = true;
            for (size_t pos = 0; pos < data->d_size; ) {
                const char* s = buf + pos;
                size_t l = strnlen(s, data->d_size - pos);
                if (l > 0) {
                    if (!first) {
                        comp_._comment += " | ";
                    }
                    comp_._comment += s;
                    first = false;
                }
                pos += l + 1;
            }
        }

        else if (strcmp(sname, ".debug_info") == 0) {
            has_debug_sec = true;
        }
    }

    comp_._stripped  = !has_symtab;
    comp_._has_debug = has_debug_sec;

    if (ehdr.e_type == ET_DYN && comp_._soname.empty()
        && ehdr.e_entry != 0 && !comp_._needed.empty()) {
        comp_._type   = ElfType::Executable;
        comp_._is_pie = true;
    }

    comp_._name = comp_._soname.empty() ? path_.substr(path_.rfind('/') + 1): comp_._soname;

    elf_end(elf);
    close(fd);

    /* Pass 1 – DWARF CU sources */
    if (has_debug_sec) {
        read_dwarf_sources(path_, comp_._cu_sources);
    }

    /* Pass 2 – symbol-based static lib detection (defined then referenced) */
    detect_from_symbols(defined_syms, undef_syms, comp_._needed, comp_._static_libs);

    /* Pass 3 – .rodata version strings + DWARF build paths */
    scan_version_strings(path_, comp_._cu_sources, comp_._static_libs);

    /* Pass 4 – byte-pattern and symbol-cluster signatures (binwalk/DIE style) */
    scan_signatures(path_, comp_._static_libs);

    return true;
}
