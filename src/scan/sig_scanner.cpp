#include <scan/sig_scanner.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

/* ── Merge helper ────────────────────────────────────────────────────────── */

static void merge(std::vector<StaticLibInfo>& found_,
                  const std::string&          name_,
                  const std::string&          version_,
                  const std::string&          method_) {
    for (auto& e : found_) {
        if (e._name == name_) {
            if (e._version.empty() && !version_.empty()) {
                e._version = version_;
                e._method  = method_;
            }
            return;
        }
    }
    found_.push_back({name_, version_, method_, ""});
}

/* ════════════════════════════════════════════════════════════════════════════
 * 1. Symbol collection
 *
 * Read SHT_SYMTAB and SHT_DYNSYM once; all detection strategies share the
 * resulting vector to avoid iterating the ELF symbol tables multiple times.
 *
 * Note on stripped binaries: SHT_SYMTAB is removed by strip(1), but
 * SHT_DYNSYM survives in shared libraries and PIE executables.  A fully
 * static binary stripped to the bare minimum will have neither table,
 * leaving byte-pattern scanning as the only applicable strategy.
 * ════════════════════════════════════════════════════════════════════════════ */

static void collect_symbols(Elf*                      elf_,
                             std::vector<std::string>& names_) {
    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf_, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == nullptr) {
            continue;
        }
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM) {
            continue;
        }
        if (shdr.sh_entsize == 0) {
            continue;
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (data == nullptr) {
            continue;
        }

        size_t n = shdr.sh_size / shdr.sh_entsize;
        names_.reserve(names_.size() + n);

        for (size_t i = 1; i < n; i++) {
            GElf_Sym sym;
            if (gelf_getsym(data, (int)i, &sym) == nullptr) {
                continue;
            }
            const char* name = elf_strptr(elf_, shdr.sh_link, sym.st_name);
            if (name != nullptr && *name != '\0') {
                names_.emplace_back(name);
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * 2. Byte-pattern database  (binwalk-style)
 *
 * Known magic byte sequences are searched in ELF data sections
 * (.rodata, .data, .data.rel.ro, .data1).  False-positive rate is kept low
 * by restricting the scan to data-bearing, non-executable sections and by
 * preferring patterns of 4+ bytes.  Two-byte zlib headers are deliberately
 * kept because they carry unusually distinctive low-byte distributions
 * (only four valid (CMF, FLG) pairs satisfy the RFC 1950 checksum).
 * ════════════════════════════════════════════════════════════════════════════ */

struct ByteSig {
    const char*    lib;
    const uint8_t* pattern;
    size_t         len;
};

/* zlib RFC-1950 CMF+FLG pairs */
static const uint8_t PAT_ZLIB_LOW[]  = { 0x78, 0x01 };
static const uint8_t PAT_ZLIB_DEF[]  = { 0x78, 0x9C };
static const uint8_t PAT_ZLIB_BEST[] = { 0x78, 0xDA };
static const uint8_t PAT_ZLIB_FAST[] = { 0x78, 0x5E };

/* LZ4 frame magic  (LE 0x184D2204) */
static const uint8_t PAT_LZ4_FRAME[]  = { 0x04, 0x22, 0x4D, 0x18 };
/* LZ4 legacy frame magic */
static const uint8_t PAT_LZ4_LEGACY[] = { 0x02, 0x21, 0x4C, 0x18 };
/* LZ4 skippable frames */
static const uint8_t PAT_LZ4_SKIP[]   = { 0x50, 0x2A, 0x4D, 0x18 };

/* Zstandard frame magic  (LE 0xFD2FB528) */
static const uint8_t PAT_ZSTD[] = { 0x28, 0xB5, 0x2F, 0xFD };

/* XZ stream header */
static const uint8_t PAT_XZ[]  = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };

/* bzip2 stream: "BZh" */
static const uint8_t PAT_BZ2[] = { 0x42, 0x5A, 0x68 };

/* LZMA alone properties byte 0x5D is common enough to skip; rely on XZ above */

/* Snappy framing format */
static const uint8_t PAT_SNAPPY[] = { 0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59 };

/* SQLite3 database header: "SQLite format 3\0" */
static const uint8_t PAT_SQLITE[] = {
    0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20,
    0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20,
    0x33, 0x00
};

/* PNG image signature */
static const uint8_t PAT_PNG[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

/* JPEG SOI marker: FF D8 FF */
static const uint8_t PAT_JPEG[] = { 0xFF, 0xD8, 0xFF };

/* GIF87a / GIF89a */
static const uint8_t PAT_GIF87[] = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
static const uint8_t PAT_GIF89[] = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };

/* TIFF: little-endian "II\x2A\x00" or big-endian "MM\x00\x2A" */
static const uint8_t PAT_TIFF_LE[] = { 0x49, 0x49, 0x2A, 0x00 };
static const uint8_t PAT_TIFF_BE[] = { 0x4D, 0x4D, 0x00, 0x2A };

/* WebP chunk ID inside a RIFF container */
static const uint8_t PAT_WEBP[] = { 0x57, 0x45, 0x42, 0x50 };

/* FLAC stream marker */
static const uint8_t PAT_FLAC[] = { 0x66, 0x4C, 0x61, 0x43 };

/* Ogg bitstream capture pattern */
static const uint8_t PAT_OGG[] = { 0x4F, 0x67, 0x67, 0x53 };

/* FreeType / OpenType font: 'OTTO' */
static const uint8_t PAT_OTF[] = { 0x4F, 0x54, 0x54, 0x4F };
/* TrueType sfnt v1.0 */
static const uint8_t PAT_TTF[] = { 0x00, 0x01, 0x00, 0x00, 0x00 };

/* Lua 5.x bytecode: "\x1bLua" */
static const uint8_t PAT_LUA[] = { 0x1B, 0x4C, 0x75, 0x61 };

/* WebAssembly module: "\0asm" */
static const uint8_t PAT_WASM[] = { 0x00, 0x61, 0x73, 0x6D };

/* Apache Arrow IPC file: "ARROW1" */
static const uint8_t PAT_ARROW[] = { 0x41, 0x52, 0x52, 0x4F, 0x57, 0x31 };

/* Apache Avro object container: "Obj\x01" */
static const uint8_t PAT_AVRO[] = { 0x4F, 0x62, 0x6A, 0x01 };

/* Apache Parquet file: "PAR1" */
static const uint8_t PAT_PARQUET[] = { 0x50, 0x41, 0x52, 0x31 };

/* HDF5 file signature */
static const uint8_t PAT_HDF5[] = {
    0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A
};

/* Cap'n Proto stream framing: 4-byte segment count header (value 0 = 1 seg) */
/* Too generic alone; rely on symbol detection for capnproto */

static const ByteSig BYTE_SIGS[] = {
    /* compression */
    { "zlib",      PAT_ZLIB_DEF,    2  },
    { "zlib",      PAT_ZLIB_BEST,   2  },
    { "zlib",      PAT_ZLIB_LOW,    2  },
    { "zlib",      PAT_ZLIB_FAST,   2  },
    { "lz4",       PAT_LZ4_FRAME,   4  },
    { "lz4",       PAT_LZ4_LEGACY,  4  },
    { "lz4",       PAT_LZ4_SKIP,    4  },
    { "zstd",      PAT_ZSTD,        4  },
    { "xz",        PAT_XZ,          6  },
    { "bzip2",     PAT_BZ2,         3  },
    { "snappy",    PAT_SNAPPY,     10  },
    /* databases */
    { "sqlite3",   PAT_SQLITE,     16  },
    /* image codecs */
    { "libpng",    PAT_PNG,         8  },
    { "libjpeg",   PAT_JPEG,        3  },
    { "giflib",    PAT_GIF87,       6  },
    { "giflib",    PAT_GIF89,       6  },
    { "libtiff",   PAT_TIFF_LE,     4  },
    { "libtiff",   PAT_TIFF_BE,     4  },
    { "libwebp",   PAT_WEBP,        4  },
    /* audio */
    { "libflac",   PAT_FLAC,        4  },
    { "libvorbis", PAT_OGG,         4  },
    /* fonts */
    { "freetype",  PAT_OTF,         4  },
    { "freetype",  PAT_TTF,         5  },
    /* scripting / bytecode */
    { "lua",       PAT_LUA,         4  },
    { "wasm",      PAT_WASM,        4  },
    /* data interchange */
    { "arrow",     PAT_ARROW,       6  },
    { "avro",      PAT_AVRO,        4  },
    { "parquet",   PAT_PARQUET,     4  },
    { "hdf5",      PAT_HDF5,        8  },
    { nullptr,     nullptr,          0  }
};

/*
 * Scan ELF data sections (.rodata, .data, .data.rel.ro, .data1) for the
 * patterns above.  Restricting to non-executable data sections reduces
 * false positives compared to scanning the whole binary file.
 */
static void scan_byte_sigs(Elf*                   elf_,
                            std::set<std::string>& found_) {
    size_t shstrndx = 0;
    elf_getshdrstrndx(elf_, &shstrndx);

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf_, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == nullptr) {
            continue;
        }
        if (shdr.sh_type != SHT_PROGBITS) {
            continue;
        }
        if (shdr.sh_flags & SHF_EXECINSTR) {
            continue;
        }
        if (!(shdr.sh_flags & SHF_ALLOC)) {
            continue;
        }

        const char* sname = elf_strptr(elf_, shstrndx, shdr.sh_name);
        if (sname != nullptr) {
            if (strcmp(sname, ".rodata")      != 0 &&
                strcmp(sname, ".data")        != 0 &&
                strcmp(sname, ".data.rel.ro") != 0 &&
                strcmp(sname, ".data1")       != 0) {
                continue;
            }
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (data == nullptr || data->d_buf == nullptr || data->d_size == 0) {
            continue;
        }

        const uint8_t* buf  = (const uint8_t*)data->d_buf;
        size_t         size = data->d_size;

        for (const ByteSig* sig = BYTE_SIGS; sig->lib; sig++) {
            if (size < sig->len || found_.count(sig->lib)) {
                continue;
            }
            const uint8_t* end = buf + size - sig->len + 1;
            for (const uint8_t* p = buf; p < end; p++) {
                if (memcmp(p, sig->pattern, sig->len) == 0) {
                    found_.insert(sig->lib);
                    break;
                }
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * 3. Symbol-cluster fingerprinting  (Detect-It-Easy / FLIRT-style)
 *
 * C libraries and older C++ libraries without distinctive namespace prefixes
 * are identified by counting characteristic function name occurrences.
 * ════════════════════════════════════════════════════════════════════════════ */

struct SymCluster {
    const char*        lib;
    int                threshold;
    const char* const* syms;
};

static const char* SYMS_OPENSSL[] = {
    "SSL_CTX_new", "SSL_new", "SSL_connect", "SSL_read", "SSL_write",
    "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_DigestInit_ex",
    "BN_new", "BN_free", "RSA_new", "EC_KEY_new",
    "CRYPTO_malloc", "CRYPTO_free", "ERR_get_error",
    "X509_new", "X509_free", "d2i_X509", "i2d_X509",
    "OPENSSL_init_ssl", "SSL_library_init",
    nullptr
};

static const char* SYMS_LIBRESSL[] = {
    "LIBRESSL_VERSION_NUMBER",
    nullptr
};

static const char* SYMS_CURL[] = {
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
    "curl_easy_cleanup", "curl_easy_getinfo",
    "curl_multi_init", "curl_multi_add_handle",
    "curl_global_init", "curl_global_cleanup",
    nullptr
};

static const char* SYMS_ZLIB[] = {
    "deflate", "inflate", "deflateInit_", "inflateInit_",
    "deflateEnd", "inflateEnd", "compress", "uncompress",
    "gzopen", "gzread", "gzwrite", "gzclose",
    nullptr
};

static const char* SYMS_ZSTD[] = {
    "ZSTD_compress", "ZSTD_decompress",
    "ZSTD_createCCtx", "ZSTD_createDCtx",
    "ZSTD_CCtx_setParameter", "ZSTD_compressStream",
    nullptr
};

static const char* SYMS_LZ4[] = {
    "LZ4_compress_default", "LZ4_decompress_safe",
    "LZ4_compress_fast", "LZ4_createStream",
    nullptr
};

static const char* SYMS_BROTLI[] = {
    "BrotliEncoderCreateInstance", "BrotliDecoderCreateInstance",
    "BrotliEncoderCompress", "BrotliDecoderDecompress",
    nullptr
};

static const char* SYMS_SNAPPY[] = {
    "snappy_compress", "snappy_uncompress",
    "snappy_max_compressed_length", "snappy_uncompressed_length",
    nullptr
};

static const char* SYMS_NGHTTP2[] = {
    "nghttp2_session_client_new", "nghttp2_session_send",
    "nghttp2_session_mem_recv", "nghttp2_submit_request",
    nullptr
};

static const char* SYMS_LIBSSH2[] = {
    "libssh2_session_init_ex", "libssh2_session_handshake",
    "libssh2_channel_open_ex", "libssh2_channel_read_ex",
    nullptr
};

static const char* SYMS_GNUTLS[] = {
    "gnutls_init", "gnutls_handshake", "gnutls_record_send",
    "gnutls_certificate_allocate_credentials", "gnutls_deinit",
    nullptr
};

static const char* SYMS_MBEDTLS[] = {
    "mbedtls_ssl_init", "mbedtls_ssl_handshake",
    "mbedtls_aes_init", "mbedtls_sha256_init",
    "mbedtls_entropy_init", "mbedtls_ctr_drbg_init",
    nullptr
};

static const char* SYMS_WOLFSSL[] = {
    "wolfSSL_Init", "wolfSSL_new", "wolfSSL_connect",
    "wolfSSL_CTX_new", "wolfSSL_CTX_free",
    nullptr
};

static const char* SYMS_LIBSODIUM[] = {
    "crypto_secretbox_easy", "crypto_secretbox_open_easy",
    "crypto_sign_ed25519", "crypto_box_curve25519xsalsa20poly1305",
    "sodium_init", "sodium_memzero", "randombytes_buf",
    nullptr
};

static const char* SYMS_NETTLE[] = {
    "nettle_sha256_init", "nettle_sha256_update",
    "nettle_aes128_set_encrypt_key", "nettle_aes128_encrypt",
    "nettle_rsa_sign_digest_tr",
    nullptr
};

static const char* SYMS_GCRYPT[] = {
    "gcry_cipher_open", "gcry_cipher_close",
    "gcry_md_open", "gcry_md_close",
    "gcry_pk_encrypt", "gcry_pk_decrypt",
    "gcry_control",
    nullptr
};

static const char* SYMS_LIBPNG[] = {
    "png_create_read_struct", "png_create_write_struct",
    "png_read_info", "png_write_info",
    "png_read_image", "png_write_image",
    nullptr
};

static const char* SYMS_LIBJPEG[] = {
    "jpeg_CreateCompress", "jpeg_CreateDecompress",
    "jpeg_start_compress", "jpeg_start_decompress",
    "jpeg_read_scanlines", "jpeg_write_scanlines",
    "jpeg_finish_compress", "jpeg_finish_decompress",
    nullptr
};

static const char* SYMS_LIBTIFF[] = {
    "TIFFOpen", "TIFFClose", "TIFFReadScanline",
    "TIFFWriteScanline", "TIFFGetField", "TIFFSetField",
    nullptr
};

static const char* SYMS_SQLITE[] = {
    "sqlite3_open", "sqlite3_close", "sqlite3_exec",
    "sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize",
    "sqlite3_bind_text", "sqlite3_column_text",
    nullptr
};

static const char* SYMS_LMDB[] = {
    "mdb_env_create", "mdb_env_open", "mdb_env_close",
    "mdb_txn_begin", "mdb_txn_commit", "mdb_txn_abort",
    "mdb_dbi_open", "mdb_put", "mdb_get",
    nullptr
};

static const char* SYMS_EXPAT[] = {
    "XML_ParserCreate", "XML_Parse", "XML_ParserFree",
    "XML_SetElementHandler", "XML_SetCharacterDataHandler",
    nullptr
};

static const char* SYMS_LIBXML2[] = {
    "xmlParseFile", "xmlParseMemory", "xmlFreeDoc",
    "xmlDocGetRootElement", "xmlNodeGetContent",
    "xmlXPathNewContext", "xmlXPathEvalExpression",
    nullptr
};

static const char* SYMS_PCRE2[] = {
    "pcre2_compile_8", "pcre2_match_8", "pcre2_code_free_8",
    "pcre2_match_data_create_from_pattern_8",
    nullptr
};

static const char* SYMS_PCRE[] = {
    "pcre_compile", "pcre_exec", "pcre_free",
    "pcre_study", "pcre_fullinfo",
    nullptr
};

static const char* SYMS_LIBUV[] = {
    "uv_run", "uv_loop_init", "uv_loop_close",
    "uv_tcp_init", "uv_listen", "uv_read_start",
    "uv_fs_open", "uv_timer_init",
    nullptr
};

static const char* SYMS_LUA[] = {
    "lua_newstate", "lua_close", "lua_pcall",
    "luaL_newstate", "luaL_loadbuffer", "lua_pushstring",
    nullptr
};

static const char* SYMS_GMP[] = {
    "__gmpz_init", "__gmpz_clear", "__gmpz_add",
    "__gmpz_mul", "__gmpz_powm", "__gmpz_set_str",
    nullptr
};

static const char* SYMS_LIBEVENT[] = {
    "event_base_new", "event_base_dispatch",
    "event_new", "event_add", "event_free",
    "evhttp_new", "evconnlistener_new_bind",
    nullptr
};

static const char* SYMS_LIBEV[] = {
    "ev_default_loop", "ev_loop", "ev_io_init",
    "ev_timer_init", "ev_run",
    nullptr
};

static const char* SYMS_LIBARCHIVE[] = {
    "archive_read_new", "archive_write_new",
    "archive_read_open_filename", "archive_read_next_header",
    "archive_entry_pathname", "archive_read_free",
    nullptr
};

static const char* SYMS_JSONC[] = {
    "json_object_new_object", "json_object_put",
    "json_tokener_parse", "json_object_to_json_string",
    nullptr
};

static const char* SYMS_CJSON[] = {
    "cJSON_Parse", "cJSON_Print", "cJSON_Delete",
    "cJSON_CreateObject", "cJSON_AddItemToObject",
    nullptr
};

static const char* SYMS_CARES[] = {
    "ares_init", "ares_destroy", "ares_gethostbyname",
    "ares_query", "ares_process_fd",
    nullptr
};

static const char* SYMS_JEMALLOC[] = {
    "je_malloc", "je_free", "je_realloc",
    "je_calloc", "je_posix_memalign",
    nullptr
};

static const char* SYMS_TCMALLOC[] = {
    "tc_malloc", "tc_free", "tc_realloc",
    "tc_calloc", "MallocExtension_GetNumericProperty",
    nullptr
};

static const char* SYMS_MIMALLOC[] = {
    "mi_malloc", "mi_free", "mi_realloc",
    "mi_calloc", "mi_heap_new",
    nullptr
};

static const char* SYMS_FREETYPE[] = {
    "FT_Init_FreeType", "FT_Done_FreeType",
    "FT_New_Face", "FT_Done_Face",
    "FT_Load_Glyph", "FT_Render_Glyph",
    nullptr
};

static const char* SYMS_HARFBUZZ[] = {
    "hb_buffer_create", "hb_buffer_destroy",
    "hb_shape", "hb_font_create",
    nullptr
};

static const char* SYMS_CAIRO[] = {
    "cairo_create", "cairo_destroy",
    "cairo_surface_destroy", "cairo_image_surface_create",
    "cairo_fill", "cairo_stroke", "cairo_paint",
    "cairo_set_source_rgba",
    nullptr
};

static const char* SYMS_OPENH264[] = {
    "WelsCreateSVCEncoder", "WelsDestroyEncoder",
    "WelsCreateDecoder", "WelsDestroyDecoder",
    nullptr
};

static const char* SYMS_LIBVPX[] = {
    "vpx_codec_enc_init_ver", "vpx_codec_dec_init_ver",
    "vpx_codec_encode", "vpx_codec_decode",
    nullptr
};

static const char* SYMS_XXHASH[] = {
    "XXH32", "XXH64", "XXH3_64bits",
    "XXH32_reset", "XXH64_reset",
    nullptr
};

static const char* SYMS_LIBTOMCRYPT[] = {
    "register_cipher", "register_hash",
    "cbc_encrypt", "cbc_decrypt",
    "sha256_process", "rsa_sign_hash",
    nullptr
};

static const SymCluster SYM_CLUSTERS[] = {
    { "openssl",      3, SYMS_OPENSSL    },
    { "libressl",     1, SYMS_LIBRESSL   },
    { "libcurl",      3, SYMS_CURL       },
    { "zlib",         2, SYMS_ZLIB       },
    { "zstd",         2, SYMS_ZSTD       },
    { "lz4",          2, SYMS_LZ4        },
    { "brotli",       2, SYMS_BROTLI     },
    { "snappy",       2, SYMS_SNAPPY     },
    { "nghttp2",      2, SYMS_NGHTTP2    },
    { "libssh2",      2, SYMS_LIBSSH2    },
    { "gnutls",       3, SYMS_GNUTLS     },
    { "mbedtls",      3, SYMS_MBEDTLS    },
    { "wolfssl",      3, SYMS_WOLFSSL    },
    { "libsodium",    3, SYMS_LIBSODIUM  },
    { "nettle",       3, SYMS_NETTLE     },
    { "libgcrypt",    3, SYMS_GCRYPT     },
    { "libpng",       2, SYMS_LIBPNG     },
    { "libjpeg",      3, SYMS_LIBJPEG    },
    { "libtiff",      3, SYMS_LIBTIFF    },
    { "sqlite3",      3, SYMS_SQLITE     },
    { "lmdb",         3, SYMS_LMDB       },
    { "expat",        2, SYMS_EXPAT      },
    { "libxml2",      2, SYMS_LIBXML2    },
    { "pcre2",        2, SYMS_PCRE2      },
    { "pcre",         2, SYMS_PCRE       },
    { "libuv",        3, SYMS_LIBUV      },
    { "lua",          3, SYMS_LUA        },
    { "gmp",          3, SYMS_GMP        },
    { "libevent",     2, SYMS_LIBEVENT   },
    { "libev",        2, SYMS_LIBEV      },
    { "libarchive",   2, SYMS_LIBARCHIVE },
    { "json-c",       2, SYMS_JSONC      },
    { "cjson",        2, SYMS_CJSON      },
    { "c-ares",       3, SYMS_CARES      },
    { "jemalloc",     3, SYMS_JEMALLOC   },
    { "tcmalloc",     3, SYMS_TCMALLOC   },
    { "mimalloc",     3, SYMS_MIMALLOC   },
    { "freetype",     3, SYMS_FREETYPE   },
    { "harfbuzz",     2, SYMS_HARFBUZZ   },
    { "cairo",        3, SYMS_CAIRO      },
    { "openh264",     2, SYMS_OPENH264   },
    { "libvpx",       2, SYMS_LIBVPX     },
    { "xxhash",       2, SYMS_XXHASH     },
    { "libtomcrypt",  3, SYMS_LIBTOMCRYPT},
    { nullptr,        0, nullptr          }
};

static void scan_symbol_clusters(const std::vector<std::string>& names_,
                                  std::set<std::string>&          found_) {
    /* Build a set for O(1) membership tests */
    std::set<std::string> sym_set(names_.begin(), names_.end());

    for (const SymCluster* cl = SYM_CLUSTERS; cl->lib; cl++) {
        int hits = 0;
        for (const char* const* s = cl->syms; *s; s++) {
            if (sym_set.count(*s)) {
                hits++;
            }
        }
        if (hits >= cl->threshold) {
            found_.insert(cl->lib);
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * 4. C++ namespace prefix fingerprinting  (Itanium ABI, a la Detect-It-Easy)
 *
 * In the Itanium C++ ABI (used on all Linux/ELF targets), a symbol in
 * namespace foo::Bar is mangled as _ZN<len>foo<len>Bar...  The namespace
 * length-prefix is deterministic, so "_ZN4llvm" matches any symbol in the
 * LLVM namespace and constitutes strong evidence that LLVM is linked.
 *
 * This is the primary detection strategy for C++ libraries (LLVM, absl,
 * RocksDB, …) where individual function names are unstable across versions
 * but the namespace is constant.
 *
 * Caveat — recompiled static libraries:
 *   A statically linked library is typically a custom build that may differ
 *   from the system package in version, configuration, and patches.  Namespace
 *   prefix matches confirm presence with high confidence but carry NO reliable
 *   version information.  Do NOT infer the version from the host system's
 *   package manager for these detections; use the "pkg-inferred" method label
 *   (assigned in infer_versions_from_pkg) as a reminder of this uncertainty.
 * ════════════════════════════════════════════════════════════════════════════ */

struct NsSig {
    const char* lib;
    /* Itanium mangled prefix: "_ZN" + len(ns) + ns  (case-sensitive) */
    const char* prefix;
    int         threshold;
};

/*
 * Itanium mangling cheatsheet used to build this table:
 *   namespace foo        → _ZN3foo        (3 = strlen("foo"))
 *   namespace foo::bar   → _ZN3foo3bar    (3+3)
 *   class Foo            → _ZN3Foo        (same as namespace)
 *
 * A match on the prefix alone is sufficient: any symbol that starts with
 * "_ZN4llvm" must belong to the llvm:: namespace tree.
 */
static const NsSig NS_SIGS[] = {
    /* ── LLVM ecosystem ───────────────────────────────────────────────── */
    /* "llvm" = 4 chars */
    { "llvm",         "_ZN4llvm",             5 },
    /* "clang" = 5 chars */
    { "clang",        "_ZN5clang",            5 },
    /* "lld" = 3 chars */
    { "lld",          "_ZN3lld",              3 },
    /* "lldb_private" = 12 chars */
    { "lldb",         "_ZN12lldb_private",    3 },
    /* "mlir" = 4 chars */
    { "mlir",         "_ZN4mlir",             3 },

    /* ── Cryptography ─────────────────────────────────────────────────── */
    /* "Botan" = 5 chars (capital B) */
    { "botan",        "_ZN5Botan",            3 },

    /* ── Google / open-source C++ base libraries ──────────────────────── */
    /* "absl" = 4 chars (Abseil) */
    { "abseil",       "_ZN4absl",             5 },
    /* "folly" = 5 chars (Meta Folly) */
    { "folly",        "_ZN5folly",            5 },
    /* "re2" = 3 chars */
    { "re2",          "_ZN3re2",              2 },

    /* ── Serialization / data interchange ─────────────────────────────── */
    /* "google" + "protobuf" = 6+8 */
    { "protobuf",     "_ZN6google8protobuf",  3 },
    /* "flatbuffers" = 11 chars */
    { "flatbuffers",  "_ZN11flatbuffers",     2 },
    /* "capnp" = 5 chars (Cap'n Proto) */
    { "capnproto",    "_ZN5capnp",            2 },
    /* "rapidjson" = 9 chars */
    { "rapidjson",    "_ZN9rapidjson",        2 },
    /* "simdjson" = 8 chars */
    { "simdjson",     "_ZN8simdjson",         2 },
    /* "nlohmann" = 8 chars */
    { "nlohmann-json","_ZN8nlohmann",         2 },
    /* "cereal" = 6 chars */
    { "cereal",       "_ZN6cereal",           2 },
    /* "msgpack" = 7 chars */
    { "msgpack",      "_ZN7msgpack",          2 },

    /* ── Compression (C++ APIs) ───────────────────────────────────────── */
    /* "snappy" = 6 chars (has a C++ API too) */
    { "snappy",       "_ZN6snappy",           2 },

    /* ── Databases ────────────────────────────────────────────────────── */
    /* "rocksdb" = 7 chars */
    { "rocksdb",      "_ZN7rocksdb",          3 },
    /* "leveldb" = 7 chars */
    { "leveldb",      "_ZN7leveldb",          3 },

    /* ── Computer vision ─────────────────────────────────────────────── */
    /* "cv" = 2 chars (OpenCV) */
    { "opencv",       "_ZN2cv",               5 },

    /* ── Machine learning / inference ─────────────────────────────────── */
    /* "tflite" = 6 chars (TensorFlow Lite) */
    { "tflite",       "_ZN6tflite",           3 },
    /* "onnxruntime" = 11 chars */
    { "onnxruntime",  "_ZN11onnxruntime",     3 },
    /* "Ort" = 3 chars (ONNX Runtime C++ namespace) */
    { "onnxruntime",  "_ZN3Ort",              3 },
    /* "torch" = 5 chars (LibTorch / PyTorch C++) */
    { "libtorch",     "_ZN5torch",            5 },
    /* "at" = 2 chars (ATen, PyTorch tensor lib) */
    { "libtorch",     "_ZN2at",               5 },

    /* ── Networking / RPC ─────────────────────────────────────────────── */
    /* "grpc" = 4 chars */
    { "grpc",         "_ZN4grpc",             3 },
    /* "grpc_core" = 9 chars */
    { "grpc",         "_ZN9grpc_core",        3 },

    /* ── Data / analytics ─────────────────────────────────────────────── */
    /* "arrow" = 5 chars (Apache Arrow) */
    { "arrow",        "_ZN5arrow",            3 },

    /* ── Logging / formatting ─────────────────────────────────────────── */
    /* "spdlog" = 6 chars */
    { "spdlog",       "_ZN6spdlog",           2 },
    /* "fmt" = 3 chars (fmtlib) */
    { "fmtlib",       "_ZN3fmt",              3 },

    /* ── Test frameworks (survive in debug / test binaries) ────────────── */
    /* "testing" = 7 chars (Google Test) */
    { "googletest",   "_ZN7testing",          3 },
    /* "benchmark" = 9 chars (Google Benchmark) */
    { "googlebench",  "_ZN9benchmark",        2 },

    /* ── Boost (commonly statically linked sub-libraries) ──────────────── */
    /* "boost" = 5 chars */
    { "boost",        "_ZN5boost",            5 },

    /* ── Audio ────────────────────────────────────────────────────────── */
    /* "opus" = 4 chars */
    { "opus",         "_ZN4opus",             2 },

    { nullptr,        nullptr,                 0  }
};

static void scan_cxx_namespaces(const std::vector<std::string>& names_,
                                 std::set<std::string>&          found_) {
    for (const NsSig* ns = NS_SIGS; ns->lib; ns++) {
        if (found_.count(ns->lib)) {
            continue;  /* already detected by cluster or earlier ns entry */
        }
        size_t plen = strlen(ns->prefix);
        int hits = 0;
        for (const auto& nm : names_) {
            if (nm.size() >= plen &&
                nm.compare(0, plen, ns->prefix) == 0) {
                hits++;
                if (hits >= ns->threshold) {
                    found_.insert(ns->lib);
                    break;
                }
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public interface
 * ════════════════════════════════════════════════════════════════════════════ */

void scan_signatures(const std::string&         path_,
                     std::vector<StaticLibInfo>& found_) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return;
    }

    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (elf == nullptr) {
        close(fd);
        return;
    }

    /* Collect symbol names once; share across all detection strategies */
    std::vector<std::string> sym_names;
    collect_symbols(elf, sym_names);

    std::set<std::string> byte_hits;
    std::set<std::string> cluster_hits;

    scan_byte_sigs(elf, byte_hits);
    scan_symbol_clusters(sym_names, cluster_hits);
    scan_cxx_namespaces(sym_names, cluster_hits);

    elf_end(elf);
    close(fd);

    /* Byte-pattern results */
    for (const auto& lib : byte_hits) {
        merge(found_, lib, "", "byte-sig");
    }

    /*
     * Symbol-based results (clusters + C++ namespace prefixes).
     *
     * Important: these detections carry NO version information.  The version
     * may later be filled by infer_versions_from_pkg() using the host system's
     * package database, but for a statically linked library this is unreliable:
     * the linked version was typically built from source and may differ from
     * anything the package manager knows about.  The method will be changed to
     * "pkg-inferred" by that pass to make the uncertainty visible.
     */
    for (const auto& lib : cluster_hits) {
        merge(found_, lib, "", "symbol-cluster");
    }
}
