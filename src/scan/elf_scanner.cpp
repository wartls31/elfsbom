#include <scan/elf_scanner.hpp>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

/* ── ELF magic detection ─────────────────────────────────────────────────── */

bool is_elf_file(const std::string& path_) {
    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return false;
    }
    unsigned char magic[4] = {0};
    ssize_t n = read(fd, magic, 4);
    close(fd);
    return n == 4 && magic[0] == 0x7f
                  && magic[1] == 'E'
                  && magic[2] == 'L'
                  && magic[3] == 'F';
}

/* ── ELF type reader ─────────────────────────────────────────────────────── */
/*
 * Read e_type from the ELF header without fully parsing it.
 * Only reads the first 18 bytes (EI_NIDENT=16 + e_type=2).
 *
 * ELF types:
 *   ET_NONE = 0   unknown
 *   ET_REL  = 1   relocatable object file (.o)   ← skip when --no-obj
 *   ET_EXEC = 2   position-dependent executable
 *   ET_DYN  = 3   shared library / PIE executable
 *   ET_CORE = 4   core dump
 *
 * Returns 0 on error.
 */
static uint16_t read_elf_type(const std::string& path_) {
    int fd = open(path_.c_str(), O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    unsigned char buf[18];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n < 18) {
        return 0;
    }
    if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        return 0;
    }

    /* e_type is at offset 16, 2 bytes.
     * EI_DATA (offset 5): 1 = little-endian, 2 = big-endian. */
    if (buf[5] == 2 /* ELFDATA2MSB */) {
        return (uint16_t)((buf[16] << 8) | buf[17]);
    } else { /* ELFDATA2LSB (default) */
        return (uint16_t)(buf[16] | (buf[17] << 8));
    }
}

/* ── Recursive walker ────────────────────────────────────────────────────── */

using InodeSet = std::set<std::pair<dev_t, ino_t>>;

static void walk(const std::string& dir_,
                  bool skip_objects_,
                  std::vector<std::string>& results_,
                  InodeSet& seen_) {
    DIR* dp = opendir(dir_.c_str());
    if (!dp) {
        return;
    }

    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }

        std::string full = dir_ + "/" + de->d_name;

        struct stat st;
        if (stat(full.c_str(), &st) != 0) {
            continue;
        }

        auto inode = std::make_pair(st.st_dev, st.st_ino);
        if (!seen_.insert(inode).second) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk(full, skip_objects_, results_, seen_);
        } else if (S_ISREG(st.st_mode) && st.st_size >= 64) {
            /* Quick ELF magic check */
            if (!is_elf_file(full)) {
                continue;
            }

            /* Optional: skip relocatable object files (ET_REL = 1) */
            if (skip_objects_ && read_elf_type(full) == 1 /* ET_REL */) {
                continue;
            }

            char resolved[PATH_MAX];
            if (realpath(full.c_str(), resolved)) {
                results_.emplace_back(resolved);
            } else {
                results_.push_back(full);
            }
        }
    }
    closedir(dp);
}

/* ── Public interface ────────────────────────────────────────────────────── */

std::vector<std::string> scan_elf_files(const std::string& dir_,
                                         bool skip_objects_) {
    std::vector<std::string> results;
    InodeSet seen;

    struct stat st;
    if (stat(dir_.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "[warn] not a directory: %s\n", dir_.c_str());
        return results;
    }

    walk(dir_, skip_objects_, results, seen);
    std::sort(results.begin(), results.end());
    return results;
}
