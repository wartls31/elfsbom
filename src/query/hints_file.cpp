#include <query/hints_file.hpp>

#include <cctype>
#include <cstdio>
#include <cstring>

static void rtrim(char* s_) {
    size_t n = strlen(s_);
    while ((n > 0) && ((unsigned char)s_[n-1] <= ' ')) {
        n--;
        s_[n] = '\0';
    }
}

static void rtrim_str(std::string& s_) {
    while ((!s_.empty()) && ((unsigned char)s_.back() <= ' ')) {
        s_.pop_back();
    }
}

static const char* ltrim(const char* s_) {
    while ((*s_ == ' ') || (*s_ == '\t')) {
        s_++;
    }
    return s_;
}

HintsFile load_hints_file(const std::string& path_) {
    HintsFile result;

    FILE* f = fopen(path_.c_str(), "r");
    if (!f) {
        fprintf(stderr, "[warn] cannot open hints file: %s\n", path_.c_str());
        return result;
    }

    char line[1024] = {0};
    int  lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        rtrim(line);

        const char* p = ltrim(line);
        if ((*p == '\0') || (*p == '#')) {
            continue;
        }

        if (*p == '!') {
            p++;  /* skip '!' */
            const char* name_start = p;
            while ((*p) && ((unsigned char)*p > ' ')) {
                p++;
            }

            std::string name(name_start, p);
            if ((name.empty()) || (name.size() > 128)) {
                fprintf(stderr, "[warn] hints file line %d: invalid exclusion name, skipped\n", lineno);
                continue;
            }
            result._excludes.insert(name);
            continue;
        }
        /* Token 1: product name */
        const char* name_start = p;
        while ((*p) && ((unsigned char)*p > ' ')) {
            p++;
        }

        std::string name(name_start, p);
        if ((name.empty()) || (name.size() > 128)) {
            fprintf(stderr, "[warn] hints file line %d: invalid name, skipped\n", lineno);
            continue;
        }

        p = ltrim(p);

        /* Token 2: version (optional) */
        std::string version;
        if ((*p != '\0') && (*p != '#')) {
            const char* ver_start = p;
            while ((*p) && ((unsigned char)*p > ' ')) {
                p++;
            }
            std::string v(ver_start, p);

            /* '-' and '?' are placeholders meaning "version unknown" */
            if ((v != "-") && (v != "?")) {
                version = std::move(v);
            }

            p = ltrim(p);
        }

        /* Token 3+: SPDX license expression (rest of line) */
        std::string license;
        if ((*p != '\0') && (*p != '#')) {
            license = p;
            rtrim_str(license);
        }

        result._libs.push_back({name, version, "hint-file", license});
    }

    fclose(f);

    fprintf(stderr, "Loaded %zu hint(s), %zu exclusion(s) from %s\n", result._libs.size(), 
                                                                      result._excludes.size(),
                                                                      path_.c_str());
    return result;
}
