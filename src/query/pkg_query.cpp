#include <query/pkg_query.hpp>
#include <cstdio>
#include <cstring>
#include <unistd.h>

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
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) {
        out.pop_back();
    }
    return out;
}

enum class PkgMgr { DPkg, RPM, Apk, None };

static PkgMgr detect_pm() {
    if (access("/usr/bin/dpkg",  X_OK) == 0) {
        return PkgMgr::DPkg;
    }
    if (access("/usr/bin/rpm",   X_OK) == 0) {
        return PkgMgr::RPM;
    }
    if (access("/sbin/apk",      X_OK) == 0) {
        return PkgMgr::Apk;
    }
    if (access("/usr/sbin/apk",  X_OK) == 0) {
        return PkgMgr::Apk;
    }
    return PkgMgr::None;
}

void query_package_info(Component& comp_) {
    static PkgMgr pm = detect_pm();
    if (pm == PkgMgr::None || comp_._path.empty()) {
        return;
    }

    char cmd[2048];
    switch (pm) {
        case PkgMgr::DPkg:
            snprintf(cmd, sizeof(cmd),
                "dpkg -S '%s' 2>/dev/null | head -1 | cut -d: -f1",
                comp_._path.c_str());
            comp_._pkg_name = run_cmd(cmd);
            if (!comp_._pkg_name.empty()) {
                snprintf(cmd, sizeof(cmd),
                    "dpkg -s '%s' 2>/dev/null | grep '^Version:' | cut -d' ' -f2",
                    comp_._pkg_name.c_str());
                comp_._pkg_version = run_cmd(cmd);
            }
            break;
        case PkgMgr::RPM:
            snprintf(cmd, sizeof(cmd),
                "rpm -qf '%s' --queryformat '%%{NAME}\\t%%{VERSION}-%%{RELEASE}' 2>/dev/null",
                comp_._path.c_str());
            {
                std::string info = run_cmd(cmd);
                size_t t = info.find('\t');
                if (t != std::string::npos) {
                    comp_._pkg_name    = info.substr(0, t);
                    comp_._pkg_version = info.substr(t + 1);
                }
            }
            break;
        case PkgMgr::Apk:
            snprintf(cmd, sizeof(cmd),
                "apk info --who-owns '%s' 2>/dev/null | awk 'NF{print $NF}'",
                comp_._path.c_str());
            comp_._pkg_name = run_cmd(cmd);
            if (!comp_._pkg_name.empty()) {
                snprintf(cmd, sizeof(cmd),
                    "apk list --installed 2>/dev/null | grep '^%s-' | awk '{print $1}' | head -1",
                    comp_._pkg_name.c_str());
                comp_._pkg_version = run_cmd(cmd);
            }
            break;
        default:
            break;
    }
}
