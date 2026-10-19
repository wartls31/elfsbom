#pragma once
#include <util/types.hpp>

enum class SbomFormat {
    Text,           /* human-readable report */
    CycloneDX_JSON, /* CycloneDX 1.4 JSON  (cyclonedx.org) */
    SPDX_TagValue,  /* SPDX 2.3 tag-value  (ISO/IEC 5962:2021) */
};

/* Single-file analysis output */
void write_sbom(const DepGraph& graph_, SbomFormat fmt_, const std::string& output_ = {});

/* Directory (batch) analysis output */
void write_sbom_multi(const MultiGraph& mg_, SbomFormat fmt_, const std::string& output_ = {});
