#pragma once
#include <util/types.hpp>

/* Query dpkg / rpm / apk for the package name and version of a file. */
void query_package_info(Component& comp_);
