cmake_minimum_required(VERSION 3.10)
project(openvpn VERSION 2.7.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Include cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# Include configuration modules
include(compiler_settings)
include(platform_detection)
include(external_deps)
include(dependencies)
include(source_files)
include(target)
# include(installation)
include(summary)