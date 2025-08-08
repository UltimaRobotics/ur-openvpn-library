# Force static linking
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

# Dependencies directory
set(DEPS_DIR "${CMAKE_BINARY_DIR}/deps")
set(INSTALL_DIR "${CMAKE_BINARY_DIR}/install")

# ExternalProject module
include(ExternalProject)
include(FetchContent)

# Create install directory
file(MAKE_DIRECTORY ${INSTALL_DIR})

# ============================================================================ 
# If _PORTABLE_BUILD flag is ON, download & build external dependencies
# ============================================================================ 
if(_PORTABLE_BUILD)
    message(STATUS "Portable build enabled - building all dependencies locally")

    # ============================================================================
    # OpenSSL Dependency
    # ============================================================================
    ExternalProject_Add(openssl_external
        URL https://www.openssl.org/source/openssl-1.1.1w.tar.gz
        URL_HASH SHA256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
        PREFIX ${DEPS_DIR}/openssl
        CONFIGURE_COMMAND 
            <SOURCE_DIR>/config 
            --prefix=${INSTALL_DIR}
            --openssldir=${INSTALL_DIR}/ssl
            no-shared
            no-tests
            -fPIC
        BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
        INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1
    )

    # ============================================================================
    # LZO Compression Library
    # ============================================================================
    ExternalProject_Add(lzo_external
        URL http://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz
        URL_HASH SHA256=c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072
        PREFIX ${DEPS_DIR}/lzo
        CONFIGURE_COMMAND 
            <SOURCE_DIR>/configure 
            --prefix=${INSTALL_DIR}
            --enable-static
            --disable-shared
            --disable-dependency-tracking
        BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE 1
    )

    # ============================================================================
    # LZ4 Compression Library
    # ============================================================================
    ExternalProject_Add(lz4_external
        URL https://github.com/lz4/lz4/archive/v1.9.4.tar.gz
        URL_HASH SHA256=0b0e3aa07c8c063ddf40b082bdf7e37a1562bda40a0ff5272957f3e987e0e54b
        PREFIX ${DEPS_DIR}/lz4
        CONFIGURE_COMMAND ""
        BUILD_COMMAND 
            make -C <SOURCE_DIR> -j${CMAKE_BUILD_PARALLEL_LEVEL} 
            PREFIX=${INSTALL_DIR} 
            BUILD_STATIC=yes 
            BUILD_SHARED=no
        INSTALL_COMMAND 
            make -C <SOURCE_DIR> install 
            PREFIX=${INSTALL_DIR} 
            BUILD_STATIC=yes 
            BUILD_SHARED=no
        BUILD_IN_SOURCE 1
    )

    # ============================================================================
    # libcap-ng Library (for capability management)
    # ============================================================================
    if(NOT WIN32)
        ExternalProject_Add(libcapng_external
            URL https://people.redhat.com/sgrubb/libcap-ng/libcap-ng-0.8.3.tar.gz
            URL_HASH SHA256=bed6f6848e22bb2f83b5f764b2aef0ed393054e803a8e3a8711cb2a39e6b492d
            PREFIX ${DEPS_DIR}/libcapng
            CONFIGURE_COMMAND 
                <SOURCE_DIR>/configure 
                --prefix=${INSTALL_DIR}
                --enable-static
                --disable-shared
                --disable-dependency-tracking
                --without-python
                --without-python3
            BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
            INSTALL_COMMAND make install
            BUILD_IN_SOURCE 1
        )
    endif()

    # ============================================================================
    # libnl Library (for Linux DCO support)
    # ============================================================================
    if(NOT WIN32)
        ExternalProject_Add(libnl_external
            URL https://github.com/thom311/libnl/releases/download/libnl3_7_0/libnl-3.7.0.tar.gz
            URL_HASH SHA256=9fe43ccbeeea72c653bdcf8c93332583135cda46a79507bfd0a483bb57f65939
            PREFIX ${DEPS_DIR}/libnl
            CONFIGURE_COMMAND 
                <SOURCE_DIR>/configure 
                --prefix=${INSTALL_DIR}
                --enable-static
                --disable-shared
                --disable-dependency-tracking
                --disable-cli
            BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
            INSTALL_COMMAND make install
            BUILD_IN_SOURCE 1
        )
    endif()

else()
    message(STATUS "Portable build disabled - using system-installed libraries")
endif()

# ============================================================================ 
# Library paths (either from portable build or system)
# ============================================================================ 
set(LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/install/lib")

# OpenSSL libraries
set(OPENSSL_LIBRARIES_GEN
    "${LIB_DIR}/libssl.a"
    "${LIB_DIR}/libcrypto.a"
)

# LZO compression library
set(LZO_LIBRARIES_GEN
    "${LIB_DIR}/liblzo2.a"
)

# LZ4 compression library
set(LZ4_LIBRARIES_GEN
    "${LIB_DIR}/liblz4.a"
)

# libnl libraries (Netlink)
set(LIBNL_LIBRARIES_GEN
    "${LIB_DIR}/libnl-3.a"
    "${LIB_DIR}/libnl-genl-3.a"
    "${LIB_DIR}/libnl-idiag-3.a"
    "${LIB_DIR}/libnl-nf-3.a"
    "${LIB_DIR}/libnl-route-3.a"
    "${LIB_DIR}/libnl-xfrm-3.a"
)
