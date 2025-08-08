
# Print configuration summary
message(STATUS "OpenVPN Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  OpenSSL: ${OPENSSL_FOUND}")

if(LIBCAPNG_FOUND)
    message(STATUS "  libcap-ng: YES")
else()
    message(STATUS "  libcap-ng: NO")
endif()

if(LIBNL_FOUND AND LIBNL_GENL_FOUND)
    message(STATUS "  libnl: YES")
    message(STATUS "  libnl-genl: YES")
    message(STATUS "  DCO support: YES")
else()
    message(STATUS "  libnl: NO")
    message(STATUS "  libnl-genl: NO")
    message(STATUS "  DCO support: NO")
endif()

if(LZO_FOUND)
    message(STATUS "  LZO compression: YES")
else()
    message(STATUS "  LZO compression: NO")
endif()

if(LZ4_FOUND)
    message(STATUS "  LZ4 compression: YES")
else()
    message(STATUS "  LZ4 compression: NO")
endif()

