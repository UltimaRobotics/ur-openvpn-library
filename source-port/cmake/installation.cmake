
# Installation
install(TARGETS openvpn
    RUNTIME DESTINATION sbin
)

install(TARGETS ovpn-client-api ovpn-server-api
    RUNTIME DESTINATION bin
)

# Optional: Create a compatibility library (libcompat)
# This would need to be implemented based on src/compat contents
# add_subdirectory(src/compat)
# target_link_libraries(openvpn compat)

