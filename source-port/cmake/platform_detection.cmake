
# Platform detection
if(WIN32)
    set(WIN32_PLATFORM ON)
    add_definitions(-DUNICODE)
else()
    set(WIN32_PLATFORM OFF)
endif()

