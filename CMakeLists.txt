cmake_minimum_required(VERSION 3.17)
project(vxm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

string(TIMESTAMP VXM_COPYRIGHT_YEAR "%Y")
add_compile_definitions(VXM_COPYRIGHT_YEAR="${VXM_COPYRIGHT_YEAR}")

# === 1. COMPILER FLAGS (x86-64-v3) ===
# Only apply x86-64 optimizations if we are actually compiling for x86_64.
if((CMAKE_CXX_COMPILER_ID MATCHES "GNU") OR (CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        add_compile_options(-march=x86-64-v3)
    endif()
endif()

add_executable(vxm
    src/main.cpp
    src/HardwareDetection.cpp
    src/VirtualMachine.cpp
    src/DeviceManager.cpp
    src/ProfileManager.cpp
    src/InputManager.cpp
)

target_include_directories(vxm PRIVATE src)

install(TARGETS vxm
    RUNTIME DESTINATION bin
)

if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
