cmake_minimum_required(VERSION 3.17)
project(vxm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-mavx2 -O3)

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
