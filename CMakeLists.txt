cmake_minimum_required(VERSION 3.17)
project(vxm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
