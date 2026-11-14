cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0091 NEW)
project(visualizer LANGUAGES CXX)

add_library(visualizer SHARED entropy.cpp)
set_target_properties(visualizer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

if(MSVC)
    set_property(TARGET visualizer PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_compile_options(visualizer PRIVATE /O2 /EHsc)
else()
    target_compile_options(visualizer PRIVATE -O3)
endif()
