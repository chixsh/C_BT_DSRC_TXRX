cmake_minimum_required(VERSION 3.3)
project(Safety)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")


add_custom_target(Safety COMMAND make -C ${Safety_SOURCE_DIR}/src/ CLION_EXE_DIR=${PROJECT_BINARY_DIR})
