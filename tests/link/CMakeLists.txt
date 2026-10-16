# Host build of the DeskHop Link codec tests. Not part of the firmware build.
#
#   cmake -S tests/link -B build-host
#   cmake --build build-host
#   ctest --test-dir build-host -C Debug --output-on-failure

cmake_minimum_required(VERSION 3.13)
project(deskhop_link_host_tests C)

set(REPO_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)

add_executable(test_link_codec
  test_link_codec.c
  ${REPO_DIR}/src/link_codec.c
)
target_include_directories(test_link_codec PRIVATE ${REPO_DIR}/src/include)
set_target_properties(test_link_codec PROPERTIES C_STANDARD 11)

if (MSVC)
  target_compile_definitions(test_link_codec PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_options(test_link_codec PRIVATE /W4)
else()
  target_compile_options(test_link_codec PRIVATE -Wall -Wextra)
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
enable_testing()
add_test(NAME link_codec
  COMMAND Python3::Interpreter ${REPO_DIR}/tools/run-link-codec-tests.py $<TARGET_FILE:test_link_codec>)
