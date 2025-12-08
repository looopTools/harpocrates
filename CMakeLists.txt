cmake_minimum_required(VERSION 4.0.3)
project(harpocrates LANGUAGES CXX)

# Get latests Git tag
execute_process(
    COMMAND git describe --tags --abbrev=0
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_TAG
    RESULT_VARIABLE GIT_TAG_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Remove leading v in case it is used in tag
string(REGEX REPLACE "^v" "" GIT_VERSION "${GIT_TAG}")

# Ensure we have major, minor, patch
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ "${GIT_VERSION}")

if(NOT CMAKE_MATCH_COUNT EQUAL 3)
    message(FATAL_ERROR "Invalid version tag format: ${GIT_TAG} (expected X.Y.Z)")
endif()

set(PROJECT_MAJOR_VERSION "${CMAKE_MATCH_1}")
set(PROJECT_MINOR_VERSION "${CMAKE_MATCH_2}")
set(PROJECT_PATCH_VERSION "${CMAKE_MATCH_3}")

set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

If(EXPORT_COMPILE_COMMANDS)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED LIBCRYPTO_VERSION)
set(LIBCRYPTO_VERSION 3)
endif()
find_package(OpenSSL REQUIRED)

if(BUILD_STATIC)
  add_library(${PROJECT_NAME} STATIC
    ${CMAKE_SOURCE_DIR}/src/harpocrates/harpocrates.cpp
    ${CMAKE_SOURCE_DIR}/src/harpocrates/hashing.cpp)
else()
  add_library(${PROJECT_NAME} SHARED
    ${CMAKE_SOURCE_DIR}/src/harpocrates/harpocrates.cpp
    ${CMAKE_SOURCE_DIR}/src/harpocrates/hashing.cpp)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
  VERSION ${PROJECT_MAJOR_VERSION}.${PROJECT_MINOR_VERSION}.${PROJECT_PATCH_VERSION}
  SOVERSION ${PROJECT_MAJOR_VERSION}
)

target_compile_definitions(${PROJECT_NAME} PUBLIC
  LIBCRYPTO_VERSION=${LIBCRYPTO_VERSION}
)


target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

if(BUILD_MEASUREMENTS)
  add_subdirectory(measurements)
endif()

if(BUILD_TEST)
  add_subdirectory(test)
  enable_testing()
endif()

install(TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION lib)

install(DIRECTORY include/harpocrates DESTINATION include)
