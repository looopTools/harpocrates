cmake_minimum_required(VERSION 4.0.3)
project(harpocrates LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

message(${PROJECT_NAME})
if(BUILD_STATIC)
  add_library(${PROJECT_NAME} STATIC
    ${CMAKE_SOURCE_DIR}/src/harpocrates/harpocrates.cpp
    ${CMAKE_SOURCE_DIR}/src/harpocrates/hashing.cpp)
else()
  add_library(${PROJECT_NAME} SHARED
    ${CMAKE_SOURCE_DIR}/src/harpocrates/harpocrates.cpp
    ${CMAKE_SOURCE_DIR}/src/harpocrates/hashing.cpp)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

if(BUILD_MEASUREMENTS)
  add_subdirectory(measurements)
endif()

if(BUILD_TEST)
  add_subdirectory(test)
endif()

install(TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION lib)

install(DIRECTORY include/harpocrates DESTINATION include)
