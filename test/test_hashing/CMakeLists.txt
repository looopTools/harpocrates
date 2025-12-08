add_executable(test_hashing test_hashing.cpp)

target_link_libraries(test_hashing ${PROJECT_NAME})
target_link_libraries(test_hashing GTest::gtest_main)

add_test(NAME test_hashing COMMAND test_hashing)
