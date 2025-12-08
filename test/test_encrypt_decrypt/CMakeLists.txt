add_executable(test_encrypt_decrypt test_encrypt_decrypt.cpp)

target_link_libraries(test_encrypt_decrypt ${PROJECT_NAME})
target_link_libraries(test_encrypt_decrypt GTest::gtest_main)

add_test(NAME test_encrypt_decrypt COMMAND test_encrypt_decrypt)
