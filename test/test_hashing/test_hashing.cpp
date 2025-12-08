#include <harpocrates/hashing.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <algorithm>
#include <ctime>

#include <sstream>
#include <utility>

void print_hex(const std::vector<uint8_t> &data)
{
  std::stringstream ss;
  for (const auto &elm : data)
  {
    ss << std::hex << (int)elm;
  }

  std::cout << ss.str() << std::endl;
}

std::vector<uint8_t> generate_data(size_t size)
{
  std::vector<uint8_t> data(size);
  std::generate(data.begin(), data.end(), rand);
  return data;
}

TEST(test_hashing, test_hash_name)
{
  EXPECT_EQ("SHA-1", harpocrates::hashing::hash_name(harpocrates::hashing::hash_type::SHA1));
  EXPECT_EQ("SHA-256", harpocrates::hashing::hash_name(harpocrates::hashing::hash_type::SHA256));
  EXPECT_EQ("SHA-512", harpocrates::hashing::hash_name(harpocrates::hashing::hash_type::SHA512));
}

TEST(test_hashing, test_sha1_hashing_1kb)
{

  std::vector<uint8_t> data = generate_data(1024);
  std::vector<uint8_t> data1 = data;
  std::vector<uint8_t> data2 = generate_data(1024);

  EXPECT_EQ(data, data1);
  EXPECT_NE(data, data2);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  std::vector<uint8_t> hash3;

  harpocrates::hashing::vectors::sha1_hash(data, hash1);
  harpocrates::hashing::vectors::sha1_hash(data1, hash2);
  harpocrates::hashing::vectors::sha1_hash(data2, hash3);

  EXPECT_EQ(hash1, hash2);
  EXPECT_NE(hash1, hash3);
}

TEST(test_hashing, test_sha1_hashing_4kb)
{

  std::vector<uint8_t> data = generate_data(4096);
  std::vector<uint8_t> data1 = data;
  std::vector<uint8_t> data2 = generate_data(4096);

  EXPECT_EQ(data, data1);
  EXPECT_NE(data, data2);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  std::vector<uint8_t> hash3;

  harpocrates::hashing::vectors::sha1_hash(data, hash1);
  harpocrates::hashing::vectors::sha1_hash(data1, hash2);
  harpocrates::hashing::vectors::sha1_hash(data2, hash3);

  EXPECT_EQ(hash1, hash2);
  EXPECT_NE(hash1, hash3);
}

TEST(test_hashing, test_sha256_hashing_1kb)
{

  std::vector<uint8_t> data = generate_data(1024);
  std::vector<uint8_t> data1 = data;
  std::vector<uint8_t> data2 = generate_data(1024);

  EXPECT_EQ(data, data1);
  EXPECT_NE(data, data2);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  std::vector<uint8_t> hash3;

  harpocrates::hashing::vectors::sha256_hash(data, hash1);
  harpocrates::hashing::vectors::sha256_hash(data1, hash2);
  harpocrates::hashing::vectors::sha256_hash(data2, hash3);

  EXPECT_EQ(hash1, hash2);
  EXPECT_NE(hash1, hash3);
}

TEST(test_hashing, test_sha256_hashing_4kb)
{

  std::vector<uint8_t> data = generate_data(4096);
  std::vector<uint8_t> data1 = data;
  std::vector<uint8_t> data2 = generate_data(4096);

  EXPECT_EQ(data, data1);
  EXPECT_NE(data, data2);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  std::vector<uint8_t> hash3;

  harpocrates::hashing::vectors::sha256_hash(data, hash1);
  harpocrates::hashing::vectors::sha256_hash(data1, hash2);
  harpocrates::hashing::vectors::sha256_hash(data2, hash3);

  EXPECT_EQ(hash1, hash2);
  EXPECT_NE(hash1, hash3);
}

TEST(test_hashing, test_sha512_hashing_1kb)
{

  std::vector<uint8_t> data = generate_data(1024);
  std::vector<uint8_t> data1 = data;
  std::vector<uint8_t> data2 = generate_data(1024);

  EXPECT_EQ(data, data1);
  EXPECT_NE(data, data2);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  std::vector<uint8_t> hash3;

  harpocrates::hashing::vectors::sha512_hash(data, hash1);
  harpocrates::hashing::vectors::sha512_hash(data1, hash2);
  harpocrates::hashing::vectors::sha512_hash(data2, hash3);

  EXPECT_EQ(hash1, hash2);
  EXPECT_NE(hash1, hash3);
}

TEST(test_hashing, test_sha512_hashing_4kb)
{

  std::vector<uint8_t> data = generate_data(4096);
  std::vector<uint8_t> data1 = data;
  std::vector<uint8_t> data2 = generate_data(4096);

  EXPECT_EQ(data, data1);
  EXPECT_NE(data, data2);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  std::vector<uint8_t> hash3;

  harpocrates::hashing::vectors::sha512_hash(data, hash1);
  harpocrates::hashing::vectors::sha512_hash(data1, hash2);
  harpocrates::hashing::vectors::sha512_hash(data2, hash3);

  EXPECT_EQ(hash1, hash2);
  EXPECT_NE(hash1, hash3);
}

TEST(test_hashing, test_sha_hash_sha1_1kb_function)
{

  std::vector<uint8_t> data = generate_data(1024);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;

  harpocrates::hashing::vectors::sha1_hash(data, hash1);
  harpocrates::hashing::vectors::sha_hash(data, hash2, harpocrates::hashing::hash_type::SHA1);

  EXPECT_EQ(hash1, hash2);
}

TEST(test_hashing, test_sha_hash_sha256_1kb_function)
{

  std::vector<uint8_t> data = generate_data(1024);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;

  harpocrates::hashing::vectors::sha256_hash(data, hash1);
  harpocrates::hashing::vectors::sha_hash(data, hash2, harpocrates::hashing::hash_type::SHA256);

  EXPECT_EQ(hash1, hash2);
}

TEST(test_hashing, test_sha_hash_sha512_1kb_function)
{

  std::vector<uint8_t> data = generate_data(1024);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;

  harpocrates::hashing::vectors::sha512_hash(data, hash1);
  harpocrates::hashing::vectors::sha_hash(data, hash2, harpocrates::hashing::hash_type::SHA512);

  EXPECT_TRUE(hash2.size() > 0);
  EXPECT_EQ(hash1, hash2);
}

TEST(test_hashing, test_hmac_vector_hashing_1kb)
{
  std::vector<uint8_t> data = generate_data(1024);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  harpocrates::hashing::vectors::hmac_hash(data, hash1);
  EXPECT_EQ(hash1.size(), (size_t)20);

  harpocrates::hashing::vectors::hmac_hash(data, hash2);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_EQ(hash1, hash2);

  std::vector<uint8_t> data2 = generate_data(1024);
  harpocrates::hashing::vectors::hmac_hash(data2, hash2);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_NE(hash1, hash2);
}

TEST(test_hashing, test_hmac_vector_hashing_1kb_none_empty_key)
{
  std::vector<uint8_t> data = generate_data(1024);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  harpocrates::hashing::vectors::hmac_hash(data, hash1, false);
  EXPECT_EQ(hash1.size(), (size_t)20);

  harpocrates::hashing::vectors::hmac_hash(data, hash2, false);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_EQ(hash1, hash2);

  std::vector<uint8_t> data2 = generate_data(1024);
  harpocrates::hashing::vectors::hmac_hash(data2, hash2, false);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_NE(hash1, hash2);
}

TEST(test_hashing, test_hmac_vector_hashing_4kb)
{
  std::vector<uint8_t> data = generate_data(4096);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  harpocrates::hashing::vectors::hmac_hash(data, hash1);
  EXPECT_EQ(hash1.size(), (size_t)20);

  harpocrates::hashing::vectors::hmac_hash(data, hash2);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_EQ(hash1, hash2);

  std::vector<uint8_t> data2 = generate_data(4096);
  harpocrates::hashing::vectors::hmac_hash(data2, hash2);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_NE(hash1, hash2);
}

TEST(test_hashing, test_hmac_vector_hashing_4kb_none_empty_key)
{
  std::vector<uint8_t> data = generate_data(4096);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  harpocrates::hashing::vectors::hmac_hash(data, hash1, false);
  EXPECT_EQ(hash1.size(), (size_t)20);

  harpocrates::hashing::vectors::hmac_hash(data, hash2, false);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_EQ(hash1, hash2);

  std::vector<uint8_t> data2 = generate_data(4096);
  harpocrates::hashing::vectors::hmac_hash(data2, hash2, false);
  EXPECT_EQ(hash2.size(), (size_t)20);

  EXPECT_NE(hash1, hash2);
}

TEST(test_hashing, test_crc_vector_hashing_1kb)
{
  std::vector<uint8_t> data = generate_data(1024);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  harpocrates::hashing::vectors::crc32_hash(data, hash1);
  EXPECT_EQ(hash1.size(), (size_t)CRC_DIGEST_LENGTH);

  harpocrates::hashing::vectors::crc32_hash(data, hash2);
  EXPECT_EQ(hash2.size(), (size_t)CRC_DIGEST_LENGTH);

  EXPECT_EQ(hash1, hash2);

  std::vector<uint8_t> data2 = generate_data(1024);
  harpocrates::hashing::vectors::crc32_hash(data2, hash2);
  EXPECT_EQ(hash2.size(), (size_t)CRC_DIGEST_LENGTH);

  EXPECT_NE(hash1, hash2);
}

TEST(test_hashing, test_crc_vector_hashing_4kb)
{
  std::vector<uint8_t> data = generate_data(4096);

  std::vector<uint8_t> hash1;
  std::vector<uint8_t> hash2;
  harpocrates::hashing::vectors::crc32_hash(data, hash1);
  EXPECT_EQ(hash1.size(), (size_t)CRC_DIGEST_LENGTH);

  harpocrates::hashing::vectors::crc32_hash(data, hash2);
  EXPECT_EQ(hash2.size(), (size_t)CRC_DIGEST_LENGTH);

  EXPECT_EQ(hash1, hash2);

  std::vector<uint8_t> data2 = generate_data(4096);
  harpocrates::hashing::vectors::crc32_hash(data2, hash2);
  EXPECT_EQ(hash2.size(), (size_t)CRC_DIGEST_LENGTH);

  EXPECT_NE(hash1, hash2);
}

int main(int argc, char **argv)
{

  srand(static_cast<uint32_t>(time(0)));

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
