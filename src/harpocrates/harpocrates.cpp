#include <harpocrates/harpocrates.hpp>
#include <harpocrates/static_block.hpp> //We need this to ensure srand is called when the application starts

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/modes.h>

#include <cstdint>
#include <string.h>
#include <string>
#include <vector>

#include <algorithm>
#include <ctime>

#include <iostream>
#include <stdexcept>

static_block { srand(static_cast<uint32_t>(time(0))); }

namespace harpocrates
{

/* Generates a random sequence of size bytes, which is used for the randomised
 * IV
 * @param size is the size of the randomise vector in bytes
 * @return a vector of bytes
 */
std::vector<uint8_t> generate_iv(size_t size)
{
  std::vector<uint8_t> data(size);
  std::generate(data.begin(), data.end(), rand);
  return data;
}

std::vector<uint8_t> genrate_test()
{
  uint8_t x = 10 * 100;
  uint8_t y = x + 10;
  return {x, y};
}

/* Encrypts the data based on the provided key using AES-CBC-128.
 * If the key is longer than 16Bytes, no problem we cut it off
 * The input vector is overwritten to contain the result of the encryption and
 * will have the following format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT |
 * IV(OPTIONAL 16B)} The IV is only included if random_iv==true.
 *
 * IMPORTANT: the value of random_iv must be the same when calling encrypt and
 * decrypt
 *
 * @param key is a string containing the key used for the AES CBC encryption [by
 * default 16 characters long]
 * @param data is the data to be encrypt and will contain the encrypted data
 * @param random_iv determines if we use a random IV. If set to false we will
 * use an all 0 IV. If true we have appended the IV to the data
 */
void encrypt(const std::string &key, std::vector<uint8_t> &data, bool random_iv)
{
  if (key.size() < HARPOCRATES_AES_KEY_SIZE)
  {
    throw std::runtime_error(
        "Provided AES key is too short! By default key must be 16 bytes long");
  }

  // Set up the key, convert it to the format required by OpenSSL
  unsigned char ukey[HARPOCRATES_AES_KEY_SIZE];
  for (uint32_t i = 0; i < HARPOCRATES_AES_KEY_SIZE; ++i)
  {
    ukey[i] = (unsigned char)key[i];
  }
  AES_KEY encryption_key;
  AES_set_encrypt_key(ukey, HARPOCRATES_AES_KEY_SIZE * 8,
                      &encryption_key); // key size in bits rather than bytes

  // If necessary, pad the cleartext to have a size that is a multiple of
  // AES_BLOCK_SIZE
  size_t cleartext_size = data.size();
  size_t padded_size = cleartext_size;
  uint8_t padding = AES_BLOCK_SIZE - cleartext_size % AES_BLOCK_SIZE;

  if (padding == AES_BLOCK_SIZE)
  {
    padding = 0;
  }

  if (padding != 0)
  {
    padded_size += padding;
    data.resize(padded_size);
  }

  size_t ciphertext_size = padded_size;

  // Generate the initialization vector, either randomly or by chosing an all-0
  // vector
  std::vector<uint8_t> iv;
  if (random_iv)
  {
    iv = generate_iv(AES_BLOCK_SIZE);
    ciphertext_size += AES_BLOCK_SIZE;
  }
  else
  {
    iv = std::vector<uint8_t>(AES_BLOCK_SIZE, 0);
  }

  // Generate a vector representing the original cleartext_size
  const size_t size_vec_size =
      1; // Extra byte to represent the amount of padding
  ciphertext_size += 1;

  // Create the vector that will hold the ciphertext and emplace the metadata to
  // its end Format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL
  // 16B)}
  std::vector<uint8_t> ciphertext(ciphertext_size);
  ciphertext[0] = padding;
  if (random_iv)
  {
    memcpy(ciphertext.data() + size_vec_size + padded_size, iv.data(),
           AES_BLOCK_SIZE);
  }

  // Do the actual encryption
  AES_cbc_encrypt(data.data(), ciphertext.data() + size_vec_size, padded_size,
                  &encryption_key, iv.data(), AES_ENCRYPT);

  // Save result
  data = ciphertext;
}

void encrypt_ctr(const std::string &key, std::vector<uint8_t> &data,
                 bool random_iv)
{
  // if (key.size() < HARPOCRATES_AES_KEY_SIZE)
  // {
  //     throw std::runtime_error("Provided AES key is too short! By default key
  //     must be 16 bytes long");
  // }

  // // Set up the key, convert it to the format required by OpenSSL
  // unsigned char ukey[HARPOCRATES_AES_KEY_SIZE];
  // for (uint32_t i = 0; i < HARPOCRATES_AES_KEY_SIZE; ++i)
  // {
  //     ukey[i] = (unsigned char) key[i];
  // }
  // AES_KEY encryption_key;
  // AES_set_encrypt_key(ukey, HARPOCRATES_AES_KEY_SIZE * 8, &encryption_key);
  // //key size in bits rather than bytes

  // // If necessary, pad the cleartext to have a size that is a multiple of
  // AES_BLOCK_SIZE size_t cleartext_size = data.size(); size_t padded_size =
  // cleartext_size; uint8_t padding  = AES_BLOCK_SIZE - cleartext_size %
  // AES_BLOCK_SIZE;

  // if(padding == AES_BLOCK_SIZE)
  // {
  //     padding = 0;
  // }

  // if(padding != 0)
  // {
  //     padded_size += padding;
  //     data.resize(padded_size);
  // }

  // size_t ciphertext_size = padded_size;

  // // Generate the initialization vector, either randomly or by chosing an
  // all-0 vector std::vector<uint8_t> iv; if (random_iv)
  // {
  //     iv = generate_iv(AES_BLOCK_SIZE);
  //     ciphertext_size += AES_BLOCK_SIZE;
  // }
  // else
  // {
  //     iv = std::vector<uint8_t>(AES_BLOCK_SIZE, 0);
  // }

  // //Generate a vector representing the original cleartext_size
  // const size_t size_vec_size = 1;// Extra byte to represent the amount of
  // padding ciphertext_size += 1;

  // //Create the vector that will hold the ciphertext and emplace the metadata
  // to its end
  // //Format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL 16B)}
  // std::vector<uint8_t> ciphertext(ciphertext_size);
  // ciphertext[0] = padding;
  // if(random_iv)
  // {
  //     memcpy(ciphertext.data() + size_vec_size + padded_size, iv.data(),
  //     AES_BLOCK_SIZE);
  // }

  if (key.size() < HARPOCRATES_AES_KEY_SIZE)
  {
    throw std::runtime_error(
        "Provided AES key is too short! By default key must be 16 bytes long");
  }

  // Set up the key, convert it to the format required by OpenSSL
  unsigned char ukey[HARPOCRATES_AES_KEY_SIZE];
  for (uint32_t i = 0; i < HARPOCRATES_AES_KEY_SIZE; ++i)
  {
    ukey[i] = (unsigned char)key[i];
  }
  AES_KEY encryption_key;
  AES_set_encrypt_key(ukey, HARPOCRATES_AES_KEY_SIZE * 8,
                      &encryption_key); // key size in bits rather than bytes

  // If necessary, pad the cleartext to have a size that is a multiple of
  // AES_BLOCK_SIZE
  size_t cleartext_size = data.size();
  size_t padded_size = cleartext_size;
  uint8_t padding = AES_BLOCK_SIZE - cleartext_size % AES_BLOCK_SIZE;

  if (padding == AES_BLOCK_SIZE)
  {
    padding = 0;
  }

  if (padding != 0)
  {
    padded_size += padding;
    data.resize(padded_size);
  }

  size_t ciphertext_size = padded_size;

  // Generate the initialization vector, either randomly or by chosing an all-0
  // vector
  std::vector<uint8_t> iv;
  if (random_iv)
  {
    iv = generate_iv(AES_BLOCK_SIZE);
    ciphertext_size += AES_BLOCK_SIZE;
  }
  else
  {
    iv = std::vector<uint8_t>(AES_BLOCK_SIZE, 0);
  }

  // Generate a vector representing the original cleartext_size
  const size_t size_vec_size =
      1; // Extra byte to represent the amount of padding
  ciphertext_size += 1;

  // Create the vector that will hold the ciphertext and emplace the metadata to
  // its end Format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL
  // 16B)}
  std::vector<uint8_t> ciphertext(ciphertext_size);
  ciphertext[0] = padding;
  if (random_iv)
  {
    memcpy(ciphertext.data() + size_vec_size + padded_size, iv.data(),
           AES_BLOCK_SIZE);
  }

  // unsigned int num = 0;
  // unsigned int counter = 0;
  // unsigned char ecount[AES_BLOCK_SIZE];
  // Do the actual encryption
  // TODO:         AES_ctr128_encrypt(indata, outdata, bytes_read, &key,
  // state.ivec, state.ecount, &state.num);
  // https://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
  //        AES_ctr128_encrypt(data.data(), ciphertext.data() + size_vec_size,
  //        (unsigned long) data.size(), &encryption_key, iv.data(), counter,
  //        &num, AES_ENCRYPT);
  /// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
  EVP_CIPHER_CTX *ctx;
  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    // TODO: Throw exception
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, ukey, iv.data()))
  {
    // TODO: Throw Exception
  }

  int length;
  if (1 != EVP_EncryptUpdate(ctx, ciphertext.data() + size_vec_size, &length,
                             data.data(), data.size()))
  {
    // TODO: Throw Exception
  }

  // ciphertext.data() + length
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + size_vec_size, &length))
  {
    // TODO: Throw execption
  }

  EVP_CIPHER_CTX_free(ctx);

  data = ciphertext;
}

/* Decrypts the data based on the provided key using AES-CBC-128.
 * If the key is longer than 16Bytes, no problem we cut it off
 * The input vector is overwritten to contain the result of the decryption. The
 * expected input format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL
 * 16B)} The IV must only be included if random_iv==true.
 *
 * IMPORTANT: the value of random_iv must be the same when calling encrypt and
 * decrypt for a buffer
 *
 * @param key is a string containing the key used for the AES CBC decryption [by
 * default 16 characters long]
 * @param data is the data to be decrypted and will contain the decrypted data
 * @paramrandom_iv determines if a random IV was used for encryption. If set to
 * false we will use an all 0 IV
 */
void decrypt(const std::string &key, std::vector<uint8_t> &data, bool random_iv)
{
  if (key.size() < HARPOCRATES_AES_KEY_SIZE)
  {
    throw std::runtime_error(
        "Provided AES key is too short! By default key must be 16 bytes long");
  }

  unsigned char ukey[HARPOCRATES_AES_KEY_SIZE];

  // Set up the key, convert it to the format required by OpenSSL
  for (uint32_t i = 0; i < HARPOCRATES_AES_KEY_SIZE; ++i)
  {
    ukey[i] = (unsigned char)key[i];
  }

  AES_KEY decrypt_key;
  AES_set_decrypt_key(ukey, HARPOCRATES_AES_KEY_SIZE * 8,
                      &decrypt_key); // key size in bits rather than bytes

  // Extract the metadata from data
  // Format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL 16B)}
  std::vector<uint8_t>::const_iterator cipher_start = data.begin() + 1;
  std::vector<uint8_t>::const_iterator cipher_end;

  if (random_iv)
  {
    cipher_end = data.begin() + data.size() - AES_BLOCK_SIZE;
  }
  else
  {
    cipher_end = data.end();
  }

  std::vector<uint8_t> cipher = std::vector<uint8_t>(cipher_start, cipher_end);

  std::vector<uint8_t> iv;

  if (random_iv)
  {
    std::vector<uint8_t>::const_iterator iv_start = cipher_end;
    std::vector<uint8_t>::const_iterator iv_end = data.end();

    iv = std::vector<uint8_t>(iv_start, iv_end);
  }
  else
  {
    iv = std::vector<uint8_t>(AES_BLOCK_SIZE, 0);
  }

  size_t cleartext_size = cipher.size() - data[0];
  std::vector<uint8_t> decrypted(cipher.size());

  // Do the actual decryption
  AES_cbc_encrypt(cipher.data(), decrypted.data(), cipher.size(), &decrypt_key,
                  iv.data(), AES_DECRYPT);

  // Remove any potential padding
  decrypted.resize(cleartext_size);
  data = decrypted;
}

void decrypt_ctr(const std::string &key, std::vector<uint8_t> &data,
                 bool random_iv)
{
  if (key.size() < HARPOCRATES_AES_KEY_SIZE)
  {
    throw std::runtime_error(
        "Provided AES key is too short! By default key must be 16 bytes long");
  }

  unsigned char ukey[HARPOCRATES_AES_KEY_SIZE];

  // Set up the key, convert it to the format required by OpenSSL
  for (uint32_t i = 0; i < HARPOCRATES_AES_KEY_SIZE; ++i)
  {
    ukey[i] = (unsigned char)key[i];
  }

  AES_KEY decrypt_key;
  AES_set_decrypt_key(ukey, HARPOCRATES_AES_KEY_SIZE * 8,
                      &decrypt_key); // key size in bits rather than bytes

  // Extract the metadata from data
  // Format: {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL 16B)}
  std::vector<uint8_t>::const_iterator cipher_start = data.begin() + 1;
  std::vector<uint8_t>::const_iterator cipher_end;

  if (random_iv)
  {
    cipher_end = data.begin() + data.size() - AES_BLOCK_SIZE;
  }
  else
  {
    cipher_end = data.end();
  }

  std::vector<uint8_t> cipher = std::vector<uint8_t>(cipher_start, cipher_end);

  std::vector<uint8_t> iv;

  if (random_iv)
  {
    std::vector<uint8_t>::const_iterator iv_start = cipher_end;
    std::vector<uint8_t>::const_iterator iv_end = data.end();

    iv = std::vector<uint8_t>(iv_start, iv_end);
  }
  else
  {
    iv = std::vector<uint8_t>(AES_BLOCK_SIZE, 0);
  }

  size_t cleartext_size = cipher.size() - data[0];
  std::vector<uint8_t> decrypted(cipher.size());

  //         //
  //         https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    // TODO: Throw exception
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, ukey, iv.data()))
  {
    // TODO: Throw Exceptions
  }

  int length = 0;
  if (1 != EVP_DecryptUpdate(ctx, decrypted.data(), &length, cipher.data(),
                             cipher.size()))
  {
    // TODO: Throw Exceptions
  }

  if (1 != EVP_DecryptFinal_ex(ctx, decrypted.data() + length, &length))
  {
    // TODO: Throw excpetion
  }

  EVP_CIPHER_CTX_free(ctx);

  decrypted.resize(cleartext_size);
  data = decrypted;
}
} // namespace harpocrates
