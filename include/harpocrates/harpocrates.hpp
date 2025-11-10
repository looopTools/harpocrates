#ifndef HARPOCRATES_H
#define HARPOCRATES_H

#include <string>
#include <cstdint>
#include <vector>

namespace harpocrates
{
    // Standard AES key size for CBC std is 128bit
    const size_t HARPOCRATES_AES_KEY_SIZE = 16;

    /* Standard AES key size for CBC std is 128bit
     * The initialization vector (IV) is the same size 
     * The cleartext is padded to a multiple of this.
     */
    const size_t HARPOCRATES_AES_BLOCK_SIZE = 16;

    /* Encrypts the data based on the provided key using AES-CBC-128.
    * If the key is longer than 16Bytes, no problem we cut it off
    * The input vector is overwritten to contain the result of the encryption and will have the following format:
    * {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL 16B)}
    * The IV is only included if random_iv==true.
    *
    * IMPORTANT: the value of random_iv must be the same when calling encrypt and decrypt
    *
    * @param key is a string containing the key used for the AES CBC encryption [by default 16 characters long]
    * @param data is the data to be encrypt and will contain the encrypted data
    * @param random_iv determines if we use a random IV. If set to false we will use an all 0 IV. If true we have appended the IV to the data
    */
    void encrypt(const std::string& key, std::vector<uint8_t>& data, bool random_iv=false);

    void encrypt_ctr(const std::string& key, std::vector<uint8_t>& data, bool random_iv=false);    

    /* Decrypts the data based on the provided key using AES-CBC-128.
    * If the key is longer than 16Bytes, no problem we cut it off
    * The input vector is overwritten to contain the result of the decryption. The expected input format:
    * {SIZE_OF_PADDING(1B) | PADDED_CIPHERTEXT | IV(OPTIONAL 16B)}
    * The IV must only be included if random_iv==true.
    *
    * IMPORTANT: the value of random_iv must be the same when calling encrypt and decrypt for a buffer
    *
    * @param key is a string containing the key used for the AES CBC decryption [by default 16 characters long]
    * @param data is the data to be decrypted and will contain the decrypted data
    * @paramrandom_iv determines if a random IV was used for encryption. If set to false we will use an all 0 IV
    */
    void decrypt(const std::string& key, std::vector<uint8_t>& data, bool random_iv=false);

    void decrypt_ctr(const std::string& key, std::vector<uint8_t>& data, bool random_iv=false);    
}
#endif /* HARPOCRATES_H */ 

