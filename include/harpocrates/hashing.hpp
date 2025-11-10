#ifndef HARPOCRATES_HASHING_H
#define HARPOCRATES_HASHING_H

#include <string>
#include <cstdint>
#include <vector>

#define CRC_DIGEST_LENGTH 4

namespace harpocrates
{
namespace hashing
{
enum hash_type
{
    SHA1,
    SHA256,
    SHA512,
    HMAC,
    CRC32,
};

    /// Returns length of digest for specified hash function
    /// @param type the type of hash function
    /// @return length of digest in bytes
    size_t get_digest_length(hash_type type);

    std::string hash_name(hash_type type);
        

namespace vectors
{
    /// Create a hash for the data of the provided hash type
    /// @param data the data to be hashed
    /// @param hash will contain the hash
    /// @param type is the hash_type which will be used
    void hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash, hash_type type);

    
    /// Creates a SHA-1 hash finger print for a chunk
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param hash the sink for the hash
    void sha1_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash);

    /// Creates a SHA-256 hash finger print for a chunk
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param hash the sink for the hash        
    void sha256_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash);    
    
    /// Creates a SHA-512 hash finger print for a chunk
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param hash the sink for the hash        
    void sha512_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash);

    void hmac_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash, bool empty_key=true);

    /// Creates a CRC-32 hash finger print for a chunk
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param hash the sink for the hash
    void crc32_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash);
}

namespace pointers
{

    /// Create a hash for the data of the provided hash type, pointer-based version
    /// @param data the data to be hashed
    /// @param size length of data
    /// @param hash will contain the hash, memory allocated by caller
    /// @param type is the hash_type which will be used
    void hash(const uint8_t* data, const size_t size, uint8_t* hash, hash_type type);

    /// Creates a SHA-1 hash finger print for a chunk, pointer-based version
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param size length of data
    /// @param hash the sink for the hash, memory allocated by caller
    void sha1_hash(const uint8_t* data, const size_t size, uint8_t* hash);    

    /// Creates a SHA-256 hash finger print for a chunk, pointer-based version
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param size length of data
    /// @param hash the sink for the hash, memory allocated by caller
    void sha256_hash(const uint8_t* data, const size_t size, uint8_t* hash);


    /// Creates a SHA-512 hash finger print for a chunk, pointer-based version
    /// @param data the data chunk the fingerprint will be constructed for
    /// @param size length of data
    /// @param hash the sink for the hash, memory allocated by caller
    void sha512_hash(const uint8_t* data, const size_t size, uint8_t* hash);
}   
}
}

#endif /* HARPOCRATES_HASHING_H */
