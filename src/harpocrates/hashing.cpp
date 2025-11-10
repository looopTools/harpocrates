#include <harpocrates/hashing.hpp>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <numeric>

namespace harpocrates
{
namespace hashing
{

    size_t get_digest_length(hash_type type)
    {
	switch(type)
        {
        case hash_type::SHA1:
            return SHA_DIGEST_LENGTH;
	case hash_type::SHA256:
	    return SHA256_DIGEST_LENGTH;
        case hash_type::SHA512:
            return SHA512_DIGEST_LENGTH;
	case hash_type::CRC32:
            return CRC_DIGEST_LENGTH;
        default:
            return SHA_DIGEST_LENGTH;
        }
     }

    std::string hash_name(hash_type type)
    {
	switch(type)
        {
        case hash_type::SHA1:
            return "SHA-1";
	case hash_type::SHA256:
	    return "SHA-256";
        case hash_type::SHA512:
            return "SHA-512";
        case hash_type::HMAC:
            return "HMAC";
        case hash_type::CRC32:
            return "CRC32";
        default:
            return "SHA-1";
        }
    }

namespace vectors
{
    void hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash, hash_type type)
    {
        switch(type)
        {
        case hash_type::SHA1:
            sha1_hash(data, hash);
            break;
        case hash_type::SHA256:
            sha256_hash(data, hash);
            break;
        case hash_type::SHA512:
            sha512_hash(data, hash);
            break;
        case hash_type::HMAC:
            hmac_hash(data, hash);
            break;
        case hash_type::CRC32:
            crc32_hash(data, hash);
            break;
        default:
            sha1_hash(data, hash);
            break;
        }
    }

    void sha1_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash)
    {
        unsigned char digest[SHA_DIGEST_LENGTH];

        SHA_CTX shactx;

        SHA1_Init(&shactx);
        SHA1_Update(&shactx, data.data(), data.size());
        SHA1_Final(digest, &shactx);

        hash = std::vector<uint8_t>(SHA_DIGEST_LENGTH);
        for (uint32_t i = 0; i < SHA_DIGEST_LENGTH; ++i)
        {
            hash.at(i) = (uint8_t) digest[i];
        }
    }

    void sha256_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH];

        SHA256_CTX shactx;

        SHA256_Init(&shactx);
        SHA256_Update(&shactx, data.data(), data.size());
        SHA256_Final(digest, &shactx);

        hash = std::vector<uint8_t>(SHA256_DIGEST_LENGTH);
        for (uint32_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        {
            hash.at(i) = (uint8_t) digest[i];
        }
    }

    void sha512_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash)
    {
        unsigned char digest[SHA512_DIGEST_LENGTH];

        SHA512_CTX shactx;

        SHA512_Init(&shactx);
        SHA512_Update(&shactx, data.data(), data.size());
        SHA512_Final(digest, &shactx);

        hash = std::vector<uint8_t>(SHA512_DIGEST_LENGTH);
        for (uint32_t i = 0; i < SHA512_DIGEST_LENGTH; ++i)
        {
            hash.at(i) = (uint8_t) digest[i];
        }
    }

    void hmac_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash, bool empty_key)
    {
        std::vector<uint8_t> temp_data(data.size() + 1);
        temp_data.at(0) = 0x01;
        std::memcpy(temp_data.data()+1, data.data(), data.size());

        std::vector<uint8_t> key;

        if (!empty_key)
        {
            sha1_hash(data, key);
        }
        else
        {
            key = std::vector<uint8_t>(SHA_DIGEST_LENGTH, 0);
        }

        uint8_t* temp;

        temp =  (uint8_t*) ::HMAC(EVP_sha1(), key.data(), key.size(),
                                  (unsigned char*)temp_data.data(), temp_data.size(), NULL, NULL);
        hash = std::vector<uint8_t>(SHA_DIGEST_LENGTH);
        memcpy(hash.data(), temp, SHA_DIGEST_LENGTH);
    }

    std::array<std::uint_fast32_t, 256> generate_crc_lookup_table() noexcept
    {
        auto const reversed_polynomial = std::uint_fast32_t{0xEDB88320uL};

        struct byte_checksum
	{
	    std::uint_fast32_t operator()() noexcept
	    {
                auto checksum = static_cast<std::uint_fast32_t>(n++);

                for (auto i = 0; i < 8; ++i)
                    checksum = (checksum >> 1) ^ ((checksum & 0x1u) ? reversed_polynomial : 0);

                return checksum;
            }

            unsigned n = 0;
        };

	auto table = std::array<std::uint_fast32_t, 256>{};
	std::generate(table.begin(), table.end(), byte_checksum{});

	return table;
    }

    void crc32_hash(const std::vector<uint8_t>& data, std::vector<uint8_t>& hash)
    {
        static auto const table = generate_crc_lookup_table();

        std::uint_fast32_t temp = std::uint_fast32_t{0xFFFFFFFFuL} & ~std::accumulate(data.cbegin(), data.cend(), ~std::uint_fast32_t{0} & std::uint_fast32_t{0xFFFFFFFFuL}, [](std::uint_fast32_t checksum, std::uint_fast32_t value){return table[(checksum ^ value) & 0xFFu] ^ (checksum >> 8);});
        hash.clear();
        hash.reserve(CRC_DIGEST_LENGTH);
        for (int i = CRC_DIGEST_LENGTH - 1; i >= 0; --i)
	    hash.push_back(*(static_cast<uint8_t *>(static_cast<void *>(&temp)) + i));
    }
}

namespace pointers
{
    void hash(const uint8_t* data, const size_t size, uint8_t* hash, hash_type type)
    {
        switch(type)
        {
        case hash_type::SHA1:
            sha1_hash(data, size, hash);
            break;
	case hash_type::SHA256:
            sha256_hash(data, size, hash);
            break;
        case hash_type::SHA512:
            sha512_hash(data, size, hash);
            break;
        default:
            sha1_hash(data, size, hash);
            break;
        }
    }

    void sha1_hash(const uint8_t* data, const size_t size, uint8_t* hash)
    {
        SHA_CTX shactx;

        SHA1_Init(&shactx);
        SHA1_Update(&shactx, data, size);
        SHA1_Final(hash, &shactx);
    }



    void sha256_hash(const uint8_t* data, const size_t size, uint8_t* hash)
    {
	SHA256_CTX shactx;

        SHA256_Init(&shactx);
        SHA256_Update(&shactx, data, size);
        SHA256_Final(hash, &shactx);
    }



    void sha512_hash(const uint8_t* data, const size_t size, uint8_t* hash)
    {
	SHA512_CTX shactx;

	SHA512_Init(&shactx);
	SHA512_Update(&shactx, data, size);
	SHA512_Final(hash, &shactx);
    }

}
}
}
