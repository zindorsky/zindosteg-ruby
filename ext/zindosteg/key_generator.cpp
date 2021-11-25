#include "key_generator.h"
#include <openssl/evp.h>

namespace zindorsky {
namespace crypto {

key_generator::key_generator(std::string const& password, byte_vector const & salt, int iterations)
	: password{password}
	, salt{salt}
	, iterations{iterations}
{
}

key_generator::key_generator(std::string const& password, byte const* salt, std::size_t salt_sz, int iterations)
	: password{password}
	, salt{salt,salt+salt_sz}
	, iterations{iterations}
{
}

void key_generator::generate(byte * key, std::size_t length) const
{
	PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), static_cast<int>(password.size()), salt.data(), static_cast<int>(salt.size()), iterations, static_cast<int>(length), key);
}

byte_vector key_generator::generate(std::size_t length) const
{
	byte_vector key(length);
	if(!key.empty()) {
		generate(&key[0],length);
	}
	return key;
}

}}	//namespace zindorsky::crypto

