#pragma once

#include "steg_defs.h"
#include <string>

namespace zindorsky {
namespace crypto {

class key_generator {
public:
	key_generator(std::string const& password, byte_vector const& salt, int iterations = 10000);
	key_generator(std::string const& password, byte const* salt, std::size_t salt_sz, int iterations = 10000);

	void generate(byte * key, std::size_t length) const;
	byte_vector generate(std::size_t length) const;

private:
	std::string password;
	byte_vector salt;
	int iterations;
};

}}	//namespace zindorsky::crypto
