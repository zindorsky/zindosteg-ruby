#pragma once

#include "steg_defs.h"
#include <openssl/aes.h>
#include <ios>

namespace zindorsky {
namespace crypto {

class aes {
public:
	aes(byte const* key, int keysize);
	void encrypt(byte const* in, byte * out) const;
	void decrypt(byte const* in, byte * out) const;
	void rekey(byte const* key, int keysize);

private:
	AES_KEY ekey_;
	AES_KEY dkey_;
};

class aes_ctr_mode {
public:
	aes_ctr_mode(byte const* key, int keysize, byte const* iv);
	void crypt(void const* in, void * out, size_t length);
	void seek(std::streampos pos);
	std::streampos tell() const { return pos_; }

private:
	aes key_;
	byte iv_[16], buff_[16];
	std::streampos pos_;
	size_t buffpos_;
};

}}	//namespace zindorsky::steganography
