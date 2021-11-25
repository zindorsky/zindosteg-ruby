#include "./aes.h"
#include <string.h>
#include <algorithm>
#include "steg_endian.h"

namespace zindorsky {
namespace crypto {

aes::aes(byte const* key, int keysize) { rekey(key,keysize); }
void aes::encrypt(byte const* in, byte * out) const { AES_encrypt(in,out,&ekey_); }
void aes::decrypt(byte const* in, byte * out) const { AES_decrypt(in,out,&dkey_); }
void aes::rekey(byte const* key, int keysize) { AES_set_encrypt_key(key,keysize*8,&ekey_); AES_set_decrypt_key(key,keysize*8,&dkey_); }

namespace {

void add128(byte * a, int p)
{
	std::int64_t a0,a1;
	endian::read_be(a+8,a0);
	a1 = a0+p;
	endian::write_be(a1,a+8);
	if( (p<0 && a1>a0) || (p>0 && a1<a0) ) {
		endian::read_be(a,a0);
		endian::write_be(a0+(p<0?-1:1),a);
	}
}

}	//namespace

aes_ctr_mode::aes_ctr_mode(byte const* key, int keysize, byte const* iv)
	: key_(key,keysize)
	, pos_(0)
	, buffpos_(0)
{
	memcpy(iv_,iv,sizeof(iv_));
	key_.encrypt(iv_,buff_);
}

void aes_ctr_mode::crypt(void const* inv, void * outv, size_t length)
{
    byte const* in = static_cast<byte const*>(inv);
    byte * out = static_cast<byte *>(outv);
	while(length > 0) {
		size_t todo = std::min(length, 16-buffpos_);
		for(size_t i=0; i<todo; ++i) {
			*out++ = *in++ ^ buff_[buffpos_++];
		}
		length -= todo;
		pos_ += todo;
		if(buffpos_ >= 16) {
			for(int i=15; i>=0; --i) {
				if( ++iv_[i] != 0 ) {
					break;
				}
			}
			buffpos_ = 0;
			key_.encrypt(iv_,buff_);
		}
	}
}

void aes_ctr_mode::seek(std::streampos pos)
{
	auto block = pos_/16, newblock = pos/16;
	buffpos_ = static_cast<size_t>(pos)%16;
	if(block != newblock) {
		add128(iv_,static_cast<int>(newblock-block));
		key_.encrypt(iv_,buff_);
	}
	pos_ = pos;
}

}}	//namespace zindorsky::crypto
