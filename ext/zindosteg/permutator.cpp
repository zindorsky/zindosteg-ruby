#include "./permutator.h"
#include <openssl/evp.h>
#include "steg_endian.h"
#include <algorithm>

namespace zindorsky {
namespace permutator {

namespace {
	struct key_cstr_helper {
		key_cstr_helper(crypto::key_generator const& generator, size_t len)
			: key(len)
		{
			generator.generate(key.data(), key.size());
		}

		byte_vector key;
	};
}	//namespace

context::context(index_t array_size, crypto::key_generator const& generator, int keylen)
	: context{array_size, key_cstr_helper{generator, static_cast<size_t>(keylen)}.key.data(), keylen}
{
}

context::context(index_t array_size, byte const* key, int keylen)
	: context{array_size, crypto::aes{key, keylen}}
{
}

context::context(index_t array_size, crypto::aes const& key)
	: size_{array_size}
	, key_{key}
{
	for(bitlen_=0; array_size!=0; ++bitlen_) 
		array_size >>= 1;
	split_ = bitlen_/2;
	split_mask_[0] = (1<<split_)-1;
	split_mask_[1] = (1<<((bitlen_+1)/2))-1;

	if( bitlen_ <= 9 ) {
		rounds_ = 36;
	} else if( bitlen_ <= 13 ) {
		rounds_ = 30;
	} else if( bitlen_ <= 19 ) {
		rounds_ = 24;
	} else if( bitlen_ <= 31 ) {
		rounds_ = 18;
	} else {
		rounds_ = 12;
	}

	//Pre-compute AES(P)
	//VERS
	P_templ_[0] = 0; P_templ_[1]=1;
	//method
	P_templ_[2] = 2;
	//addition
	P_templ_[3] = 0;
	//radix
	P_templ_[4] = 2;
	//n
	P_templ_[5] = bitlen_;
	//split(n)
	P_templ_[6] = split_;
	//rnds(n)
	P_templ_[7] = rounds_;
	//tweak length (no tweak in this implementation)
	std::fill_n(&P_templ_[8], 8, 0);
	key_.encrypt(P_templ_,P_templ_);
}

//AES-FFX-A2 encrypt
index_t context::operator[] (index_t index) const
{
	half_t A = static_cast<half_t>( index & split_mask_[0] );
	half_t B = static_cast<half_t>( index >> split_ );

	for(byte i=0; i<rounds_; ++i) {
		half_t C = A ^ F(i,B);
		A = B;
		B = C;
	}

	index_t retval = (static_cast<index_t>(B)<<split_) | static_cast<index_t>(A);

	//Chain-walking:
	if( retval >= size_ ) {
		return operator[](retval);
	}
	return retval;
}

//AES-FFX-A2 decrypt
index_t context::reverse(index_t index) const
{
	half_t A = static_cast<half_t>( index & split_mask_[0] );
	half_t B = static_cast<half_t>( index >> split_ );

	for(byte i=rounds_; i>0; --i) {
		half_t C = B;
		B = A;
		A = C ^ F(i-1,B);
	}

	index_t retval = (static_cast<index_t>(B)<<split_) | static_cast<index_t>(A);

	//Chain-walking:
	if( retval >= size_ ) {
		return reverse(retval);
	}
	return retval;
}

context::half_t context::F(byte r, half_t B) const
{
	byte Q[AES_BLOCK_SIZE] = {0};
	//Fill out Q. (No tweak in this implementation.)
	Q[7] = r;
	endian::write_be(B,&Q[sizeof(Q)-sizeof(B)]);
	for(std::size_t i=0; i<sizeof(Q); ++i) {
		Q[i] ^= P_templ_[i];	
	}
	key_.encrypt(Q,Q);
	endian::read_be(&Q[sizeof(Q)-sizeof(B)],B);
	return B & split_mask_[r%2];
}

}}	//namespace zindorsky::permutator
