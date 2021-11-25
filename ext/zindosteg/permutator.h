#pragma once

/* An implementation of the AES-FFX-A2 algorithm as a means to a low-memory, random-access, cryptographically-strong, index permutator.
See http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ffx/ffx-spec.pdf for the spec.
*/

#include "steg_defs.h"
#include <cstring>
#include "aes.h"
#include "key_generator.h"
#include <cstdint>

namespace zindorsky {
namespace permutator {

using index_t = uint_fast64_t;

class context {
public:
	context(index_t array_size, crypto::key_generator const& generator, int keylen = 16);
	context(index_t array_size, byte const* key, int keylen = 16);
	context(index_t array_size, crypto::aes const& key);

	index_t operator[] (index_t index) const;
	index_t reverse (index_t index) const;

private:
	using half_t = uint_fast32_t;

	index_t size_;
	crypto::aes key_;
	byte bitlen_, split_, rounds_;
	byte P_templ_[AES_BLOCK_SIZE];
	half_t split_mask_[2];

	half_t F(byte r, half_t B) const;
};

}}	//namespace zindorsky::permutator
