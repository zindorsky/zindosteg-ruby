#ifndef steganography_jpeg_helpers_h_included
#define steganography_jpeg_helpers_h_included

#include "steg_defs.h"
#include <cstdio>
#include <jpeglib.h>
#include <vector>

//error handling callback for jpeg lib
extern "C" void jpeglib_error_handler(j_common_ptr);

namespace zindorsky {
namespace steganography {
namespace jpeg {

class jpeg_exception : public std::runtime_error {
public:
	jpeg_exception() : std::runtime_error("JPEG file error") {}
};

class decompress_ctx {
public:
	explicit decompress_ctx( filesystem::path const& filename );
	decompress_ctx(byte const* data, size_t size);
	explicit decompress_ctx(byte_vector const& data);
	explicit decompress_ctx(byte_vector && data);

	//Non-copyable
	decompress_ctx(decompress_ctx const&) = delete;
	decompress_ctx & operator = (decompress_ctx const&) = delete;
	//Movable
	decompress_ctx(decompress_ctx &&);
	decompress_ctx & operator = (decompress_ctx &&);
	~decompress_ctx();
	
	jpeg_decompress_struct * object() { return &info_; }
	jpeg_decompress_struct const* object() const { return &info_; }

	jvirt_barray_ptr* coefficients() const { return coeff_; }

	void save_to_file( filesystem::path const& filename );
	byte_vector save_to_memory();

private:
	byte_vector data_;
	jpeg_error_mgr err_mgr_;
	jpeg_decompress_struct info_;
	jvirt_barray_ptr *coeff_;
};

}}}	//namespace zindorsky::steganography::jpeg

#endif //include guard

