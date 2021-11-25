#include "jpeg_helpers.h"
#include "file_utils.h"

extern "C" void jpeglib_error_handler(j_common_ptr info)
{
	if(info) {
		jpeg_abort(info);
	}
	//can't throw in extern "C" functions.
//	throw steganography::jpeg::jpeg_exception(); 
}

namespace zindorsky {
namespace steganography {
namespace jpeg {

decompress_ctx::decompress_ctx( std::filesystem::path const& filename )
	: decompress_ctx( utils::load_from_file(filename) )
{
}

decompress_ctx::decompress_ctx(byte const* data, size_t size)
	: decompress_ctx( byte_vector(data, data+size) ) 
{
}

decompress_ctx::decompress_ctx(byte_vector const& data)
	: decompress_ctx(data.data(), data.size())
{
}

decompress_ctx::decompress_ctx(byte_vector && data)
	: data_(std::move(data))
{
	info_.err = jpeg_std_error(&err_mgr_);
	err_mgr_.error_exit = jpeglib_error_handler;

	jpeg_create_decompress(&info_);
	//save markers for writing later
	jpeg_save_markers(&info_,JPEG_COM,0xffff);
	for(int i=1; i<=15; ++i) {
		jpeg_save_markers(&info_,JPEG_APP0+i,0xffff);
	}

	try {
		jpeg_mem_src(&info_, data_.data(), static_cast<unsigned long>(data_.size()));
		jpeg_read_header(&info_,TRUE);
		coeff_ = jpeg_read_coefficients(&info_);
		if(!coeff_) {
			throw jpeg_exception();
		}
	} catch(...) {
		jpeg_destroy_decompress(&info_);
		throw;
	}
}

decompress_ctx::decompress_ctx(decompress_ctx && rhs)
	: data_( std::move(rhs.data_) )
	, err_mgr_( std::move(rhs.err_mgr_) )
	, info_{0}
	, coeff_( std::move(rhs.coeff_) )
{
	std::swap(info_, rhs.info_);
}

decompress_ctx & decompress_ctx::operator = (decompress_ctx && rhs)
{
	data_ = std::move(rhs.data_);
	err_mgr_ = std::move(rhs.err_mgr_);
	std::swap(info_, rhs.info_);
	coeff_ = std::move(rhs.coeff_);
	return *this;
}

decompress_ctx::~decompress_ctx()
{
	if (info_.src) {
		jpeg_destroy_decompress(&info_);
	}
}

void decompress_ctx::save_to_file( std::filesystem::path const& filename )
{
	FILE* file = ::fopen( filename.c_str(), "wb" );
	if(!file) {
		throw std::ios_base::failure("file open fail");
	}

	jpeg_error_mgr err_mgr;
	jpeg_compress_struct info;

	info.err = jpeg_std_error(&err_mgr);
	err_mgr.error_exit = jpeglib_error_handler;

	jpeg_create_compress(&info);
	info.optimize_coding = TRUE;

	jpeg_stdio_dest(&info, file);

	jpeg_copy_critical_parameters(object(), &info);
	jpeg_write_coefficients(&info, coefficients());
	//copy markers and comments
	for(jpeg_saved_marker_ptr curr=object()->marker_list; curr; curr=curr->next) {
		if(curr->data && curr->data_length>0)
			jpeg_write_marker(&info, curr->marker, curr->data, curr->data_length);
	}
	jpeg_finish_compress(&info);
	jpeg_destroy_compress(&info);
	::fclose(file);
}

byte_vector decompress_ctx::save_to_memory()
{
	byte *mem = nullptr;
	unsigned long memsz = 0;

	jpeg_error_mgr err_mgr;
	jpeg_compress_struct info;

	info.err = jpeg_std_error(&err_mgr);
	err_mgr.error_exit = jpeglib_error_handler;

	jpeg_create_compress(&info);
	info.optimize_coding = TRUE;

	jpeg_mem_dest(&info, &mem, &memsz);

	jpeg_copy_critical_parameters(object(), &info);
	jpeg_write_coefficients(&info, coefficients());
	//copy markers and comments
	for(jpeg_saved_marker_ptr curr=object()->marker_list; curr; curr=curr->next) {
		if(curr->data && curr->data_length>0)
			jpeg_write_marker(&info, curr->marker, curr->data, curr->data_length);
	}
	jpeg_finish_compress(&info);
	jpeg_destroy_compress(&info);

	if (mem && memsz) {
		byte_vector result{ mem, mem + memsz };
		::free(mem);
		return result;
	}

	return{};
}

}}}	//namespace zindorsky::steganography::jpeg

