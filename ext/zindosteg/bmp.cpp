#include "bmp.h"
#include "steg_endian.h"
#include "file_utils.h"
#include <cstdint>

namespace zindorsky {
namespace steganography {

bmp_provider::bmp_provider( filesystem::path const& filename )
	: bmp_provider( utils::load_from_file(filename) )
{
}

bmp_provider::bmp_provider(byte const* data, size_t size)
	: bmp_provider( byte_vector(data, data+size) )
{
}

bmp_provider::bmp_provider(byte_vector const& data)
	: bmp_provider(data.data(), data.size())
{
}

bmp_provider::bmp_provider(byte_vector && data)
	: file_(std::move(data))
{
	if (file_.size() < 54) {
		throw invalid_carrier();
	}

	byte const* header = &file_[0];

	int bits_per_pixel = (int(header[29])<<8) | header[28];
	//only 24-bit BMPs for now (others use a palette, which makes steganography more difficult)
	if( bits_per_pixel != 24 ) {
		throw std::runtime_error("unsupported BMP format");
	}

	uint32_t data_offset, col_count, row_count;
	endian::read_le(&header[10], data_offset);
	endian::read_le(&header[18], col_count);
	endian::read_le(&header[22], row_count);

	row_sz_ = (col_count*bits_per_pixel + 7)/8;
	row_count_ = row_count;
	if( row_sz_ % 4 == 0 ) {
		slack_sz_ = 0;
	} else {
		slack_sz_ = 4 - row_sz_%4;
	}

	data_ = file_.data() + data_offset;
}

provider_t::index_t bmp_provider::size() const
{
	return row_sz_ * row_count_;
}

byte & bmp_provider::access_indexed_data( index_t index )
{
	return *(data_ + logical_to_physical(index));
}

byte const& bmp_provider::access_indexed_data( index_t index ) const
{
	return *(data_ + logical_to_physical(index));
}

byte_vector bmp_provider::commit_to_memory()
{
	return file_;
}

void bmp_provider::commit_to_file(filesystem::path const& file)
{
	utils::save_to_file(file, file_);
}

byte_vector bmp_provider::salt() const
{
	byte salt[8]={0};
	for(std::size_t i=0; i<row_count_; ++i) {
		salt[ i%sizeof(salt) ] += access_indexed_data(i*row_sz_ + i%row_sz_)>>1;
	}	

	return byte_vector(salt,salt+sizeof(salt));
}

std::size_t bmp_provider::logical_to_physical( provider_t::index_t index ) const
{
	if( slack_sz_ == 0 ) {
		return static_cast<std::size_t>(index);
	}
	std::size_t row = static_cast<std::size_t>(index / row_sz_), col = static_cast<std::size_t>(index % row_sz_);
	return row*(row_sz_+slack_sz_) + col;
}

}}	//namespace zindorsky::steganography

