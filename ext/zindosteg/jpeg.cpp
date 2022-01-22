#include "jpeg.h"
#include "steg_endian.h"
#include "file_utils.h"
#include <stdexcept>

namespace zindorsky {
namespace steganography {

jpeg_provider::jpeg_provider( filesystem::path const& filename )
	: jpeg_provider( utils::load_from_file(filename) )
{
}

jpeg_provider::jpeg_provider(byte_vector const& data)
	: jpeg_provider(data.data(), data.size())
{
}

jpeg_provider::jpeg_provider(byte const* data, size_t size)
	: jpeg_provider( byte_vector(data, data+size) )
{
}

jpeg_provider::jpeg_provider(byte_vector && data)
	: jinfo_(std::move(data))
	, component_count_(0)
	, sz_(0)
{
	component_count_ = static_cast<std::size_t>( jinfo_.object()->num_components );
	wib_.resize(component_count_);
	hib_.resize(component_count_);
	comp_sz_.resize(component_count_);
	for(std::size_t i=0; i<component_count_; ++i) {
		wib_[i] = static_cast<std::size_t>( jinfo_.object()->comp_info[i].width_in_blocks );
		hib_[i] = static_cast<std::size_t>( jinfo_.object()->comp_info[i].height_in_blocks );
		comp_sz_[i] = wib_[i]*hib_[i]*DCTSIZE2;
		sz_ += comp_sz_[i];
	}
}

provider_t::index_t jpeg_provider::size() const
{
	return sz_;
}

#if LITTLE_ENDIAN
# define INT16_LSB 0
#else
# define INT16_LSB 1
#endif

byte & jpeg_provider::access_indexed_data( provider_t::index_t index )
{
	std::size_t comp, row, col, block;
	index_to_coordinates(index,comp,row,col,block);
	JBLOCKARRAY rowblock = (*jinfo_.object()->mem->access_virt_barray)( (j_common_ptr)jinfo_.object(), jinfo_.coefficients()[comp], (JDIMENSION)row, 1, TRUE);
	return reinterpret_cast<byte*>( &rowblock[0][col][block] )[ INT16_LSB ];
}

byte const& jpeg_provider::access_indexed_data( provider_t::index_t index ) const
{
	std::size_t comp, row, col, block;
	index_to_coordinates(index,comp,row,col,block);
	JBLOCKARRAY rowblock = (*jinfo_.object()->mem->access_virt_barray)( (j_common_ptr)jinfo_.object(), jinfo_.coefficients()[comp], (JDIMENSION)row, 1, FALSE);
	return reinterpret_cast<byte const*>( &rowblock[0][col][block] )[ INT16_LSB ];
}

byte_vector jpeg_provider::commit_to_memory()
{
	return jinfo_.save_to_memory();
}

void jpeg_provider::commit_to_file(filesystem::path const& file)
{
	jinfo_.save_to_file(file);
}

byte_vector jpeg_provider::salt() const
{
	byte salt[8] = {0};
	std::size_t salt_index=0;

	for(std::size_t i=0; i<component_count_; ++i) {
		for(std::size_t j=0; j<hib_[i]; ++j) {
			JBLOCKARRAY rowblock = (*jinfo_.object()->mem->access_virt_barray)( (j_common_ptr)jinfo_.object(), jinfo_.coefficients()[i], (JDIMENSION)j, 1, FALSE);
			salt[ salt_index++ % sizeof(salt) ] += static_cast<byte>( rowblock[0][j%wib_[i]][j%DCTSIZE2]>>1 );
		}
	}

	return byte_vector(salt, salt+sizeof(salt));
}

void jpeg_provider::index_to_coordinates(provider_t::index_t index, std::size_t & comp, std::size_t & row, std::size_t & col, std::size_t & block) const
{
	if(index >= sz_) { throw std::out_of_range("index out of range"); }
	for(comp=0; comp<component_count_; ++comp) {
		if( index < comp_sz_[comp] ) {
			break;
		}
		index -= comp_sz_[comp];
	}
	if(comp==component_count_) { throw std::logic_error("computed sizes incorrect"); }
	
	std::size_t rowsz = wib_[comp] * DCTSIZE2;
	row = index / rowsz;
	col = (index % rowsz) / DCTSIZE2;
	block = index % DCTSIZE2;
}

}}	//namespace zindorsky::steganography 

