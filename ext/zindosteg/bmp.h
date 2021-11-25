#pragma once

#include "provider.h"
#include <vector>

namespace zindorsky {
namespace steganography {

class bmp_provider : public provider_t {
public:
	explicit bmp_provider( std::filesystem::path const& filename );
	bmp_provider(byte const* data, size_t size);
	explicit bmp_provider(byte_vector const& data);
	explicit bmp_provider(byte_vector && data);
	//Copyable
	bmp_provider(bmp_provider const&) = default;
	bmp_provider & operator = (bmp_provider const&) = default;
	//Movable
	bmp_provider(bmp_provider &&) = default;
	bmp_provider & operator = (bmp_provider &&) = default;

	static std::string format() { return "BMP"; }

	virtual index_t size() const override;
	virtual byte & access_indexed_data( index_t index ) override;
	virtual byte const& access_indexed_data( index_t index ) const override;
	virtual byte_vector commit_to_memory() override;
	virtual void commit_to_file(std::filesystem::path const& file) override;
	virtual byte_vector salt() const override;

private:
	byte_vector file_;
	byte *data_;
	std::size_t row_sz_, row_count_, slack_sz_; 

	std::size_t logical_to_physical( index_t index ) const;
};

}}	//namespace zindorsky::steganography
