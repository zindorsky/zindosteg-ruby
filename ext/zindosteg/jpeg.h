#pragma once

#include "provider.h"
#include <exception>
#include "jpeg_helpers.h"

namespace zindorsky {
namespace steganography {

class jpeg_provider : public provider_t {
public:
	explicit jpeg_provider( filesystem::path const& filename );
    explicit jpeg_provider(byte_vector const& data);
    explicit jpeg_provider(byte_vector && data);
    jpeg_provider(byte const* data, size_t size);
	//Movable:
	jpeg_provider(jpeg_provider &&) = default;
	jpeg_provider & operator = (jpeg_provider &&) = default;
	
	static std::string format() { return "JPG"; }

	virtual index_t size() const override;
	virtual byte & access_indexed_data( index_t index ) override;
	virtual byte const& access_indexed_data( index_t index ) const override;
	virtual byte_vector commit_to_memory() override;
	virtual void commit_to_file(filesystem::path const& file) override;
	virtual byte_vector salt() const override;

private:
	jpeg::decompress_ctx jinfo_;

	std::size_t component_count_;
	std::vector<std::size_t> wib_, hib_, comp_sz_;
	index_t sz_;

	void index_to_coordinates(index_t index, std::size_t & comp, std::size_t & row, std::size_t & col, std::size_t & block) const;
};

}}	//namespace zindorsky::steganography
