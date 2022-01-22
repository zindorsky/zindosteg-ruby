#pragma once

#include "steg_defs.h"
#include <vector>
#include <memory>
#include <cstdint>
#include <exception>

namespace zindorsky {
namespace steganography {

class invalid_carrier : public std::runtime_error {
public:
	invalid_carrier() : std::runtime_error{"Invalid carrier file"} {}
	explicit invalid_carrier(char const* msg) : std::runtime_error{msg} {}
};

class provider_t {
public:
	//Loads from file.
	static std::unique_ptr<provider_t> load(filesystem::path const& file);
	//Loads from memory. Caller retains ownership of buffer.
	static std::unique_ptr<provider_t> load(void const* data, size_t size);

	static std::vector<std::string> supported_formats();

	using index_t = uint_fast64_t;

	virtual ~provider_t() {}

	virtual index_t size() const = 0;
	virtual byte & access_indexed_data(index_t index) = 0;
	virtual byte const& access_indexed_data( index_t index ) const = 0;
	virtual byte_vector commit_to_memory() = 0;
	virtual void commit_to_file(filesystem::path const& file) = 0;
	virtual byte_vector salt() const = 0;

};

}}	//namespace zindorsky::steganography
