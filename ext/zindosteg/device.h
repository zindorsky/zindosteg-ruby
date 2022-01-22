#pragma once

#include <ios>
#include "provider.h"
#include "permutator.h"
#include <stdexcept>
#include "steg_defs.h"

namespace zindorsky {
namespace steganography {

class payload_extraction_error : public std::runtime_error {
public:
	payload_extraction_error() : std::runtime_error{"invalid payload data"} {}
};

class device_t {
public:
  using char_type = char;

	//If "open_existing_payload" is true, a check will be made for a valid payload length (and possibly other parameters).
	//If the check fails then if throw_on_open_existing_fail is true a payload_extraction_error exception will be thrown. If throw_on_open_existing_fail is false, the intitial size will be set to zero.
	//If "open_existing_payload" is false, no check will be made and a new length will be written when the device is closed.
	device_t(filesystem::path const& carrier_file, std::string const& password, bool open_existing_payload, bool throw_on_open_existing_fail = true);
	//Takes ownership of provider:
	device_t(std::unique_ptr<provider_t> provider, std::string const& password, bool open_existing_payload, bool throw_on_open_existing_fail = true);

	//Non-copyable
	device_t(device_t const&) = delete;
	device_t & operator = (device_t const&) = delete;
	//Movable
	device_t( device_t && ) = default;
	device_t & operator = (device_t &&) = default;

	// I/O streams seekable, closable interface:
	std::streamsize read(char * s, std::streamsize n);
	std::streamsize write(char const* s, std::streamsize n);
	std::streampos seek(std::streamoff off, std::ios::seekdir way);
	void close();

	//Not part of the I/O streams interface, but sometimes handy:
	std::streamsize size() const { return payload_sz_; }
	std::streamsize capacity() const { return max_sz_; }
	std::streamsize truncate(); //sets eof to current position
	void flush();

	void write_to_file(filesystem::path const& outfile);
	byte_vector write_to_memory();

	//Returns salt derived from the carrier.
	byte_vector salt_for_encryption() const;

private:
	std::unique_ptr<provider_t>  provider_;
	filesystem::path carrier_file_;
	permutator::context shuffler_;
	std::streamsize max_sz_, payload_sz_;
	std::streampos pos_;
	bool dirty_;

	byte get_byte(std::streampos const& pos, provider_t::index_t * lo_start = 0, provider_t::index_t * hi_start = 0) const;
	void put_byte(byte b, std::streampos const& pos);

	std::streamsize read_payload_length(bool throw_on_fail = true) const;
	void write_payload_length();

};

}}	//namespace zindorsky::steganography
