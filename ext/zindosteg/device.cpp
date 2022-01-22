#include "device.h"
#include <cassert>
#include "steg_endian.h"

namespace zindorsky {
namespace steganography {

enum { max_length_sz = 9, nybble_span = 15, byte_span = nybble_span*2, };

device_t::device_t( filesystem::path const& carrier_file, std::string const& password, bool open_existing_payload, bool throw_on_open_existing_fail )
	: device_t( provider_t::load(carrier_file), password, open_existing_payload, throw_on_open_existing_fail )
{
	carrier_file_ = carrier_file;
}

device_t::device_t( std::unique_ptr<provider_t> provider, std::string const& password, bool open_existing_payload, bool throw_on_open_existing_fail )
	: provider_( std::move(provider) )
	, shuffler_(provider_->size() / nybble_span, crypto::key_generator(password,provider_->salt()))
	, max_sz_( provider_->size() / byte_span - max_length_sz )
	, payload_sz_( 0 )
	, pos_(0)
	, dirty_(false)
{
	if (!provider_) {
		throw invalid_carrier();
	}

	if( max_sz_ <= 0 ) {
		throw payload_extraction_error();
	}
	if( open_existing_payload ) {
		payload_sz_ = read_payload_length(throw_on_open_existing_fail);
	}
	if( payload_sz_ > max_sz_ ) {
		if (throw_on_open_existing_fail) {
			throw payload_extraction_error();
		} else {
			payload_sz_ = 0;
		}
	}
}

std::streamsize device_t::read(char * s, std::streamsize n)
{
	if(!s || n<=0) {
		return 0;
	}
	if( pos_ >= payload_sz_ ) {
		return std::char_traits<char_type>::eof();
	}
	std::streamsize r=0;
	while(n > 0 && pos_ < payload_sz_) {
		*s = static_cast<char>(get_byte(pos_));
		++s;
		pos_ += 1;
		++r;
		--n;
	}
	return r;
}

std::streamsize device_t::write(char const* s, std::streamsize n)
{
	if(!s || n<=0) {
		return 0;
	}
	if( pos_ >= max_sz_ ) {
		return std::char_traits<char_type>::eof();
	}
	std::streamsize r=0;
	while(n > 0 && pos_ < max_sz_) {
		byte b = static_cast<byte>(*s);
		put_byte(b,pos_);
		++s;
		pos_ += 1;
		++r;
		--n;
	}
	if( pos_ > payload_sz_ ) {
		payload_sz_ = pos_;
		dirty_ = true;
	}
	return r;
}

std::streampos device_t::seek(std::streamoff off, std::ios::seekdir way)
{
	std::streampos newpos;
	switch(way) {
	case std::ios::cur: newpos = pos_; break;
	case std::ios::end: newpos = payload_sz_; break;
	default: newpos = 0; break;
	}
	newpos += off;
	if( newpos < 0 ) {
		throw std::ios::failure("underseek");
	}
	if( newpos > max_sz_ ) {
		newpos = max_sz_;
	}
	return pos_ = newpos;
}

void device_t::close()
{
	if (dirty_ && !carrier_file_.empty()) {
		write_to_file(carrier_file_);
		dirty_ = false;
	}
}

void device_t::flush()
{
	if (dirty_ && !carrier_file_.empty()) {
		write_to_file(carrier_file_);
		dirty_ = false;
	}
}

void device_t::write_to_file(filesystem::path const& outfile)
{
	if (dirty_) {
		write_payload_length();
	}
	provider_->commit_to_file(outfile);
	dirty_ = false;
}

byte_vector device_t::write_to_memory()
{
	if (dirty_) {
		write_payload_length();
	}
	dirty_ = false;
	return provider_->commit_to_memory();
}

byte device_t::get_byte(std::streampos const& pos, provider_t::index_t * lo_start, provider_t::index_t * hi_start) const
{
	assert( pos < max_sz_ + max_length_sz );

	provider_t::index_t index = shuffler_[pos*2]*nybble_span;
	if(lo_start) { *lo_start = index; }

	byte cl=0;
	for(byte i=1; i<=nybble_span; ++i) {
		if( provider_->access_indexed_data( index++ ) & 1 ) {
			cl ^= i;
		}
	}

	index = shuffler_[pos*2+1]*nybble_span;
	if(hi_start) { *hi_start = index; }

	byte ch=0;
	for(byte i=1; i<=nybble_span; ++i) {
		if( provider_->access_indexed_data( index++ ) & 1 ) {
			ch ^= i;
		}
	}
	return (ch<<4)|cl;
}

void device_t::put_byte(byte b, std::streampos const& pos)
{
	assert( pos < max_sz_ + max_length_sz );

	provider_t::index_t lo_start, hi_start;
	byte c = get_byte(pos,&lo_start,&hi_start);
	byte cl = c&15, ch = c>>4, bl = b&15, bh = b>>4;
	if(bl != cl) {
		provider_->access_indexed_data( lo_start + (bl^cl) - 1 ) ^= 1;
		dirty_ = true;
	}
	if(bh != ch) {
		provider_->access_indexed_data( hi_start + (bh^ch) - 1 ) ^= 1;
		dirty_ = true;
	}
}

std::streamsize device_t::truncate()
{
    if(payload_sz_ != pos_) {
        dirty_ = true;
    }
	return payload_sz_ = pos_;
}

std::streamsize device_t::read_payload_length(bool throw_on_fail) const
{
	std::streampos pos = max_sz_+max_length_sz-1;
	std::streamsize sz = 0;
	unsigned int shift=0;
	byte b;
	do {
		if(shift+7 > sizeof(std::streampos)*8) {
			if (throw_on_fail) {
				throw payload_extraction_error();
			} else {
				return 0;
			}
		}
		b = get_byte(pos);
		pos -= 1;
		sz |= static_cast<std::streampos>(b&0x7f)<<shift;
		shift += 7;
	} while(b&0x80);

	return sz;
}

void device_t::write_payload_length()
{
	if (payload_sz_ < 0) {
		throw payload_extraction_error();
	}
	std::streampos pos = max_sz_+max_length_sz-1;
	std::streamsize sz = payload_sz_;
	do {
		byte b = static_cast<byte>( sz&0x7f );
		sz >>= 7;
		if( sz > 0 ) {
			b |= 0x80;
		}
		put_byte(b,pos);
		pos -= 1;
	} while( sz>0 );
}

byte_vector device_t::salt_for_encryption() const
{
	if (!provider_) {
		return{};
	}
	byte_vector salt = provider_->salt();
	//Though it's probably fine, for safety, make the salt different than the salt used by the shuffler.
	if(!salt.empty()) {
		salt.front() += 1;
	}
	return salt;
}

}}	//namespace zindorsky::steganography

