#include <fstream>
#include "provider.h"
//Currently implemented providers:
#include "bmp.h"
#include "jpeg.h"
#include "png_provider.h"

namespace zindorsky {
namespace steganography {

namespace {
	const size_t min_header_sz = 0x40;
}

std::unique_ptr<provider_t> provider_t::load(filesystem::path const& file)
{
	std::ifstream source(file.c_str());
	//read first few bytes for header
	byte header[min_header_sz];
	source.read(reinterpret_cast<char*>(header),sizeof(header));
	source.close();
	
	if( header[0]=='B' && header[1]=='M' ) {
		return std::make_unique<bmp_provider>( file );
	}
	if( header[0]==0xff && header[1]==0xd8 && header[2]==0xff
		&& (memcmp(&header[6],"JFIF",4)==0 || memcmp(&header[6],"Exif",4)==0) )
	{
		return std::make_unique<jpeg_provider>( file );
	}
    if( memcmp(header, png_provider::signature, sizeof(png_provider::signature)) == 0 ) {
        return std::make_unique<png_provider>(file);
    }

	throw invalid_carrier{};
}

std::unique_ptr<provider_t> provider_t::load(void const* data, size_t size)
{
	byte const* d = static_cast<byte const*>(data);

	if (!d || size < min_header_sz) {
		throw invalid_carrier{};
	}

	if( d[0]=='B' && d[1]=='M' ) {
		return std::make_unique<bmp_provider>( d, size );
	}
	if( d[0]==0xff && d[1]==0xd8 && d[2]==0xff
		&& (memcmp(&d[6],"JFIF",4)==0 || memcmp(&d[6],"Exif",4)==0) )
	{
		return std::make_unique<jpeg_provider>( d, size );
	}
    if( memcmp(data, png_provider::signature, sizeof(png_provider::signature))==0 ) {
        return std::make_unique<png_provider>(d, size);
    }

	throw invalid_carrier{};
}

std::vector<std::string> provider_t::supported_formats()
{
	return{ 
		bmp_provider::format()
		, jpeg_provider::format()
		, png_provider::format()
	};
}

}}	//namespace zindorsky::steganography

