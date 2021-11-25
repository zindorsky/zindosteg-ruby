#pragma once

#include <fstream>
#include <filesystem>
#include <vector>

namespace zindorsky {
namespace steganography {
namespace utils {

inline byte_vector load_from_file( std::filesystem::path const& filename )
{
	std::ifstream f(filename.c_str(), std::ios::binary | std::ios_base::in);
	std::streampos sz = f.seekg(0, std::ios::end).tellg();
	f.seekg(0, std::ios::beg);

	byte_vector buffer(static_cast<size_t>(sz));
	char *d = reinterpret_cast<char*>(buffer.data());
	size_t remaining = buffer.size();
	while(remaining > 0) {
		std::streamsize r = f.read(d, remaining).gcount();
		if (r < 0) { break; }
		d += static_cast<size_t>(r);
		remaining -= static_cast<size_t>(r);
	}
	return buffer;
}

inline void save_to_file( std::filesystem::path const& filename, byte_vector const& data )
{
	std::ofstream f(filename.c_str(), std::ios::binary | std::ios::out);
	f.write(reinterpret_cast<char const*>(data.data()), data.size());
}

}}}	//namespace zinodrsky::steganography::utils

