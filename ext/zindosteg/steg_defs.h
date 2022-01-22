#pragma once

#include <vector>
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 9
# define EXPERIMENTAL_FILESYSTEM
# include <experimental/filesystem>
#else
# include <filesystem>
#endif

namespace zindorsky {

using byte = unsigned char;
using byte_vector = std::vector<byte>;

#if defined(EXPERIMENTAL_FILESYSTEM)
# include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#else
# include <filesystem>
namespace filesystem = std::filesystem;
#endif

} // namespace zindorsky
