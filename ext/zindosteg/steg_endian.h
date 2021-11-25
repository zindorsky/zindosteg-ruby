#pragma once

#include <string.h>

#if defined(_MSC_VER)

# include <stdlib.h>

# define bswap32(x) _byteswap_ulong(x)
# define bswap64(x) _byteswap_uint64(x)
# define LITTLE_ENDIAN 1

#elif defined(__GNUC__)

# if ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 3)))   //  __builtin_bswap first present in gcc 4.3
#  define bswap32(x)  __builtin_bswap32(x)
#  define bswap64(x)  __builtin_bswap64(x)
#elif defined(__clang__)
#  define bswap32(x)  __builtin_bswap32(x)
#  define bswap64(x)  __builtin_bswap64(x)
# else
#  define bswap32(x)  ( ((x)>>24) | (((x)>>8)&0xff00) | (((x)<<8)&0xff0000) | ((x)<<24) )
# endif

# if !defined(LITTLE_ENDIAN)
#  define LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
# endif

#endif

#if !defined(LITTLE_ENDIAN)
# error "Need LITTLE_ENDIAN defined"
#endif

#include <cstdint>

namespace zindorsky {
namespace endian {

inline void read_be( void const* src, std::uint32_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if LITTLE_ENDIAN
	dest = bswap32(dest);	
#endif
}

inline void write_be(std::uint32_t src, void * dest)
{
#if LITTLE_ENDIAN
	src = bswap32(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_be( void const* src, std::int32_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if LITTLE_ENDIAN
	dest = bswap32(dest);	
#endif
}

inline void write_be(std::int32_t src, void * dest)
{
#if LITTLE_ENDIAN
	src = bswap32(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_be( void const* src, std::uint64_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if LITTLE_ENDIAN
	dest = bswap64(dest);
#endif
}

inline void write_be(std::uint64_t src, void * dest)
{
#if LITTLE_ENDIAN
	src = bswap64(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_be( void const* src, std::int64_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if LITTLE_ENDIAN
	dest = bswap64(dest);
#endif
}

inline void write_be(std::int64_t src, void * dest)
{
#if LITTLE_ENDIAN
	src = bswap64(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_le( void const* src, std::uint32_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if !LITTLE_ENDIAN
	dest = bswap32(dest);	
#endif
}

inline void write_le(std::uint32_t src, void * dest)
{
#if !LITTLE_ENDIAN
	src = bswap32(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_le( void const* src, std::int32_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if !LITTLE_ENDIAN
	dest = bswap32(dest);	
#endif
}

inline void write_le(std::int32_t src, void * dest)
{
#if !LITTLE_ENDIAN
	src = bswap32(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_le( void const* src, std::uint64_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if !LITTLE_ENDIAN
	dest = bswap64(dest);
#endif
}

inline void write_le(std::uint64_t src, void * dest)
{
#if !LITTLE_ENDIAN
	src = bswap64(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

inline void read_le( void const* src, std::int64_t & dest)
{
	memcpy(&dest,src,sizeof(dest));
#if !LITTLE_ENDIAN
	dest = bswap64(dest);
#endif
}

inline void write_le(std::int64_t src, void * dest)
{
#if !LITTLE_ENDIAN
	src = bswap64(src);	
#endif
	memcpy(dest,&src,sizeof(src));
}

}}	//namespace zindorsky::endian
