#include "png_provider.h"
#include <exception>
#include "file_utils.h"

namespace zindorsky {
namespace steganography {

namespace {

struct read_context {
  read_context(byte const* data, size_t size) : data{data}, size{size} {}
  byte const*  data;
  size_t size;
  size_t pos = 0;
};

void read_data(png_structp png_ptr, png_bytep data, png_size_t length)
{
  auto source = reinterpret_cast<read_context*>(png_get_io_ptr(png_ptr));
  if (source->pos + length >= source->size) {
    length = source->size - source->pos;
  }
  memcpy(data, source->data + source->pos, length);
  source->pos += length;
}

void write_data(png_structp png_ptr, png_bytep data, png_size_t length)
{
  byte_vector* sink = reinterpret_cast<byte_vector*>(png_get_io_ptr(png_ptr));
  sink->insert(sink->end(), data, data + length);
}

void flush_data(png_structp)
{
}

} //namespace

const byte png_provider::signature[8] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};

png_provider::png_provider(std::filesystem::path const& filename)
    : png_provider( utils::load_from_file(filename) )
{
}

png_provider::png_provider(byte_vector const& data)
	: png_provider(data.data(), data.size())
{
}

png_provider::png_provider(byte const* data, size_t size)
{
  if(size < sizeof(signature) || memcmp(data, signature, sizeof(signature))!=0) {
    throw invalid_carrier();
  }

  ctx_ = std::make_unique<png_read_ctx>();
  if (setjmp(png_jmpbuf(ctx_->ptr))) {
    throw invalid_carrier();
  }

  read_context read_ctx{data, size};
  png_set_read_fn(ctx_->ptr, &read_ctx, read_data);

  png_read_info(ctx_->ptr, ctx_->info);

  width_ = png_get_image_width(ctx_->ptr, ctx_->info);
  height_ = png_get_image_height(ctx_->ptr, ctx_->info);
  bit_depth_ = png_get_bit_depth(ctx_->ptr, ctx_->info);
  color_type_ = png_get_color_type(ctx_->ptr, ctx_->info);

  if( (color_type_==0 && bit_depth_!=1 && bit_depth_!=2 && bit_depth_!=4 && bit_depth_!=8 && bit_depth_!=16)
      || ((color_type_==2 || color_type_==4 || color_type_==6) && bit_depth_!=8 && bit_depth_!=16)
      || (color_type_==3 &&bit_depth_!=1 && bit_depth_!=2 && bit_depth_!=4 && bit_depth_!=8)
    ) {
    throw invalid_carrier();
  }

  //We're going to disallow images with bit depth less than 8, since hidden data is more noticeable in them.
  if(bit_depth_ < 8) {
    throw invalid_carrier("PNG bit depth too small");
  }
  //Palette types are also not good for steganography:
  if(color_type_ & 1) {
    throw invalid_carrier("palette using PNG files not supported");
  }

  auto row_size = png_get_rowbytes(ctx_->ptr, ctx_->info);
  data_.resize(row_size * height_);
  row_pointers_.resize(height_);
  for(auto i = 0U; i < height_; ++i) {
    row_pointers_[i] = &data_[0] + i * row_size;
  }
  png_read_image(ctx_->ptr, &row_pointers_[0]);
}

provider_t::index_t png_provider::size() const
{
    return data_.size() / (bit_depth_ / 8);
}

byte & png_provider::access_indexed_data(provider_t::index_t index)
{
    return data_[adjust_index(index)];
}

byte const& png_provider::access_indexed_data(index_t index) const
{
    return data_[adjust_index(index)];
}

byte_vector png_provider::commit_to_memory()
{
	byte_vector data;
  png_write_ctx write_ctx;
  if (setjmp(png_jmpbuf(write_ctx.ptr))) {
    throw std::exception();
  }
  png_set_write_fn(write_ctx.ptr, &data, write_data, flush_data);
  write_ctx.copy_from_read(*ctx_);

  png_write_info(write_ctx.ptr, write_ctx.info);
  png_write_image(write_ctx.ptr, &row_pointers_[0]);
  png_write_end(write_ctx.ptr, nullptr);

	return data;
}

void png_provider::commit_to_file(std::filesystem::path const& file)
{
  FILE *f = fopen(file.string().c_str(), "wb");
  png_write_ctx write_ctx;
  if (setjmp(png_jmpbuf(write_ctx.ptr))) {
    if(f) fclose(f);
    throw std::exception();
  }
  png_init_io(write_ctx.ptr, f);
  write_ctx.copy_from_read(*ctx_);

  png_write_info(write_ctx.ptr, write_ctx.info);
  png_write_image(write_ctx.ptr, &row_pointers_[0]);
  png_write_end(write_ctx.ptr, nullptr);
  fclose(f);
}

byte_vector png_provider::salt() const
{
	byte salt[8]={0};
	for(std::size_t i=0; i<height_; ++i) {
		salt[ i%sizeof(salt) ] += access_indexed_data(i*width_ + i%width_)>>1;
	}	

	return byte_vector(salt,salt+sizeof(salt));
}

size_t png_provider::adjust_index(size_t index) const
{
    return index * (bit_depth_ / 8);
}


void png_write_ctx::copy_from_read(png_read_ctx const& read_ctx)
{
  std::uint32_t width, height;
  int bit_depth, color_type;
  int interlace_type, compression_type, filter_type;

  if (png_get_IHDR(read_ctx.ptr, read_ctx.info, &width, &height, &bit_depth, &color_type, &interlace_type, &compression_type, &filter_type))
    png_set_IHDR(ptr, info, width, height, bit_depth,
#if defined(PNG_WRITE_INTERLACING_SUPPORTED)
      color_type, interlace_type, compression_type, filter_type
#else
      color_type, PNG_INTERLACE_NONE, compression_type, filter_type
#endif
    );
#if defined(PNG_FIXED_POINT_SUPPORTED)
#if defined(PNG_cHRM_SUPPORTED)
   png_fixed_point white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
   if (png_get_cHRM_fixed(read_ctx.ptr, read_ctx.info, &white_x, &white_y, &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y))
     png_set_cHRM_fixed(ptr, info, white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y);
#endif
#if defined(PNG_gAMA_SUPPORTED)
   png_fixed_point gamma;
   if (png_get_gAMA_fixed(read_ctx.ptr, read_ctx.info, &gamma))
     png_set_gAMA_fixed(ptr, info, gamma);
#endif
#else /* Use floating point versions */
#if defined(PNG_FLOATING_POINT_SUPPORTED)
#if defined(PNG_cHRM_SUPPORTED)
   double white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
   if (png_get_cHRM(read_ctx.ptr, read_ctx.info, &white_x, &white_y, &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y))
     png_set_cHRM(ptr, info, white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y);
#endif
#if defined(PNG_gAMA_SUPPORTED)
   double gamma;
   if (png_get_gAMA(read_ctx.ptr, read_ctx.info, &gamma))
     png_set_gAMA(ptr, info, gamma);
#endif
#endif /* floating point */
#endif /* fixed point */
#if defined(PNG_iCCP_SUPPORTED)
   png_charp name;
   png_bytep profile;
   png_uint_32 proflen;
   if (png_get_iCCP(read_ctx.ptr, read_ctx.info, &name, &compression_type, &profile, &proflen))
     png_set_iCCP(ptr, info, name, compression_type, profile, proflen);
#endif
#if defined(PNG_sRGB_SUPPORTED)
   int intent;
   if (png_get_sRGB(read_ctx.ptr, read_ctx.info, &intent))
     png_set_sRGB(ptr, info, intent);
#endif
   png_colorp palette;
   int num_palette;
   if (png_get_PLTE(read_ctx.ptr, read_ctx.info, &palette, &num_palette))
     png_set_PLTE(ptr, info, palette, num_palette);
#if defined(PNG_bKGD_SUPPORTED)
   png_color_16p background;
   if (png_get_bKGD(read_ctx.ptr, read_ctx.info, &background))
     png_set_bKGD(ptr, info, background);
#endif
#if defined(PNG_hIST_SUPPORTED)
   png_uint_16p hist;
   if (png_get_hIST(read_ctx.ptr, read_ctx.info, &hist))
     png_set_hIST(ptr, info, hist);
#endif
#if defined(PNG_oFFs_SUPPORTED)
   png_int_32 offset_x, offset_y;
   int unit_type;
   if (png_get_oFFs(read_ctx.ptr, read_ctx.info,&offset_x,&offset_y,&unit_type))
     png_set_oFFs(ptr, info, offset_x, offset_y, unit_type);
#endif
#if defined(PNG_pCAL_SUPPORTED)
   png_charp purpose, units;
   png_charpp params;
   png_int_32 X0, X1;
   int type, nparams;

   if (png_get_pCAL(read_ctx.ptr, read_ctx.info, &purpose, &X0, &X1, &type, &nparams, &units, &params))
     png_set_pCAL(ptr, info, purpose, X0, X1, type, nparams, units, params);
#endif
#if defined(PNG_pHYs_SUPPORTED)
   png_uint_32 res_x, res_y;
   if (png_get_pHYs(read_ctx.ptr, read_ctx.info, &res_x, &res_y, &unit_type))
     png_set_pHYs(ptr, info, res_x, res_y, unit_type);
#endif
#if defined(PNG_sBIT_SUPPORTED)
   png_color_8p sig_bit;

   if (png_get_sBIT(read_ctx.ptr, read_ctx.info, &sig_bit))
     png_set_sBIT(ptr, info, sig_bit);
#endif
#if defined(PNG_sCAL_SUPPORTED)
#ifdef PNG_FLOATING_POINT_SUPPORTED
   int unit;
   double scal_width, scal_height;

   if (png_get_sCAL(read_ctx.ptr, read_ctx.info, &unit, &scal_width, &scal_height))
     png_set_sCAL(ptr, info, unit, scal_width, scal_height);
#else
#ifdef PNG_FIXED_POINT_SUPPORTED
   int unit;
   png_charp scal_width, scal_height;

   if (png_get_sCAL_s(read_ctx.ptr, read_ctx.info, &unit, &scal_width, &scal_height))
     png_set_sCAL_s(ptr, info, unit, scal_width, scal_height);
#endif
#endif
#endif
#if defined(PNG_TEXT_SUPPORTED)
   png_textp text_ptr;
   int num_text;
   if (png_get_text(read_ctx.ptr, read_ctx.info, &text_ptr, &num_text) > 0)
     png_set_text(ptr, info, text_ptr, num_text);
#endif
#if defined(PNG_tIME_SUPPORTED)
   png_timep mod_time;

   if (png_get_tIME(read_ctx.ptr, read_ctx.info, &mod_time)) {
     png_set_tIME(ptr, info, mod_time);
   }
#endif
#if defined(PNG_tRNS_SUPPORTED)
   png_bytep trans;
   int num_trans;
   png_color_16p trans_values;
   if (png_get_tRNS(read_ctx.ptr, read_ctx.info, &trans, &num_trans, &trans_values))
     png_set_tRNS(ptr, info, trans, num_trans, trans_values);
#endif
#if defined(PNG_WRITE_UNKNOWN_CHUNKS_SUPPORTED)
   png_unknown_chunkp unknowns;
   int num_unknowns = (int)png_get_unknown_chunks(read_ctx.ptr, read_ctx.info, &unknowns);
   if (num_unknowns) {
     png_size_t i;
     png_set_unknown_chunks(ptr, info, unknowns, num_unknowns);
     for (i = 0; i < num_unknowns; i++)
       png_set_unknown_chunk_location(ptr, info, i, unknowns[i].location);
   }
#endif
}

}}   //namespace

