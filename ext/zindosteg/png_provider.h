#pragma once

#include "provider.h"
#include <vector>
#include <cstdint>
#include <png.h>
#include <memory>

namespace zindorsky {
  namespace steganography {

    struct png_read_ctx {
      png_structp ptr = nullptr;
      png_infop info = nullptr;

      png_read_ctx()
      {
        ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
        if (ptr) {
          info = png_create_info_struct(ptr);
        }
      }

      ~png_read_ctx()
      {
        if(ptr) {
          png_destroy_read_struct(&ptr, info ? &info : nullptr, nullptr);
        }
      }
    };

    struct png_write_ctx {
      png_structp ptr = nullptr;
      png_infop info = nullptr;

      png_write_ctx()
      {
        ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
        if (ptr) {
          info = png_create_info_struct(ptr);
        }
      }

      ~png_write_ctx()
      {
        if(ptr) {
          png_destroy_write_struct(&ptr, info ? &info : nullptr);
        }
      }

      void copy_from_read(png_read_ctx const& read_ctx);
    };

    class png_provider : public provider_t {
      public:
        explicit png_provider(filesystem::path const& filename);
        explicit png_provider(byte_vector const& data);
        png_provider(byte const* data, size_t size);

        //Non-copyable:
        png_provider(png_provider const&) = delete;
        png_provider & operator = (png_provider const&) = delete;
        //Movable:
        png_provider(png_provider &&) = default;
        png_provider & operator = (png_provider &&) = default;

        static std::string format() { return "PNG"; }
        virtual index_t size() const override;
        virtual byte & access_indexed_data(index_t index) override;
        virtual byte const& access_indexed_data(index_t index) const override;
        virtual byte_vector commit_to_memory() override;
        virtual void commit_to_file(filesystem::path const& file) override;
        virtual byte_vector salt() const override;

        static const byte signature[8];

      private:
        std::unique_ptr<png_read_ctx> ctx_;
        byte_vector data_;
        std::vector<byte*> row_pointers_;
        std::uint32_t width_, height_;
        byte bit_depth_, color_type_;

        size_t adjust_index(size_t index) const;
    }; 

  }}	//namespace zindorsky::steganography
