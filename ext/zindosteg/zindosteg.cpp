#include <rice/rice.hpp>
#include <rice/stl.hpp>
#include "device.h"
#include "hmac.h"
#include "key_generator.h"
#include "aes.h"
#include <memory>

using namespace Rice;
using namespace zindorsky;
using namespace std::string_literals;

namespace {
  class rubyError : public std::runtime_error {
  public:
    rubyError(const char* msg = "") : std::runtime_error(msg) {}
    rubyError(std::string const& msg) : std::runtime_error(msg.c_str()) {}
    virtual VALUE error_type() const = 0;
  };

  class ioError : public rubyError {
  public:
    using rubyError::rubyError;
    VALUE error_type() const override { return rb_eIOError; }
  };

  class eofError : public rubyError {
  public:
    eofError() : rubyError("EOF") {}
    VALUE error_type() const override { return rb_eEOFError; }
  };

  class argumentError : public rubyError {
  public:
    using rubyError::rubyError;
    VALUE error_type() const override { return rb_eArgError; }
  };

  [[noreturn]] void handle_ruby_error(rubyError const& e)
  {
    throw Exception(e.error_type(), e.what());
  }

  //Class representing file open mode
  struct mode {
    //Mode flags:
    bool create = false, read = true, write = false, append = false, binary = false;

    mode() = default;

    mode(std::string mode_str)
    {
      std::string m{std::move(mode_str)};

      if (m.empty()) {
        m = "r";
      }
      if (m.back() == 'b') {
        m = m.substr(0, m.size() - 1);
        binary = true;
      } else if (m.back() == 't') {
        m = m.substr(0, m.size() - 1);
      }

      if (m == "r") {
        create = false;
        read = true;
        write = false;
      } else if (m == "r+") {
        create = false;
        read = true;
        write = true;
      } else if (m == "w") {
        create = true;
        read = false;
        write = true;
      } else if (m == "w+") {
        create = true;
        read = true;
        write = true;
      } else if (m == "a") {
        create = false;
        read = false;
        write = true;
        append = true;
      } else if (m == "a+") {
        create = false;
        read = true;
        write = true;
        append = true;
      } else {
        throw ioError("invalid mode: "s + m);
      }
    }

    std::string to_string() const
    {
      std::string m;
      if (append) {
        m = read ? "a+" : "a";
      } else {
        if (read && write) {
          m = create ? "w+" : "r+";
        } else if (read) {
          m = "r";
        } else {
          m = "w";
        }
      }
      if (binary) {
        m += 'b';
      }
      return m;
    }
  };

  struct key_cstr_helper {
    explicit key_cstr_helper(zindorsky::crypto::key_generator const& generator) { generator.generate(data,sizeof(data)); }
    byte data[32+AES_BLOCK_SIZE];
  };

  class device_interface {
  public:
    device_interface(std::string const& carrier_file, std::string const& password, mode const& mode = "r"s)
			: device_interface{steganography::device_t{filesystem::path{carrier_file}, password, !mode.create, !mode.append}, password, mode}
    {
      if (!mode_.create) {
        //Check hmac to make sure password is correct, payload hasn't been tampered with, etc.
        if (sz_ >= crypto::hmac::digest_sz) {
          //We don't include the HMAC in the logical size.
          sz_ -= crypto::hmac::digest_sz;
          //Calculate HMAC
          unsigned char calculated_hmac[crypto::hmac::digest_sz], stored_hmac[crypto::hmac::digest_sz];
          compute_hmac(calculated_hmac);
          //Read stored HMAC after payload.
          if (crypto::hmac::digest_sz != device_.read(reinterpret_cast<char *>(stored_hmac), sizeof(stored_hmac))) {
            throw crypto::hmac_verification_failure{};
          }
          encryptor_.crypt(stored_hmac, stored_hmac, sizeof(stored_hmac));
          //Compare
          if (0 == memcmp(stored_hmac, calculated_hmac, sizeof(stored_hmac))) {
            //Seek back to beginning.
            seek(0, mode_.append ? std::ios::end : std::ios::beg);
            return;
          }
        }
        if (mode_.append) {
          //Append mode means we should create a new payload instead of failing.
          device_.seek(0, std::ios::beg);
          sz_ = device_.truncate();
          seek(0, std::ios::end);
          return;
        }
        throw crypto::hmac_verification_failure{};
      }
    }

    device_interface(String carrier_file, String password, String mode_str)
			: device_interface{carrier_file.str(), password.str(), mode{mode_str.str()}}
    {
    }

    ~device_interface()
    {
  		try {
  			close();
  		} catch(...) { }
    }

    //non-copyable
    device_interface(device_interface const&) = delete;
    device_interface & operator = (device_interface const&) = delete;

    //movable
    device_interface(device_interface &&) = default;
    device_interface & operator = (device_interface &&) = default;

    bool autoclose() const { return true; }
    void enable_binmode() { mode_.binary = true; }
    bool binmode() const { return mode_.binary; }
    long capacity() const { return max_sz_; }

    void close()
    {
      if (closed_) {
        return;
      }
      flush();
    	device_.close();
      closed_ = true;
    }

    bool closed() const
    {
      return closed_;
    }

    void each(Object sep, Object limit)
    {
      rb_need_block();
      while(!eof()) {
        auto line = gets(sep, limit);
        if (line.is_nil()) {
          break;
        }
        rb_yield(line.value());
      }
    }

    void each_byte()
    {
      rb_need_block();
      while(!eof()) {
        auto b = getbyte();
        if (b.is_nil()) {
          break;
        }
        rb_yield(b.value());
      }
    }

    void each_char()
    {
      rb_need_block();
      while(!eof()) {
        auto c = getc();
        if (c.is_nil()) {
          break;
        }
        rb_yield(c.value());
      }
    }

    bool eof() const
    {
      return pos_ >= sz_;
    }

    void flush()
    {
      check_closed();
      //remember where we are so we can seek back after updating the HMAC:
      long orig = pos_;
      if (dirty_) {
        //Write HMAC after the payload
        unsigned char hmac[crypto::hmac::digest_sz];
        compute_hmac(hmac);
        encryptor_.crypt(hmac, hmac, sizeof(hmac));
        device_.write(reinterpret_cast<char const *>(hmac), sizeof(hmac));
      }
      device_.flush();
      dirty_ = false;
      seek(orig);
    }

    Object getbyte()
    {
      check_closed();
      check_read();

      if (eof()) {
        return {};
      }

      char c;
      auto r = device_.read(&c, 1);
      if (r <= 0) {
        return {};
      }
      encryptor_.crypt(&c, &c, 1);
      pos_++;
      return detail::To_Ruby<int>().convert(static_cast<unsigned char>(c));
    }

    Object getc()
    {
      check_closed();
      check_read();
      if (eof()) {
        return {};
      }

      char c;
      auto r = device_.read(&c, 1);
      if (r <= 0) {
        return {};
      }
      encryptor_.crypt(&c, &c, 1);
      pos_++;
      return String(std::string(&c, 1));
    }

    Object gets(Object sep, Object limit)
    {
      check_closed();
      check_read();
      if (eof()) {
        return {};
      }

      std::string separator{"\n"};
      long lim = -1;
      if (limit.is_nil()) {
        if (!sep.is_nil()) {
          if (sep.rb_type() == T_FIXNUM) {
            lim = detail::From_Ruby<long>().convert(sep);
          } else {
            separator = detail::From_Ruby<std::string>().convert(sep);
          }
        }
      } else {
        separator = detail::From_Ruby<std::string>().convert(sep);
        lim = detail::From_Ruby<long>().convert(limit);
      }

      if (lim == 0) {
        return String{};
      }
      std::string str;
      if (lim > 0) {
        str.reserve(static_cast<std::string::size_type>(lim));
      }
      while(
        !eof()
        && (lim < 0 || str.size() < static_cast<std::string::size_type>(lim))
        && (separator.empty() || (str.size() < separator.size() || str.substr(str.size() - separator.size()) != separator))
        )
      {
        char c;
        auto r = device_.read(&c, 1);
        if (r <= 0) {
          break;
        }
        encryptor_.crypt(&c, &c, 1);
        pos_++;
        str += c;
      }
      return detail::To_Ruby<std::string>().convert(str);
    }

    bool isatty() const { return false; }

    String get_mode() const { return mode_.to_string(); }

    long set_pos(long pos)
    {
      return seek(pos);
    }

    void putc(Object obj)
    {
      switch(obj.rb_type()) {
      case T_FIXNUM:
        {
        char c[2] = {0};
        c[0] = detail::From_Ruby<char>().convert(obj);
        write(String(c));
        }
        break;
      case T_STRING:
        write(obj);
        break;
      default:
        throw argumentError("Argument must be String or Numeric");
      }
    }

    String read(Object length, Object outbuf)
    {
      check_closed();
      check_read();


      long n;
      if (length.is_nil()) {
        n = sz_ - pos_;
      } else {
        n = detail::From_Ruby<long>().convert(length);
      }
      if (n == 0) {
        return String();
      }
      //Make sure pos_ is valid.
      if (pos_ > sz_) {
        pos_ = sz_;
      }
      if (pos_ < 0) {
        pos_ = 0;
      }
      if (n < 0) {
        throw ioError("negative length");
      }
      //don't try to read past eof
      long toread = std::min(n, sz_ - pos_);

      VALUE out;
      if (outbuf.is_nil()) {
        out = rb_str_new(nullptr, toread);
      } else if (outbuf.rb_type() == T_STRING) {
        out = outbuf.value();
        rb_str_resize(out, toread);
      } else {
        throw argumentError("outbuf must be String");
      }

      auto ptr = StringValuePtr(out);
      auto r = device_.read(ptr, toread);
      encryptor_.crypt(ptr, ptr, static_cast<size_t>(r));
      pos_ += static_cast<long>(r);
      rb_str_resize(out, static_cast<long>(r));
      return out;
    }

    Object readbyte()
    {
      auto retval = getbyte();
      if (retval.is_nil()) {
        throw eofError();
      }
      return retval;
    }

    Object readchar()
    {
      auto retval = getc();
      if (retval.is_nil()) {
        throw eofError();
      }
      return retval;
    }

    Object readline(Object sep, Object limit)
    {
      auto retval = gets(sep, limit);
      if (retval.is_nil()) {
        throw eofError();
      }
      return retval;
    }

    Array readlines(Object sep, Object limit)
    {
      check_closed();
      check_read();
      if (eof()) {
        return Array{};
      }

      std::string separator{"\n"};
      long lim = -1;
      if (limit.is_nil()) {
        if (!sep.is_nil()) {
          if (sep.rb_type() == T_FIXNUM) {
            lim = detail::From_Ruby<long>().convert(sep);
          } else {
            separator = detail::From_Ruby<std::string>().convert(sep);
          }
        }
      } else {
        separator = detail::From_Ruby<std::string>().convert(sep);
        lim = detail::From_Ruby<long>().convert(limit);
      }

      if (lim == 0) {
        return Array{};
      }
      std::string str;
      if (lim > 0) {
        str.reserve(static_cast<std::string::size_type>(lim));
      }
      Array arr;
      while(!eof()) {
        str.clear();
        while(
          !eof()
          && (lim < 0 || str.size() < static_cast<std::string::size_type>(lim))
          && (separator.empty() || (str.size() < separator.size() || str.substr(str.size() - separator.size()) != separator))
          )
        {
          char c;
          auto r = device_.read(&c, 1);
          if (r <= 0) {
            break;
          }
          encryptor_.crypt(&c, &c, 1);
          pos_++;
          str += c;
        }
        arr.push(String(detail::To_Ruby<std::string>().convert(str)));
      }
      return arr;
    }
    long rewind()
    {
      return seek(0);
    }

    long seek(long off, int way = std::ios::beg)
    {
      check_closed();

      std::streampos newpos = device_.seek(off, static_cast<std::ios::seekdir>(way));
      //No seeking past EOF. (To resize the file, use write or truncate.)
      if (newpos > sz_) {
        newpos = device_.seek(sz_, std::ios::beg);
      }
      encryptor_.seek(newpos);
      pos_ = static_cast<long>(newpos);
      return pos_;
    }

    long size() const { return sz_; }

    long tell() const
    {
        check_closed();
        return pos_;
    }

    void truncate()
    {
        truncate_size(pos_);
    }

    void truncate_size(long size)
    {
      check_closed();
      check_write();

      if (size == sz_) {
        return;
      }
      if (size > max_sz_) {
        size = max_sz_;
      }

      if (size != pos_) {
        device_.seek(size, std::ios::beg);
        sz_ = static_cast<long>(device_.truncate());
        //Make sure pos_ doesn't point past eof:
        if (pos_ > sz_) {
          pos_ = sz_;
        }
        //Put current location back to pos_:
        seek(pos_, std::ios::beg);
      } else {
        sz_ = static_cast<long>(device_.truncate());
      }
      dirty_ = true;
    }

    long write(String s)
    {
      check_closed();
      check_write();
      check_append();

      auto len = static_cast<long>(s.length());
      if (pos_ > sz_) {
        pos_ = sz_;
      }
      if (pos_ + len > max_sz_) {
        len = max_sz_ - pos_;
      }

      //Encrypt and write to device
      char const *d = s.c_str();
      long sz = len, start = pos_;
      char c;
      while (sz-- > 0)
      {
        encryptor_.crypt(d++, &c, 1);
        if (device_.write(&c, 1) != 1) {
          break;
        }
        ++pos_;
      }
      //Update size if we wrote past current end
      if (pos_ > sz_) {
        sz_ = pos_;
      }
      dirty_ = true;

      return pos_ - start;
    }

  private:
    //Data members
    steganography::device_t device_;
    long pos_, sz_, max_sz_;
    crypto::aes_ctr_mode encryptor_;
    crypto::hmac hmac_;
    mode mode_;
    bool closed_, dirty_;

    //delegate constructors
    device_interface( steganography::device_t && device, std::string const& password, mode const& mode )
      : device_interface{std::move(device), key_cstr_helper(crypto::key_generator(password,device.salt_for_encryption())), password, mode}
    {
    }

    device_interface( steganography::device_t && device, key_cstr_helper const& helper, std::string const& password, mode const& mode )
      : device_{std::move(device)}
      , pos_{0}
      , sz_{static_cast<long>(device_.size())}
      , max_sz_{ std::max<long>(0, static_cast<long>(device_.capacity() - crypto::hmac::digest_sz)) }
      , encryptor_{helper.data, 32, helper.data+32}
      , hmac_{password.c_str(), static_cast<int>(password.size())}
      , mode_{mode}
      , closed_{false}
      , dirty_{false}
    {
    }

    //Computes HMAC of payload. File pointer will be at EOF afterwards.
    void compute_hmac(unsigned char * hmac)
    {
      unsigned char buff[0x1000];
    	seek(0);
      hmac_.reset();
      while(pos_ < sz_) {
          size_t toread = std::min(static_cast<size_t>(sz_ - pos_), sizeof(buff));
          device_.read(reinterpret_cast<char*>(buff), toread);
          pos_ += static_cast<long>(toread);
          encryptor_.crypt(buff, buff, toread);
          hmac_.update(buff, toread);
      }
      hmac_.final(hmac);
    }

    void check_read() const
    {
      if (!mode_.read) {
        throw ioError("File not open for reading");
      }
    }

    void check_write() const
    {
      if (!mode_.write) {
        throw ioError("File not open for writing");
      }
    }

    void check_closed() const
    {
      if (closed_) {
        throw ioError("I/O operation on closed file");
      }
    }

    void check_append()
    {
      if (mode_.append) {
        seek(0, std::ios::end);
      }
    }
  };
}

extern "C" void Init_zindosteg()
{
  Module rb_cModule = define_module("Zindosteg");
  Data_Type<device_interface> rb_cZindosteg =
    define_class_under<device_interface>(rb_cModule, "File")
    .add_handler<rubyError>(handle_ruby_error)
    .define_constructor(Constructor<device_interface, std::string, std::string, std::string>(), Arg("carrier"), Arg("password"), Arg("mode") = "r"s)
    .define_method("<<", &device_interface::write)
    .define_method("autoclose?", &device_interface::autoclose)
    .define_method("binmode", &device_interface::enable_binmode)
    .define_method("binmode?", &device_interface::binmode)
    .define_method("capacity", &device_interface::capacity)
    .define_method("closed?", &device_interface::closed)
    .define_method("close", &device_interface::close)
    .define_method("each", &device_interface::each, Arg("sep") = Object(), Arg("limit") = Object())
    .define_method("each_byte", &device_interface::each_byte)
    .define_method("each_char", &device_interface::each_char)
    .define_method("each_line", &device_interface::each, Arg("sep") = Object(), Arg("limit") = Object())
    .define_method("eof", &device_interface::eof)
    .define_method("eof?", &device_interface::eof)
    .define_method("flush", &device_interface::flush)
    .define_method("getbyte", &device_interface::getbyte)
    .define_method("getc", &device_interface::getc)
    .define_method("gets", &device_interface::gets, Arg("sep") = Object(), Arg("limit") = Object())
    .define_method("isatty", &device_interface::isatty)
    .define_method("mode", &device_interface::get_mode)
    .define_method("pos", &device_interface::tell)
    .define_method("pos=", &device_interface::set_pos)
    .define_method("print", &device_interface::write)
    .define_method("putc", &device_interface::putc)
    .define_method("puts", &device_interface::write)
    .define_method("read", &device_interface::read, Arg("length") = Object(), Arg("outbuf") = Object())
    .define_method("readbyte", &device_interface::readbyte)
    .define_method("readchar", &device_interface::readchar)
    .define_method("readline", &device_interface::readline, Arg("sep") = Object(), Arg("limit") = Object())
    .define_method("readlines", &device_interface::readlines, Arg("sep") = Object(), Arg("limit") = Object())
    .define_method("rewind", &device_interface::rewind)
    .define_method("seek", &device_interface::seek, Arg("amount"), Arg("whence") = (int)std::ios::beg)
    .define_method("size", &device_interface::size)
    .define_method("tell", &device_interface::tell)
    .define_method("tty?", &device_interface::isatty)
    .define_method("write", &device_interface::write)
    ;
}
