# Zindosteg

Steganography is the art and science of hiding data inside another set of data. The hidden data is known as the "payload", and could be any kind of data. The data that holds the hidden data is called the "carrier" and is normally an image, sound, or video file. The goal is to modify the carrier file in such a way that to human eyes it appears the same as before, but the subtle differences actually encode bits (0s and 1s) that can be reassembled into the payload.

This gem is a Ruby interface to the Zindosteg C++ library, which uses a variant of the F5 data hiding technique.

## Features
* Encryption: The payload is encrypted with AES-256-CTR using a key derived from the password using the carrier file as salt.
* Data integrity: In order to protect against accidental corruption or intentional tampering, the payload is stored with an HMAC.
* Scattering: Instead of placing the payload sequentially inside the carrier file, the order of the hidden bits is determined by a pseudo-random number generator seeded with the password.

## Supported Carrier Types
Zindosteg supports JPEG, PNG, and BMP carrier files. PNG files must have at least 8 bit depth, and not be "palette" type. BMP files must be 24-bit.

## Installation
Note: To compile the native extensions, you may need to install JPEG, PNG, and OpenSSL development packages.

Add this line to your application's Gemfile:

```ruby
gem 'zindosteg'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install zindosteg

## Usage
Zindosteg is designed to mimic Ruby's `File` class as closely as possible. The basic idea is that you get a `Zindosteg` instance by "opening" the carrier file with a password. Then you can read and write to the `Zindosteg` object in the same way you normally would to a `File` object, using the same methods (e.g. `read`, `write`, `readlines`, `eof?`, `seek`, `tell`, etc.). You can even pass the `Zindosteg` instance to functions that expect `File` objects and everything should work.

### Examples
```ruby
# Open a new carrier for writing (overwriting any existing payload)
file = ::Zindosteg::File.open("carrier.jpeg", "secretpassword", "w")

# Write the payload to it
file.write("This is my secret payload.")

# Close to finalize
file.close

# Open an existing carrier file for reading
file = ::Zindosteg::File.open("carrier.jpeg", "secretpassword", "r")

# The mode parameter is "r" by default so this is equivalent to the above:
file = ::Zindosteg::File.open("carrier.jpeg", "secretpassword")

# Read the payload
file.read

# Or you could read it as an array of lines.
file.readlines

# Use all the regular File methods as you would normally
file.seek(0)
file.tell
file.size
file.eof?
# etc

# Use the 'capacity' method to see the maximum number of bytes that the carrier file can hide.
file.capacity

# All the standard modes for opening files are supported:
file = ::Zindosteg::File.open("carrier.jpeg", "secretpassword", "w+") # Opens for reading and writing, truncating any existing payload

file = ::Zindosteg::File.open("carrier.jpeg", "secretpassword", "a") # Opens for appending

# etc

# If you open for reading (or appending) and either
#  (1) an incorrect password is given, or
#  (2) there is no existing payload, or
#  (3) the carrier file has been corrupted or tampered with
# then a "RuntimeError (HMAC verification failure.)" exception will be thrown.

# Shortcuts
# Insert a payload file into a carrier file in one line:
::Zindosteg.insert(carrier_path, password, payload_path)

# Extract a payload from a carrier in one line:
::Zindosteg.extract(carrier_path, password, payload_path)
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/zindorsky/zindosteg-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
