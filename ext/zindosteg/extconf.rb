require "mkmf-rice"

sources = %w{aes key_generator permutator bmp jpeg_helpers jpeg png_provider loader device}
$srcs = sources.map { |file| "#{file}.cpp" }
$objs = sources.map { |file| "#{file}.o" } << "zindosteg.o"
$CPPFLAGS << " -std=c++17 -O2"
$LDFLAGS << " -lcrypto -ljpeg -lpng"
$LDFLAGS << " -lstdc++fs" if have_macro("EXPERIMENTAL_FILESYSTEM", "steg_defs.h")

create_makefile("zindosteg/zindosteg")
