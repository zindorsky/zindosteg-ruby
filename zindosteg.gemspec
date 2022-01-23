require_relative 'lib/zindosteg/version'

Gem::Specification.new do |spec|
  spec.name          = "zindosteg"
  spec.version       = Zindosteg::VERSION
  spec.authors       = ["Nephi Allred"]
  spec.email         = ["nephi.allred@gmail.com"]

  spec.summary       = %q{Basic steganography}
  spec.description   = %q{Use steganography to hide and encrypt data inside JPG, PNG, and BMP files.}
  spec.homepage      = "https://github.com/zindorsky/zindosteg-ruby"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.7.0")

  spec.add_dependency "rake-compiler"
  spec.add_dependency "rice", ">= 4.0"

  spec.extensions = %w(ext/zindosteg/extconf.rb)

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
end
