require_relative 'lib/zindosteg/version'

Gem::Specification.new do |spec|
  spec.name          = "zindosteg"
  spec.version       = Zindosteg::VERSION
  spec.authors       = ["Nephi Allred"]
  spec.email         = ["nephi.allred@gmail.com"]

  spec.summary       = %q{Basic steganography}
  spec.description   = %q{Hide and encrypt data inside JPG, PNG, and BMP files.}
  #spec.homepage      = "TODO: Put your gem's website or public repo URL here."
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.7.0")

  #spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  #spec.metadata["homepage_uri"] = spec.homepage
  #spec.metadata["source_code_uri"] = "TODO: Put your gem's public repo URL here."
  #spec.metadata["changelog_uri"] = "TODO: Put your gem's CHANGELOG.md URL here."

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
