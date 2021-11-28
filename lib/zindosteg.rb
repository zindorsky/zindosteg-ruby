require "zindosteg/version"
require "zindosteg/zindosteg"

module Zindosteg
  class File
    class << self
      alias_method :open, :new
    end
  end

  def self.insert(carrier, password, payload)
    ::Zindosteg::File.open(carrier, password, "w").write(::File.open(payload).read)
  end

  def self.extract(carrier, password, payload)
    ::File.open(payload, "w").write(::Zindosteg::File.open(carrier, password).read)
  end
end
