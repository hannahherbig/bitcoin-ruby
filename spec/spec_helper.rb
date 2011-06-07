require 'rspec'

$: << File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))

def binary(str_ary)
  str_ary.collect do |d|
    raise ArgumentError, "Bad part" unless d =~ /\A[a-f0-9]{2}\Z/i
    d.to_i(16).chr
  end.join("")
end
