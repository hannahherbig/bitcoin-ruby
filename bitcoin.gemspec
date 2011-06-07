Gem::Specification.new do |gem|
  gem.name = "bitcoin"
  gem.version = "0.1"
  gem.date = Date.today.to_s
  gem.summary = "(De)serializer for the Bitcoin p2p wire protocol"
  gem.description = "Implements the generation and parsing code for Bitcoin" +
                    " p2p messages"

  gem.authors = ['Nick Thomas']
  gem.email = "nick@sharpcoin.org"
  gem.homepage = "http://sharpcoin.org"

  gem.add_dependency('rake')
  gem.add_dependency('ipaddress')
  gem.add_dependency('bindata')
  gem.add_development_dependency('rspec', ['>= 2.5.0'])

  gem.files = Dir['Rakefile', '{lib,spec}/**/*', 'README', 'CHANGELOG']
end
