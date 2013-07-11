
MRuby::Gem::Specification.new('mruby-ping') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Julien Ammous'
  
  spec.linker.libraries << %w(net pcap)
end
