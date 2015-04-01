MRuby::Build.new do |conf|
  # load specific toolchain settings
  toolchain :gcc

  # include the default GEMs
  conf.gembox 'default'
  
  conf.gem          File.expand_path('../', __FILE__)
  conf.build_dir =  File.expand_path('../build', __FILE__)
  
  conf.linker.library_paths << "/usr/local/lib"
  
  conf.cc do |cc|
    # cc.defines << %w(MRB_INT64)
    cc.include_paths << "/usr/local/include"
    cc.flags = %w(-g -Wall -Werror-implicit-function-declaration)
  end

end
