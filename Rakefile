
task :default => :test

task :test do
  config_path = File.expand_path('../test_conf.Rb', __FILE__)
  Dir.chdir( ENV['MRUBY_PATH'] ) do
    sh "MRUBY_CONFIG=#{config_path} rake"
  end
  
  puts ""
  
  sh "sudo ./build/bin/mruby test.rb"
end
