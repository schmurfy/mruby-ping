
task :test do
  sh "sudo echo Root rights acquired"
  Dir.chdir('/Users/Schmurfy/Dev/personal/mruby') do
    sh "rake"
  end
  
  puts ""
  
  sh "sudo mruby test.rb"
end
