SimpleCov.start 'rails' do
  command_name "SimpleCov #{rand(1000000)}"
  coverage_dir File.join(ENV['REPORT_ROOT'] || __dir__, 'coverage')
  # any custom configs like groups and filters can be here at a central place
end

SimpleCov.at_exit do
  puts "Formatting SimpleCov coverage report"
  SimpleCov.result.format!
  if ENV['SIMPLECOV_SLEEP']
    puts "Coverage Report Generated, sleeping forever"
    sleep()
  end
end

