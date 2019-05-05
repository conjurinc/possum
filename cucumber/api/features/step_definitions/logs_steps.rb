# frozen_string_literal: true

Given(/^I save my place in the log file$/) do
  save_num_log_lines()
end

And(/^The following appears in the log after my savepoint:$/) do |message|
  expect(num_matches_since_savepoint(message)).to eq 1
end
