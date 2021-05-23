# frozen_string_literal: true

require 'spec_helper'

describe Conjur::TrustedProxyFilter do
  it "does not raise an exception when created with valid IP addresses" do
    config = Conjur::ConjurConfig.new(trusted_proxies: '127.0.0.1')

    expect {
      Conjur::TrustedProxyFilter.new(config: config)
    }.not_to raise_error
  end
end
