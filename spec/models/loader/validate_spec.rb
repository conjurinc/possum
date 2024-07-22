# frozen_string_literal: true

require 'spec_helper'

# Test outline:
# - inject policy_result objs for the error and no-error cases
# - create the errors from EnhancedPolicyError class

describe Loader::Validate do
  @logger = Rails.logger

  mode = Loader::CreatePolicy.from_policy(nil, nil, Loader::Validate, logger: Rails.logger)

  context "when the policy parsed as an error" do
    adhoc_err = Exceptions::EnhancedPolicyError.new(
      original_error: nil,
      detail_message: "fake error"
    )
    it "reports a response with Invalid YAML status" do
      policy_result = PolicyResult.new(
        policy_version: nil,
        created_roles: nil,
        policy_parse: PolicyParse.new([], adhoc_err)
      )
      response = mode.report(policy_result, :validation)

      # TODO: _not because details not quite right yet...
      expect(response).to_not match("Invalid YAML.\n#{adhoc_err}")
    end
  end

  context "when the policy parsed with no error" do
    it "reports a response with Valid YAML status" do
      policy_result = PolicyResult.new(
        policy_version: nil,
        created_roles: nil,
        policy_parse: PolicyParse.new([], nil)
      )
      response = mode.report(policy_result, :validation)

      # TODO: _not because details not quite right yet...
      expect(response).to_not match("Valid YAML []")
    end
  end
end
