# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('Authentication::AuthnJwt::RestrictionValidation::FetchEnforcedClaims') do

  let(:authenticator_name) { 'authn-jwt' }
  let(:service_id) { "my-service" }
  let(:account) { 'my-account' }

  let(:authenticator_input) {
    Authentication::AuthenticatorInput.new(
      authenticator_name: authenticator_name,
      service_id: service_id,
      account: account,
      username: "dummy",
      credentials: "dummy",
      client_ip: "dummy",
      request: "dummy"
    )
  }

  let(:jwt_authenticator_input) {
    Authentication::AuthnJwt::JWTAuthenticatorInput.new(
      authenticator_input: authenticator_input,
      decoded_token: nil
    )
  }

  let(:enforced_claims_resource_name) {Authentication::AuthnJwt::ENFORCED_CLAIMS_RESOURCE_NAME}
  let(:enforced_claims_valid_secret_value) {'claim1 , claim2'}
  let(:enforced_claims_valid_parsed_secret_value) {%w[claim1 claim2]}

  let(:enforced_claims_invalid_secret_value) {'claim1 ,, claim2'}

  let(:mocked_resource) { double("MockedResource") }
  let(:mocked_authenticator_secret_not_exists) { double("Mocked authenticator secret not exists")  }
  let(:mocked_authenticator_secret_exists) { double("Mocked authenticator secret exists") }

  let(:mocked_fetch_authenticator_secrets_valid_values)  {  double("MochedFetchAuthenticatorSecrets") }
  let(:mocked_fetch_authenticator_secrets_invalid_values)  {  double("MochedFetchAuthenticatorSecrets") }
  let(:mocked_fetch_authenticator_secrets_empty_values)  {  double("MochedFetchAuthenticatorSecrets") }
  
  let(:mocked_valid_secrets) {
    {
      enforced_claims_resource_name => enforced_claims_valid_secret_value
    }
  }

  let(:mocked_invalid_secrets) {
    {
      enforced_claims_resource_name => enforced_claims_invalid_secret_value
    }
  }

  let(:required_secret_missing_error) { "required secret missing error" }

  before(:each) do
    allow(mocked_authenticator_secret_exists).to(
      receive(:call).and_return(true)
    )

    allow(mocked_authenticator_secret_not_exists).to(
      receive(:call).and_return(false)
    )

    allow(mocked_fetch_authenticator_secrets_valid_values).to(
      receive(:call).and_return(mocked_valid_secrets)
    )

    allow(mocked_fetch_authenticator_secrets_invalid_values).to(
      receive(:call).and_return(mocked_invalid_secrets)
    )

    allow(mocked_fetch_authenticator_secrets_empty_values).to(
      receive(:call).and_raise(required_secret_missing_error)
    )
  end

  #  ____  _   _  ____    ____  ____  ___  ____  ___
  # (_  _)( )_( )( ___)  (_  _)( ___)/ __)(_  _)/ __)
  #   )(   ) _ (  )__)     )(   )__) \__ \  )(  \__ \
  #  (__) (_) (_)(____)   (__) (____)(___/ (__) (___/

  context "'enforced_claims' variable is configured in authenticator policy" do
    context "with empty variable value" do
      subject do
        ::Authentication::AuthnJwt::RestrictionValidation::FetchEnforcedClaims.new(
          check_authenticator_secret_exists: mocked_authenticator_secret_exists,
          fetch_authenticator_secrets: mocked_fetch_authenticator_secrets_empty_values
        ).call(
          jwt_authenticator_input: jwt_authenticator_input
        )
      end

      it "raises an error" do
        expect { subject }.to raise_error(required_secret_missing_error)
      end
    end

    context "with invalid variable value" do
      subject do
        ::Authentication::AuthnJwt::RestrictionValidation::FetchEnforcedClaims.new(
          check_authenticator_secret_exists: mocked_authenticator_secret_exists,
          fetch_authenticator_secrets: mocked_fetch_authenticator_secrets_invalid_values
        ).call(
          jwt_authenticator_input: jwt_authenticator_input
        )
      end

      it "raises an error" do
        expect { subject }.to raise_error(Errors::Authentication::AuthnJwt::InvalidEnforcedClaimsFormat)
      end
    end
    
    context "with valid variable value" do
      subject do
        ::Authentication::AuthnJwt::RestrictionValidation::FetchEnforcedClaims.new(
          check_authenticator_secret_exists: mocked_authenticator_secret_exists,
          fetch_authenticator_secrets: mocked_fetch_authenticator_secrets_valid_values
        ).call(
          jwt_authenticator_input: jwt_authenticator_input
        )
      end

      it "returns parsed enforced claims list" do
        expect(subject).to eql(enforced_claims_valid_parsed_secret_value)
      end
    end
  end

  context "'enforced_claims' variable is not configured in authenticator policy" do
    subject do
      ::Authentication::AuthnJwt::RestrictionValidation::FetchEnforcedClaims.new(
        check_authenticator_secret_exists: mocked_authenticator_secret_not_exists
      ).call(
        jwt_authenticator_input: jwt_authenticator_input
      )
    end

    it "returns an empty enforced claims list" do
      expect(subject).to eql([])
    end
  end
end
