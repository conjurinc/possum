# frozen_string_literal: true

require 'spec_helper'

RSpec.describe('Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider') do
  let(:authenticator_name) { 'authn-jwt' }
  let(:service_id) { "my-service" }
  let(:account) { 'my-account' }
  let(:token_identity) { 'token-identity' }
  let(:decoded_token) {
    {
      "namespace_id" => "1",
      "namespace_path" => "root",
      "project_id" => "34",
      "project_path" => "root/test-proj",
      "user_id" => "1",
      "user_login" => "cucumber",
      "user_email" => "admin@example.com",
      "pipeline_id" => "1",
      "job_id" => "4",
      "ref" => "master",
      "ref_type" => "branch",
      "ref_protected" => "true",
      "jti" => "90c4414b-f7cf-4b98-9a4f-2c29f360e6d0",
      "iss" => "ec2-18-157-123-113.eu-central-1.compute.amazonaws.com",
      "iat" => 1619352275,
      "nbf" => 1619352270,
      "exp" => 1619355875,
      "sub" => token_identity
    }
  }

  let(:authentication_parameters) {
    Authentication::AuthnJwt::AuthenticationParameters.new(
      authentication_input: Authentication::AuthenticatorInput.new(
        authenticator_name: authenticator_name,
        service_id: service_id,
        account: account,
        username: "dummy_identity",
        credentials: "dummy",
        client_ip: "dummy",
        request: "dummy"
      ),
      jwt_token: nil
    )
  }

  def mock_resource_id(resource_name:)
    %r{#{account}:variable:conjur/#{authenticator_name}/#{service_id}/#{resource_name}}
  end

  let(:token_app_property_resource_name) { ::Authentication::AuthnJwt::TOKEN_APP_PROPERTY_VARIABLE }
  let(:identity_path_resource_name) { ::Authentication::AuthnJwt::IDENTITY_PATH_RESOURCE_NAME }
  let(:mocked_resource_not_exists_values) { double("Mocked resource value not exists")  }
  let(:mocked_resource_exists_values) { double("MockedResource") }
  let(:mocked_resource) { double("MockedResource") }
  let(:non_existing_field_name) { "non existing field name" }
  let(:mocked_valid_secrets) { double("MockedValidSecrets") }
  let(:mocked_valid_secrets_which_missing_in_token) { double("MockedValidSecretsMissingInToken") }
  let(:mocked_fetch_required_secrets_empty_values) {  double("MockedFetchRequiredSecrets") }
  let(:mocked_fetch_required_secrets_exist_values) {  double("MockedFetchRequiredSecrets") }
  let(:mocked_fetch_required_secrets_exist_value_which_missing_in_token) {  double("MockedFetchRequiredSecrets") }
  let(:required_secret_missing_error) { "required secret missing error" }
  let(:required_identity_path_secret_missing_error) { "required secret missing error" }
  let(:mocked_fetch_required_secrets_token_app_with_value_identity_path_empty) {  double("MockedFetchRequiredSecrets") }
  let(:token_app_property_secret_value) { "sub" }
  let(:missing_claim_secret_value) { "not found claim" }
  let(:mocked_fetch_identity_path_failed) { double("MockedFetchIdentityPathFailed") }
  let(:fetch_identity_path_missing_error) { "fetch identity fetch missing error" }
  let(:mocked_fetch_identity_path_valid_empty_path) { double("MockedFetchIdentityPathValid") }
  let(:identity_path_valid_empty_path) { ::Authentication::AuthnJwt::IDENTITY_PATH_DEFAULT_VALUE }
  let(:mocked_fetch_identity_path_valid_value) { double("MockedFetchIdentityPathValid") }
  let(:identity_path_valid_value) { "apps/sub-apps" }
  let(:valid_jwt_identity_without_path) {
    ::Authentication::AuthnJwt::IDENTITY_TYPE_HOST +
      ::Authentication::AuthnJwt::IDENTITY_PATH_CHARACTER_DELIMITER +
      token_identity
  }
  let(:valid_jwt_identity_with_path) {
    ::Authentication::AuthnJwt::IDENTITY_TYPE_HOST +
      ::Authentication::AuthnJwt::IDENTITY_PATH_CHARACTER_DELIMITER +
      identity_path_valid_value +
      ::Authentication::AuthnJwt::IDENTITY_PATH_CHARACTER_DELIMITER +
      token_identity
  }

  before(:each) do
    allow(authentication_parameters).to(
      receive(:decoded_token).and_return(decoded_token)
    )

    allow(mocked_resource_not_exists_values).to(
      receive(:[]).and_return(nil)
    )

    allow(mocked_resource_exists_values).to(
      receive(:[]).with(mock_resource_id(resource_name: token_app_property_resource_name)).and_return(mocked_resource)
    )

    allow(mocked_fetch_required_secrets_exist_values).to(
      receive(:call).with(
        resource_ids: [mock_resource_id(resource_name: token_app_property_resource_name)]).
        and_return(mocked_valid_secrets)
    )

    allow(mocked_valid_secrets).to(
      receive(:[]).with(mock_resource_id(resource_name: token_app_property_resource_name)).
        and_return(token_app_property_secret_value)
    )

    allow(mocked_fetch_required_secrets_exist_value_which_missing_in_token).to(
      receive(:call).with(
        resource_ids: [mock_resource_id(resource_name: token_app_property_resource_name)]).
        and_return(mocked_valid_secrets_which_missing_in_token)
    )

    allow(mocked_valid_secrets_which_missing_in_token).to(
      receive(:[]).with(mock_resource_id(resource_name: token_app_property_resource_name)).
        and_return(missing_claim_secret_value)
    )

    allow(mocked_fetch_required_secrets_empty_values).to(
      receive(:call).and_raise(required_secret_missing_error)
    )

    allow(mocked_fetch_identity_path_failed).to(
      receive(:call).and_raise(fetch_identity_path_missing_error)
    )

    allow(mocked_fetch_identity_path_valid_empty_path).to(
      receive(:call).and_return(identity_path_valid_empty_path)
    )

    allow(mocked_fetch_identity_path_valid_value).to(
      receive(:call).and_return(identity_path_valid_value)
    )

  end

  #  ____  _   _  ____    ____  ____  ___  ____  ___
  # (_  _)( )_( )( ___)  (_  _)( ___)/ __)(_  _)/ __)
  #   )(   ) _ (  )__)     )(   )__) \__ \  )(  \__ \
  #  (__) (_) (_)(____)   (__) (____)(___/ (__) (___/

  context "Identity from token with invalid configuration" do
    context "And 'token-app-property' resource not exists " do
      subject do
        ::Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider.new(
          authentication_parameters: authentication_parameters,
          resource_class: mocked_resource_not_exists_values
        )
      end

      it "jwt_identity raise an error" do
        expect { subject.jwt_identity }.to raise_error(Errors::Conjur::RequiredResourceMissing)
      end

      it "identity_available? returns value" do
        expect(subject.identity_available?).to eql(false)
      end

      it "validate_identity_configured_properly does not raise an error" do
        expect { subject.validate_identity_configured_properly }.to_not raise_error
      end
    end

    context "'token-app-property' resource exists" do
      context "with empty value" do
        subject do
          ::Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider.new(
            authentication_parameters: authentication_parameters,
            resource_class: mocked_resource_exists_values,
            fetch_required_secrets: mocked_fetch_required_secrets_empty_values
          )
        end

        it "jwt_identity raise an error" do
          expect { subject.jwt_identity }.to raise_error(required_secret_missing_error)
        end

        it "identity_available? returns value" do
          expect(subject.identity_available?).to eql(true)
        end

        it "validate_identity_configured_properly raise an error" do
          expect { subject.validate_identity_configured_properly }.to raise_error(required_secret_missing_error)
        end
      end

      context "And 'identity-path' resource exists with empty value" do
        subject do
          ::Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider.new(
            authentication_parameters: authentication_parameters,
            resource_class: mocked_resource_exists_values,
            fetch_required_secrets: mocked_fetch_required_secrets_exist_values,
            fetch_identity_path: mocked_fetch_identity_path_failed
          )
        end

        it "jwt_identity raise an error" do
          expect { subject.jwt_identity }.to raise_error(fetch_identity_path_missing_error)
        end

        it "identity_available? returns value" do
          expect(subject.identity_available?).to eql(true)
        end

        it "validate_identity_configured_properly raise an error" do
          expect { subject.validate_identity_configured_properly }.to raise_error(fetch_identity_path_missing_error)
        end
      end

      context "And identity token claim not exists in decode token " do
        subject do
          ::Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider.new(
            authentication_parameters: authentication_parameters,
            resource_class: mocked_resource_exists_values,
            fetch_required_secrets: mocked_fetch_required_secrets_exist_value_which_missing_in_token
          )
        end

        it "jwt_identity raise an error" do
          expect { subject.jwt_identity }.to raise_error(Errors::Authentication::AuthnJwt::NoSuchFieldInToken)
        end

        it "identity_available? returns value" do
          expect(subject.identity_available?).to eql(true)
        end

        it "validate_identity_configured_properly does not raise an error" do
          expect { subject.validate_identity_configured_properly }.to_not raise_error
        end
      end
    end
  end

  context "Identity from token configured correctly" do
    context "And 'token-app-property' resource exists with value" do
      context "And 'identity-path' resource not exists (valid configuration, empty path will be returned)" do
        subject do
          ::Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider.new(
            authentication_parameters: authentication_parameters,
            resource_class: mocked_resource_exists_values,
            fetch_required_secrets: mocked_fetch_required_secrets_exist_values,
            fetch_identity_path: mocked_fetch_identity_path_valid_empty_path
          )
        end

        it "jwt_identity returns host identity" do
          expect(subject.jwt_identity).to eql(valid_jwt_identity_without_path)
        end

        it "identity_available? returns value" do
          expect(subject.identity_available?).to eql(true)
        end

        it "validate_identity_configured_properly does not raise an error" do
          expect { subject.validate_identity_configured_properly }.to_not raise_error
        end
      end

      context "And 'identity-path' resource exists with value" do
        subject do
          ::Authentication::AuthnJwt::IdentityProviders::IdentityFromDecodedTokenProvider.new(
            authentication_parameters: authentication_parameters,
            resource_class: mocked_resource_exists_values,
            fetch_required_secrets: mocked_fetch_required_secrets_exist_values,
            fetch_identity_path: mocked_fetch_identity_path_valid_value
          )
        end

        it "jwt_identity returns host identity" do
          expect(subject.jwt_identity).to eql(valid_jwt_identity_with_path)
        end

        it "identity_available? returns value" do
          expect(subject.identity_available?).to eql(true)
        end

        it "validate_identity_configured_properly does not raise an error" do
          expect { subject.validate_identity_configured_properly }.to_not raise_error
        end
      end
    end
  end
end
