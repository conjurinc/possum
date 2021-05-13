module Authentication
  module AuthnJwt

    ValidateStatus = CommandClass.new(
      dependencies: {
        fetch_authenticator_secrets: Authentication::Util::FetchAuthenticatorSecrets.new,
        discover_identity_provider: Authentication::OAuth::DiscoverIdentityProvider.new
      },
      inputs: %i[account service_id]
    ) do
      def call
        validate_service_id_exists
        validate_secrets
        #validate_provider_is_responsive
      end

      private

      def validate_service_id_exists
        raise Errors::Authentication::AuthnJwt::ServiceIdMissing unless @service_id
      end

      def validate_secrets
        jwt_authenticator_secrets
      end

      def jwt_authenticator_secrets
        @jwt_authenticator_secrets ||= @fetch_authenticator_secrets.(
          service_id: @service_id,
            conjur_account: @account,
            authenticator_name: "authn-jwt",
            required_variable_names: required_variable_names
        )
      end

      def required_variable_names
        @required_variable_names ||= %w[provider-uri id-token-user-property]
      end

      def validate_provider_is_responsive
        @discover_identity_provider.(
          provider_uri: provider_uri
        )
      end

      def provider_uri
        @jwt_authenticator_secrets["provider-uri"]
      end
    end
  end
end

