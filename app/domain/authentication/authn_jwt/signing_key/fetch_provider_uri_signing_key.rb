module Authentication
  module AuthnJwt
    module SigningKey
      # This class is responsible for fetching JWK Set from provider-uri
      class FetchProviderUriSigningKey

        def initialize(
          authentication_parameters:,
          fetch_authenticator_secrets: Authentication::Util::FetchAuthenticatorSecrets.new,
          discover_identity_provider: Authentication::OAuth::DiscoverIdentityProvider.new,
          logger: Rails.logger
        )
          @logger = logger
          @fetch_authenticator_secrets = fetch_authenticator_secrets
          @discover_identity_provider = discover_identity_provider

          @authentication_parameters = authentication_parameters
        end

        def fetch_signing_key
          discover_provider
          fetch_provider_keys
        end

        def signing_key_uri
          provider_uri
        end

        private

        def discover_provider
          @logger.info(LogMessages::Authentication::AuthnJwt::FetchingJwksFromProvider.new(provider_uri))
          discovered_provider
        end

        def discovered_provider
          @discovered_provider ||= @discover_identity_provider.call(
            provider_uri: provider_uri
          )
        end

        def provider_uri
          @provider_uri ||= provider_uri_secret
        end

        def provider_uri_secret
          @provider_uri_secret ||= @fetch_authenticator_secrets.call(
            conjur_account: @authentication_parameters.account,
            authenticator_name: @authentication_parameters.authenticator_name,
            service_id: @authentication_parameters.service_id,
            required_variable_names: [PROVIDER_URI_RESOURCE_NAME]
          )[PROVIDER_URI_RESOURCE_NAME]
        end

        def fetch_provider_keys
          keys = { keys: discovered_provider.jwks }
          @logger.debug(LogMessages::Authentication::OAuth::FetchProviderKeysSuccess.new)
          keys
        rescue => e
          raise Errors::Authentication::OAuth::FetchProviderKeysFailed.new(
            provider_uri,
            e.inspect
          )
        end
      end
    end
  end
end
