require 'json'

module Authentication
  module OAuth

    Log = LogMessages::Authentication::OAuth
    Err = Errors::Authentication::OAuth
    # Possible Errors Raised:
    #   ProviderDiscoveryTimeout
    #   ProviderDiscoveryFailed
    #   FetchProviderKeysFailed

    FetchProviderKeys = CommandClass.new(
      dependencies: {
        logger:                 Rails.logger,
        discover_identity_provider: DiscoverIdentityProvider.new
      },
      inputs:       %i(provider_uri)
    ) do

      def call
        discover_provider
        fetch_provider_keys
      end

      private

      def discover_provider
        discovered_provider
      end

      def discovered_provider
        @discovered_provider ||= @discover_identity_provider.(
          provider_uri: @provider_uri
        )
      end

      def fetch_provider_keys
        jwks = {
          keys: @discovered_provider.jwks
        }
        algs = @discovered_provider.id_token_signing_alg_values_supported
        @logger.debug(Log::FetchProviderKeysSuccess.new)
        ProviderKeys.new(jwks, algs)
      rescue => e
        raise Err::FetchProviderKeysFailed.new(@provider_uri, e.inspect)
      end
    end
  end
end
