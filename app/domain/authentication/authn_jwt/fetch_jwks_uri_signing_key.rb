require 'uri'
require 'net/http'

module Authentication
  module AuthnJwt
    # This class is responsible for fetching JWK Set from JWKS-uri
    class FetchJwksUriSigningKey < FetchSigningKeyInterface

      def initialize(authenticator_parameters,
                     logger,
                     fetch_required_secrets,
                     resource_class,
                     http)
        @logger = logger
        @resource_id = authenticator_parameters.authenticator_resource_id
        @fetch_required_secrets = fetch_required_secrets
        @resource_class = resource_class
        @http = http
      end

      def has_valid_configuration?
        @jwks_uri_resource_exists ||= jwks_uri_resource_exists?
      end

      def fetch_signing_key
        fetch_jwks_uri
        fetch_jwks_keys
      end

      private

      def jwks_uri_resource_exists?
        !jwks_uri_resource.nil?
      end

      def jwks_uri_resource
        @jwks_uri_resource ||= resource
      end

      def resource
        @resource_class[jwks_uri_resource_id]
      end

      def fetch_jwks_uri
        @logger.debug(LogMessages::Authentication::AuthnJwt::JwksUriResourceNameConfiguration.new(jwks_uri_resource_id))
        jwks_uri
      end

      def jwks_uri
        @jwks_uri ||= jwks_uri_secret[jwks_uri_resource_id]
      end

      def jwks_uri_secret
        @jwks_uri_secret ||= @fetch_required_secrets.(resource_ids: [jwks_uri_resource_id])
      end

      def jwks_uri_resource_id
        "#{@resource_id}/#{JWKS_URI_RESOURCE_NAME}"
      end

      def fetch_jwks_keys
        uri = URI(jwks_uri)
        @logger.debug(LogMessages::Authentication::AuthnJwt::FetchingJwksFromJwksUri.new)
        response = @http.get_response(uri)
        @logger.debug(LogMessages::Authentication::AuthnJwt::FetchJwksUriKeysSuccess.new)
        JSON.parse(response.body)['keys']
      rescue => e
        raise Errors::Authentication::AuthnJwt::FetchJwksKeysFailed.new(
          jwks_uri,
          e.inspect
        )
      end
    end
  end
  end
