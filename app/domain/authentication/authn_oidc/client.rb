require 'uri'
require 'openid_connect'

module Authentication
  module AuthnOidc
    class Client
      def initialize(client_id:, client_secret:, redirect_uri:, provider_uri:)
        @client_id = client_id
        @client_secret = client_secret
        @redirect_uri = redirect_uri
        @provider_uri = provider_uri
      end

      def oidc_id_token_details!(authorization_code)
        oidc_client.host = host
        oidc_client.authorization_code = authorization_code

        IDTokenDetails.new(
          id_token: id_token,
          user_info: user_info,
          client_id: @client_id,
          issuer: issuer,
          expiration_time: expiration_time
        )
      rescue OpenIDConnect::HttpError => e
        # adding the reponse body as it includes additional error information
        raise e, "#{e.message}, #{e.response.body}", e.backtrace if e.response
        raise e
      end

      private

      def oidc_client
        @oidc_client ||= OpenIDConnect::Client.new(
          identifier: @client_id,
          secret: @client_secret,
          redirect_uri: @redirect_uri,
          token_endpoint: discovered_resource.token_endpoint,
          userinfo_endpoint: discovered_resource.userinfo_endpoint
        )
      end

      def host
        URI.parse(@provider_uri).host
      end

      # TODO: capture exception: JSON::JWK::Set::KidNotFound and try refresh
      # signing keys
      def id_token
        @id_token ||= OpenIDConnect::ResponseObject::IdToken.decode(
          access_token.id_token, discovered_resource.jwks
        )
      end

      def user_info
        access_token.userinfo!
      end

      def issuer
        discovered_resource.issuer
      end

      def expiration_time
        id_token.raw_attributes["exp"]
      end

      def access_token
        @access_token ||= oidc_client.access_token!
      rescue Rack::OAuth2::Client::Error => e
        raise OIDCAuthenticationError, e.message
      end

      def discovered_resource
        @discovered_resource ||= OpenIDConnect::Discovery::Provider::Config.discover!(@provider_uri)
      end
    end
  end
end
