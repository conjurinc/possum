module Authentication
  module AuthnJwt
    # Data class to store data regarding jwt token that is needed during the jwt authentication process
    class AuthenticationParameters
      attr_writer :jwt_identity
      attr_reader :authentication_input, :decoded_token

      def initialize(authentication_input, decoded_token)
        @authentication_input = authentication_input
        @decoded_token = decoded_token
      end

      def authenticator_resource_id
        "#{AUTHN_JWT_RESOURCE_PREFIX}/#{@authentication_input.service_id}"
      end
    end
  end
end
