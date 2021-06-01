module Authentication
  module AuthnJwt
    module IdentityProviders
      # Class for providing jwt identity from the decoded token from the field specified in a secret
      class IdentityFromDecodedTokenProvider < IdentityProviderInterface
        def initialize(authentication_parameters)
          super

          @resource_id = @authentication_parameters.authenticator_resource_id
          @decoded_token = @authentication_parameters.decoded_token
        end

        def jwt_identity
          return @jwt_identity if @jwt_identity

          token_field_name = fetch_token_field_name
          @logger.debug(LogMessages::Authentication::AuthnJwt::CHECKING_IDENTITY_FIELD_EXISTS.new(token_field_name))
          @jwt_identity ||= @decoded_token[token_field_name]
          if @jwt_identity.blank?
            raise Errors::Authentication::AuthnJwt::NoSuchFieldInToken, token_field_name
          end

          @logger.debug(LogMessages::Authentication::AuthnJwt::FOUND_JWT_FIELD_IN_TOKEN.new(token_field_name, jwt_identity))
          @jwt_identity
        end

        # Checks if variable that defined from which field in decoded token to get the id is configured
        def identity_available?
          identity_field_variable.present?
        end

        # This method is for the authenticator status check, unlike 'identity_available?' it checks if the
        # secret value is not empty too
        def identity_configured_properly?
          fetch_token_field_name.blank? if identity_available?
        end

        private

        def identity_field_variable
          @resource_class[token_id_field_resource_id]
        end

        def token_id_field_resource_id
          "#{@resource_id}/#{IDENTITY_FIELD_VARIABLE}"
        end

        def fetch_secret(secret_id)
          @secret_fetcher.call(resource_ids: [secret_id])[secret_id]
        end

        def fetch_token_field_name
          resource_id = token_id_field_resource_id
          @logger.debug(LogMessages::Authentication::AuthnJwt::LOOKING_FOR_IDENTITY_FIELD_NAME.new(resource_id))
          fetch_secret(resource_id)
        end
      end
    end
  end
end
