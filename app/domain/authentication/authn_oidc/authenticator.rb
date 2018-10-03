require 'command_class'

module Authentication
  module AuthnOidc
    class AuthenticationError < RuntimeError; end
    class NotFoundError < RuntimeError; end
    class OIDCConfigurationError < RuntimeError; end
    class OIDCAuthenticationError < RuntimeError; end

    # TODO: Should really have a verb name "Authenticate" since it's a command
    # object but we'll leave it like this for now for consistency
    #
    Authenticator = CommandClass.new(
      dependencies: { env: ENV },
      inputs: %i(input user_details)
    ) do

      def call
        validate_id_token_claims
        validate_user_info
        true
      end

      private

      def validate_id_token_claims
        expected = { client_id: client_id, issuer: issuer } # , nonce: 'nonce'}
        @user_details.id_token.verify!(expected)
      end

      def validate_user_info
        raise OIDCAuthenticationError, subject_err_msg unless valid_subject?
        raise OIDCAuthenticationError, no_profile_err_msg unless preferred_username
      end

      def user_info
        @user_details.user_info
      end

      def valid_subject?
        user_info.sub == id_token_subject
      end

      def preferred_username
        user_info.preferred_username
      end

      def client_id
        @user_details.client_id
      end

      def issuer
        @user_details.issuer
      end

      def id_token_subject
        @user_details.id_token.sub
      end

      def authenticator_name
        @input.authenticator_name
      end

      def service_id
        @input.service_id
      end

      def conjur_account
        @input.account
      end

      def request_body
        @request_body ||= @input.request.body.read
      end

      def service
        @service ||= Resource["#{conjur_account}:webservice:conjur/#{authenticator_name}/#{service_id}"]
      end

      def no_profile_err_msg
        "[profile] is not included in scope of authorization code request"
      end

      def subject_err_msg
        "User info subject [#{user_info.sub}] and id token subject " +
         "[#{id_token_subject}] are not equal"
      end
    end
  end
end
