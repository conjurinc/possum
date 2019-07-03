# frozen_string_literal: true

require 'logs'
require 'authentication/validate_webservice_exists'
require 'authentication/validate_account_exists'

module Authentication

  module Security

    Log = LogMessages::Authentication::Security
    Err = Errors::Authentication::Security
    # Possible Errors Raised:
    # AccountNotDefined, ServiceNotDefined,
    # UserNotDefinedInConjur, UserNotAuthorizedInConjur

    ValidateWebserviceAccess = CommandClass.new(
      dependencies: {
        role_class: ::Role,
        resource_class: ::Resource,
        validate_webservice_exists: ::Authentication::Security::ValidateWebserviceExists.new,
        validate_account_exists: ::Authentication::Security::ValidateAccountExists.new,
        logger: Rails.logger
      },
      inputs: %i(webservice account user_id)
    ) do

      def call
        # No checks required for default conjur authn
        return if default_conjur_authn?

        validate_account_exists
        validate_webservice_exists
        validate_user_is_defined
        validate_user_has_access
      end

      private

      def default_conjur_authn?
        @webservice.authenticator_name ==
          ::Authentication::Common.default_authenticator_name
      end

      def validate_account_exists
        @validate_account_exists.(
          account: @account
        )
      end

      def validate_webservice_exists
        @validate_webservice_exists.(
          webservice: @webservice,
            account: @account
        )
      end

      def validate_user_is_defined
        raise Err::UserNotDefinedInConjur, @user_id unless user_role
      end

      def validate_user_has_access
        # Ensure user has access to the service
        has_access = user_role.allowed_to?('authenticate', webservice_resource)
        unless has_access
          @logger.debug(Log::UserNotAuthorized
                          .new(@user_id, webservice_resource_id))
          raise Err::UserNotAuthorizedInConjur, @user_id
        end
      end

      def user_role_id
        @user_role_id ||= @role_class.roleid_from_username(@account, @user_id)
      end

      def user_role
        @user_role ||= @role_class[user_role_id]
      end

      def webservice_resource
        @resource_class[webservice_resource_id]
      end

      def webservice_resource_id
        @webservice.resource_id
      end
    end
  end
end
