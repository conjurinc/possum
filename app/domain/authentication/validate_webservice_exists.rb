# frozen_string_literal: true

module Authentication

  module Security

    Err = Errors::Authentication::Security
    # Possible Errors Raised:
    # AccountNotDefined, ServiceNotDefined

    ValidateWebserviceExists = CommandClass.new(
      dependencies: {
        role_class: ::Role,
        resource_class: ::Resource,
      },
      inputs: %i(webservice account)
    ) do

      def call
        # No checks required for default conjur authn
        return if default_conjur_authn?

        validate_account_exists
        validate_webservice_exists
      end

      private

      def default_conjur_authn?
        @webservice.authenticator_name ==
          ::Authentication::Common.default_authenticator_name
      end

      def validate_account_exists
        raise Err::AccountNotDefined, @account unless account_admin_role
      end

      def validate_webservice_exists
        raise Err::ServiceNotDefined, @webservice.name unless webservice_resource
      end

      def account_admin_role
        @account_admin_role ||= @role_class["#{@account}:user:admin"]
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
