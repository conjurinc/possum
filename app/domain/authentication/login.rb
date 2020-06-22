# frozen_string_literal: true

require 'command_class'

module Authentication

  Err ||= Errors::Authentication
  # Possible Errors Raised:
  # AuthenticatorNotFound, InvalidCredentials

  Login ||= CommandClass.new(
    dependencies: {
      validate_webservice_is_whitelisted:  ::Authentication::Security::ValidateWebserviceIsWhitelisted.new,
      validate_role_can_access_webservice: ::Authentication::Security::ValidateRoleCanAccessWebservice.new,
      audit_log:                           ::Audit.logger,
      role_cls:                            ::Role
    },
    inputs:       %i(authenticator_input authenticators enabled_authenticators)
  ) do

    extend Forwardable
    def_delegators(
      :@authenticator_input, :authenticator_name, :account, :username,
      :webservice, :role
    )

    def call
      validate_authenticator_exists
      validate_webservice_is_whitelisted
      validate_user_has_access_to_webservice
      validate_credentials
      audit_success
      new_login
    rescue => e
      audit_failure(e)
      raise e
    end

    private

    def authenticator
      @authenticator = @authenticators[authenticator_name]
    end

    def key
      @key = authenticator.login(@authenticator_input)
    end

    def validate_authenticator_exists
      raise Err::AuthenticatorNotFound, authenticator_name unless authenticator
    end

    def validate_credentials
      raise Err::InvalidCredentials unless key
    end

    def validate_webservice_is_whitelisted
      @validate_webservice_is_whitelisted.(
        webservice: webservice,
        account: account,
        enabled_authenticators: @enabled_authenticators
      )
    end

    def validate_user_has_access_to_webservice
      @validate_role_can_access_webservice.(
        webservice: webservice,
        account: account,
        user_id: username,
        privilege: 'authenticate'
      )
    end

    def audit_success
      @audit_log.log(
        ::Audit::Event::Authn::Login.new(
          authenticator_name: authenticator_name,
          service:            webservice,
          role:               role,
          success:            true,
          error_message:      nil
        )
      )
    end

    def audit_failure(err)
      @audit_log.log(
        ::Audit::Event::Authn::Login.new(
          authenticator_name: authenticator_name,
          service:            webservice,
          role:               role,
          success:            false,
          error_message:      err.message
        )
      )
    end

    def new_login
      LoginResponse.new(
        role_id:            role.id,
        authentication_key: key
      )
    end

    def role
      @role_cls.by_login(username, account: account)
    end
  end
end
