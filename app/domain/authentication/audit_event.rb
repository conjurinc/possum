# frozen_string_literal: true

module Authentication

  AuditEvent = CommandClass.new(
    dependencies: {
      role_cls: ::Role,
      audit_log: ::Authentication::AuditLog
    },
    inputs: %i(resource_id authenticator_name account username success message)
  ) do

    def call
      @audit_log.record_authn_event(
        role: role,
        webservice_id: @resource_id,
        authenticator_name: @authenticator_name,
        success: @success,
        message: @message
      )
    end

    private

    def role
      return nil if username.nil?

      @role_cls.by_login(username, account: @account)
    end

    def username
      @username
    end
  end
end
