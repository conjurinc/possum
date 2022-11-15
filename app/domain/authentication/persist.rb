# frozen_string_literal: true

require 'command_class'

module Authentication

  module Default
    # Performs additional setup for newly persisted authenticators
    class InitializeDefaultAuth
      extend CommandClass::Include
      include AuthorizeResource

      command_class(
        dependencies: {
          secret: Secret
        },
        inputs: %i[conjur_account service_id auth_data current_user]
      ) do
        def call
          @auth_data&.parameters&.each do |key, value|
            policy_branch = "conjur/#{@auth_data.auth_name}/#{@service_id}"
            variable_id = "#{@conjur_account}:variable:#{policy_branch}/#{key}"

            auth(@current_user, :update, Resource[variable_id])
            @secret.create(resource_id: variable_id, value: value)
          end
        end
      end

    end
  end

  # Persists a new authenticator + webservice in Conjur
  class PersistAuth
    extend CommandClass::Include

    command_class(
      dependencies: {
        logger: Rails.logger,
        auth_initializer: Authentication::Default::InitializeDefaultAuth.new,
        policy_loader: Policy::LoadPolicy.new,
        auth_data_class: Authentication::AuthnK8s::AuthenticatorData,
        application_controller: ApplicationController
      },
      inputs: %i[conjur_account service_id resource current_user client_ip request_data]
    ) do
      def call
        auth_data = @auth_data_class.new(@request_data)
        raise ArgumentError, auth_data.errors.full_messages unless auth_data.valid?

        policy_details = @policy_loader.(
          delete_permitted: false,
          action: :update,
          resource: @resource,
          policy_text: @application_controller.renderer.render(
            template: "policies/#{auth_data.auth_name}",
            locals: { service_id: @service_id, auth_data: auth_data }
          ),
          current_user: @current_user,
          client_ip: @client_ip
        )

        @auth_initializer.(conjur_account: @conjur_account, service_id: @service_id, auth_data: auth_data, current_user: @current_user)

        policy_details
      end
    end
  end

end
