# frozen_string_literal: true

require './app/domain/responses'

# This controller is responsible for managing resources created by
# Policy Factory templates
class PolicyFactoryResourcesController < RestController
  include AuthorizeResource
  include PolicyFactory

  before_action :current_user

  # Create a resource(s) from a factory
  def create
    available_params = relevant_params(%i[account kind version id])

    response = DB::Repository::PolicyFactoryRepository.new.find(
      role: current_user,
      kind: available_params[:kind],
      account: available_params[:account],
      id: available_params[:id],
      version: available_params[:version]
    ).bind do |factory|
      Factories::CreateFromPolicyFactory.new.call(
        account: available_params[:account],
        factory_template: factory,
        request_body: request.body.read,
        role: current_user,
        request_ip: request.remote_ip,
        request_method: request.request_method
      )
    end

    render_response(response) do
      render(json: response.result, status: :created)
    end
  end
<<<<<<< HEAD

  def enable
    toggle_factory_circuit_breaker('enable')
  end

  def disable
    toggle_factory_circuit_breaker('disable')
  end

  private

  def toggle_factory_circuit_breaker(action)
    response = Factories::ResourceCircuitBreaker.new.call(
      account: params[:account],
      policy_identifier: params[:policy_identifier],
      action: action,
      role: current_user,
      request_ip: request.remote_ip
    )
    render_response(response) do
      render(json: response.result)
    end
  end
=======
>>>>>>> 0874e903e (Remove all experimental/partially implemented features)
end
