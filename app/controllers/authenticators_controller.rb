# frozen_string_literal: true

# REST endpoints for persisting authenticator configuration details in Conjur
class AuthenticatorsController < RestController
  include FindResource
  include AuthorizeResource
  
  before_action :current_user
  before_action :find_or_create_root_policy

  rescue_from Sequel::UniqueConstraintViolation, with: :concurrent_load

  # TODO: This endpoint (& host initialization) should return a 422 on no valid JSON body.
  def persist_auth
    loaded_policy = Authentication::PersistAuthFactory.new_from_authenticator(params[:authenticator]).(
      conjur_account: params[:account],
      service_id: params[:service_id],
      resource: find_or_create_root_policy,
      current_user: current_user,
      client_ip: request.ip,
      raw_post: request.raw_post
    )
    render(body: loaded_policy, content_type: "text/yaml", status: :created)
  end

  def persist_auth_host
    loaded_policy = Authentication::PersistAuthHost.new.(
      conjur_account: params[:account],
      service_id: params[:service_id],
      authenticator: params[:authenticator],
      resource: find_or_create_root_policy,
      current_user: current_user,
      client_ip: request.ip,
      host_data: host_details
    )
    render(body: loaded_policy, content_type: "text/yaml", status: :created)
  end

  protected

  def find_or_create_root_policy
    Loader::Types.find_or_create_root_policy(account)
  end

  private

  def host_details
    Authentication::AuthHostDetailsFactory.new_from_authenticator(params[:authenticator], request.raw_post)
  end

  def retry_delay
    rand(1..8)
  end

  # TODO: This method is duplicated in the policies controller
  def concurrent_load(_exception)
    response.headers['Retry-After'] = retry_delay
    render(json: {
      error: {
        code: "policy_conflict",
        message: "Concurrent policy load in progress, please retry"
      }
    }, status: :conflict)
  end
end
