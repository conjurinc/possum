class AuthenticatorsController < RestController
  include FindResource
  include AssumedRole

  def index
    # Rails 5 requires parameters to be explicitly permitted before converting 
    # to Hash.  See: https://stackoverflow.com/a/46029524
    allowed_params = %i[account service_id]

    begin
      authn_oidc = AuthnOidc.new
      scope = authn_oidc.authenticators(
        assumed_role(query_role),
        **options(allowed_params)
      )
    rescue ApplicationController::Forbidden
      raise
    rescue ArgumentError => e
      raise ApplicationController::UnprocessableEntity, e.message
    end

    render(json: scope)
  end

  # The v5 API currently sends +acting_as+ when listing resources
  # for a role other than the current user.
  def query_role
    params[:role].presence || params[:acting_as].presence
  end

  def options(allowed_params)
    params.permit(*allowed_params)
      .slice(*allowed_params).to_h.symbolize_keys
  end
end
