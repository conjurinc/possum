# frozen_string_literal: true

require 'util/error_class'

# Utility methods for authenticators
#
module AuthenticatorHelpers

  MissingEnvVarirable = ::Util::ErrorClass.new(
    'Environment variable [{0}] is not defined'
  )

  def validated_env_var(var)
    raise MissingEnvVarirable, var if ENV[var].blank?
    ENV[var]
  end

  # Mostly to document the mutable variables that are in play.
  # To at least mitigate the poor design encouraged by the way cucumber
  # shares state
  #
  attr_reader :response_body, :http_status, :rest_client_error, :ldap_auth_key

  def save_variable_value(account, variable_name, value)
    resource_id = [account, "variable", variable_name].join(":")
    conjur_api.resource(resource_id).add_value(value)
  end

  def token_for(username, token_string)
    return nil unless http_status == 200
    ConjurToken.new(token_string).username == username
  rescue
    nil
  end

  def token_for_keys(keys, token_string)
    return nil unless http_status == 200
    token = JSON.parse(token_string)
    keys.all? { |k| token.key? k }
  rescue
    nil
  end

  def bad_request?
    http_status == 400
  end

  def unauthorized?
    http_status == 401
  end

  def forbidden?
    http_status == 403
  end

  def bad_gateway?
    http_status == 502
  end

  def read_timeout?
    rest_client_error.class == RestClient::Exceptions::ReadTimeout
  end

  def load_root_policy(policy)
    conjur_api.load_policy('root', policy,
                           method: Conjur::API::POLICY_METHOD_PUT)
  end

  def get(path, options = {})
    options = options.merge(
      method: :get,
      url: path
    )
    result             = RestClient::Request.execute(options)
    @response_body     = result.body
    @http_status       = result.code
  rescue RestClient::Exception => err
    @rest_client_error = err
    @http_status       = err.http_code
    @response_body     = err.response
  end

  def post(path, payload, options = {})
    result             = RestClient.post(path, payload, options)
    @response_body     = result.body
    @http_status       = result.code

  rescue RestClient::Exception => err
    @rest_client_error = err
    @http_status       = err.http_code
    @response_body     = err.response
  end

  def execute(method, path, payload = {}, options = {})
    result             = RestClient::Request.execute(method: method, url: path, payload: payload, **options)
    @response_body     = result.body
    @http_status       = result.code

  rescue RestClient::Exception => err
    @rest_client_error = err
    @http_status       = err.http_code
    @response_body     = err.response
  end

  def conjur_hostname
    ENV.fetch('CONJUR_APPLIANCE_URL', 'http://conjur')
  end

  private

  def admin_password
    ENV['CONJUR_AUTHN_API_KEY'] || 'admin'
  end

  def admin_api_key
    @admin_api_key ||= Conjur::API.login('admin', admin_password)
  end

  def conjur_api
    @conjur_api ||= api_for('admin', admin_api_key)
  end

  def api_for(username, api_key = nil)
    api_key = admin_api_key if username == 'admin'
    api_key ||= Conjur::API.new_from_key('admin', admin_api_key).role(
                  full_username(username)).rotate_api_key
    Conjur::API.new_from_key(username, api_key)
  end

  def full_username(username, account: Conjur.configuration.account)
    "#{account}:user:#{username}"
  end
end

World(AuthenticatorHelpers)
