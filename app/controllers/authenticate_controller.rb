# frozen_string_literal: true

class AuthenticateController < ApplicationController
  include BasicAuthenticator
  include AuthorizeResource

  def index
    authenticators = {
      # Installed authenticator plugins
      installed: installed_authenticators.keys.sort,

      # Authenticator webservices created in policy
      configured: configured_authenticators.sort,

      # Authenticators white-listed in CONJUR_AUTHENTICATORS
      enabled: enabled_authenticators.sort
    }

    render json: authenticators
  end

  def status
    Authentication::ValidateStatus.new.(
      authenticator_name: params[:authenticator],
        account: params[:account],
        authenticator_webservice: ::Authentication::Webservice.new(
          account: params[:account],
          authenticator_name: params[:authenticator],
          service_id: params[:service_id]
        ),
        user: current_user
    )
    status_success_json
  rescue => e
    status_failure_json(e)
  end

  def login
    result = perform_basic_authn
    raise Unauthorized, "Client not authenticated" unless authentication.authenticated?
    render text: result.authentication_key
  end

  def authenticate
    authn_token = Authentication::Authenticate.new.(
      authenticator_input: authenticator_input,
        authenticators: installed_authenticators
    )
    render json: authn_token
  rescue => e
    handle_authentication_error(e)
  end

  def authenticator_input
    Authentication::AuthenticatorInput.new(
      authenticator_name: params[:authenticator],
      service_id: params[:service_id],
      account: params[:account],
      username: params[:id],
      password: request.body.read,
      origin: request.ip,
      request: request
    )
  end

  # - Prepare ID Token request
  # - Get ID Token with code from OpenID Provider
  # - Validate ID Token
  # - Link user details to Conjur User
  # - Check user has permissions
  # - Encrypt ID Token
  #
  # Returns IDToken encrypted, Expiration Duration and Username
  def login_oidc
    oidc_encrypted_token = Authentication::AuthnOidc::GetConjurOidcToken::ConjurOidcToken.new.(
      authenticator_input: oidc_authenticator_input
    )
    render json: oidc_encrypted_token
  rescue => e
    handle_authentication_error(e)
  end

  # - Decrypt ID token
  # - Validate ID Token
  # - Check user permission
  # - Introspect ID Token
  #
  # Returns Conjur access token
  def authenticate_oidc_conjur_token
    authentication_token = Authentication::AuthnOidc::AuthenticateOidcConjurToken::Authenticate.new.(
      authenticator_input: oidc_authenticator_input
    )
    render json: authentication_token
  rescue => e
    handle_authentication_error(e)
  end

  def authenticate_oidc
    authentication_token = Authentication::AuthnOidc::AuthenticateIdToken::Authenticate.new.(
      authenticator_input: oidc_authenticator_input
    )
    render json: authentication_token
  rescue => e
    handle_authentication_error(e)
  end

  def oidc_authenticator_input
    Authentication::AuthenticatorInput.new(
      authenticator_name: 'authn-oidc',
      service_id: params[:service_id],
      account: params[:account],
      username: nil,
      password: nil,
      origin: request.ip,
      request: request
    )
  end

  def k8s_inject_client_cert
    # TODO: add this to initializer
    Authentication::AuthnK8s::InjectClientCert.new.(
      conjur_account: ENV['CONJUR_ACCOUNT'],
        service_id: params[:service_id],
        csr: request.body.read
    )
    head :ok
  rescue => e
    handle_authentication_error(e)
  end

  private

  def handle_authentication_error(err)
    logger.debug("Authentication Error: #{err.inspect}")
    err.backtrace.each do |line|
      logger.debug(line)
    end

    case err
    when Errors::Authentication::Security::NotWhitelisted,
      Errors::Authentication::Security::ServiceNotDefined,
      Errors::Authentication::Security::UserNotDefinedInConjur,
      Errors::Authentication::Security::AccountNotDefined,
      Errors::Authentication::AuthnOidc::IdTokenFieldNotFoundOrEmpty,
      Errors::Authentication::AuthnOidc::IdTokenVerifyFailed,
      Errors::Authentication::AuthnOidc::IdTokenInvalidFormat,
      Errors::Conjur::RequiredSecretMissing,
      Errors::Conjur::RequiredResourceMissing
      raise Unauthorized

    when Errors::Authentication::Security::UserNotAuthorizedInConjur
      raise Forbidden

    when Errors::Authentication::RequestBody::MissingRequestParam
      raise BadRequest

    when Errors::Authentication::AuthnOidc::IdTokenExpired
      raise Unauthorized.new(err.message, true)

    when Errors::Authentication::AuthnOidc::ProviderDiscoveryTimeout
      raise GatewayTimeout

    when Errors::Util::ConcurrencyLimitReachedBeforeCacheInitialization
      raise ServiceUnavailable

    when Errors::Authentication::AuthnOidc::ProviderDiscoveryFailed,
      Errors::Authentication::AuthnOidc::ProviderFetchCertificateFailed
      raise BadGateway

    else
      raise Unauthorized
    end
  end

  def status_success_json
    claims = {
      status: "ok"
    }

    render json: JSON[claims]
  end

  def status_failure_json(error)
    claims = {
      status: "error",
      error: error.inspect
    }

    case error
    when Err::Security::UserNotAuthorizedInConjur
      status_code = :forbidden

    when Err::StatusNotImplemented
      status_code = :not_implemented

    when Err::AuthenticatorNotFound
      status_code = :not_found

    else
      status_code = :internal_server_error
    end

    render json: JSON[claims], status: status_code
  end

  def installed_authenticators
    @installed_authenticators ||= Authentication::InstalledAuthenticators.authenticators(ENV)
  end

  def configured_authenticators
    @configured_authenticators ||= Authentication::InstalledAuthenticators.configured_authenticators
  end

  def enabled_authenticators
    Authentication::InstalledAuthenticators.enabled_authenticators(ENV)
  end
end
