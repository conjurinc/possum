require_dependency 'authn_ldap/application_controller'
require 'authn_core'


module AuthnLdap
  class AuthenticateController < ApplicationController
    def authenticate

      login    = params[:login]

      # TODO: This line causes the request to hang until it times out.
      # return false unless validate_security_requirements(login)

      password = request.body.read
      account  = params[:account]
      token    = authenticator.auth(login, password, account)

      puts "**************************************************"
      puts "LDAP_URI: #{ENV['LDAP_URI']}"
      puts "LDAP_BASE: #{ENV['LDAP_BASE']}"
      puts "LDAP_BINDDN: #{ENV['LDAP_BINDDN']}"
      puts "LDAP_BINDPW: #{ENV['LDAP_BINDPW']}"

      if token
        render json: token.to_json
      else
        render json: { status: 401 }
      end

    end

    private

    def authenticator
      @authenticator ||= AuthnLdap::Authenticator.new(
        ldap_server: AuthnLdap::LdapServer.new(
          uri:     ENV['LDAP_URI'],
          base:    ENV['LDAP_BASE'],
          bind_dn: ENV['LDAP_BINDDN'],
          bind_pw: ENV['LDAP_BINDPW']
        ),
        ldap_filter: ENV['LDAP_FILTER']
      )
    end

    def validate_security_requirements(login)
      # service id is test
      # TODO: how should this be passed? ENV variable?
      security_requirements.validate('test', login)
    # rescue => e
    #   puts e
    end

    def security_requirements
      AuthenticatorSecurityRequirements.new(
        authn_type: 'ldap',
        whitelisted_authenticators: ENV['CONJUR_AUTHENTICATORS'],
        conjur_account: ENV['CONJUR_ACCOUNT']
      )
    end

  end
end
