# frozen_string_literal: true

require 'active_support'
require 'active_support/core_ext'
require 'net/ldap'

module Authentication
  module AuthnLdap

    class Server

      def self.new(uri:, base:, bind_dn:, bind_pw:, log: nil)
        Net::LDAP.new(options(log)).tap do |ldap|
          if uri
            uri_obj = URI.parse(uri)
            ldap.host = uri_obj.host
            ldap.port = uri_obj.port
            ldap.encryption(:simple_tls) if uri_obj.scheme == 'ldaps'
          end

          ldap.auth(bind_dn, bind_pw) if bind_dn
          ldap.base = base
        end
      end

      private

      def self.options(log)
        log ? {instrumentation_service: log} : {}
      end

    end

  end
end
