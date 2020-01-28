# frozen_string_literal: true

require 'types'

module Authentication
  class AuthenticatorInput < ::Dry::Struct

    attribute :authenticator_name, ::Types::NonEmptyString
    attribute :service_id, ::Types::NonEmptyString.optional
    attribute :account, ::Types::NonEmptyString
    attribute :username, ::Types::NonEmptyString.optional
    attribute :request_body, ::Types::String.optional
    attribute :origin, ::Types::NonEmptyString
    attribute :request, ::Types::Any

    # Creates a copy of this object with the attributes updated by those
    # specified in hash
    #
    def update(hash)
      self.class.new(to_hash.merge(hash))
    end

    def webservice
      @webservice ||= ::Authentication::Webservice.new(
        account:            @account,
        authenticator_name: @authenticator_name,
        service_id:         @service_id
      )
    end
  end
end
