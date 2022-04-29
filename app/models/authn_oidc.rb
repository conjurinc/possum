class AuthnOidc

  def authenticators(role, account:, service_id: nil)
    repo = AuthenticatorRepo.new(role, account, service_id)
    variables = repo.fetch_authenticators
    return list_authenticators(variables) unless service_id

    find_service(variables, service_id)
  end

  def list_authenticators(variables)
    args_list = []
    variables.each do |variable|
      args = {}
      args[:service_id] = variable.owner_id.split('/')[-1].underscore.to_sym
      args[variable.resource_id.split('/')[-1].underscore.to_sym] =
        variable.secret.value
      args_list.push(args)
    end
    args_list.group_by{|authn| authn[:service_id]}.map do |_, authn|
      Authenticator.new(**authn.reduce({}, :merge)).return_service
    end
  end

  private

  def find_service(variables, service_id)
    return {} unless variables.count >=1

    args_list = {}.tap do |args|
      args[:service_id] = service_id
      variables.each do |variable|
        args[variable.resource_id.split('/')[-1].underscore.to_sym] =
          variable.secret.value
      end
    end
    Authenticator.new(**args_list).return_uri
  end

  class Authenticator
    attr_reader :service_id, :provider_uri, :client_id, :client_secret, :claim_mapping, :state, :nonce

    def initialize(service_id:, provider_uri:, client_id:, client_secret:, claim_mapping:, state:, nonce:)
      super()
      @service_id = service_id
      @provider_uri = provider_uri
      # @id_token_user_property = id_token_user_property

      @client_id = client_id
      @client_secret = client_secret
      @claim_mapping = claim_mapping
      @state = state
      @nonce = nonce
    end

    def return_service
      { service_id: @service_id, redirec_uri: create_redirect }
    end

    def return_uri
      { redirec_uri: create_redirect }
    end

    def create_redirect
      "#{@provider_uri}?client_id=#{@client_id}>" \
      "&redirect_uri=#{@provider_uri}&response_type=code&scope=" \
      "openid%2fprofile%2femail&state=#{@state}>&nonce=#{@nonce}" \
    end
  end

  class AuthenticatorRepo

    def initialize(
      role,
      account,
      service_id = nil,
      resource: ::Resource,
      secret: ::Secret
    )
      super()
      @resource = resource
      @secret = secret
      @role = role
      @account = account
      @service_id = service_id
    end

    def fetch_authenticators
      resources = @resource.visible_to(@role)
      variable_ids = resources.where(
        Sequel.like(
          :resource_id,
          authn_search(@account, @service_id)
        )
      ).map(:resource_id)
      resources.where(resource_id: variable_ids).eager(:secrets).all
    end

    private

    def authn_search(account, service_id)
      search = "#{account}:variable:conjur/authn-oidc"
      return "#{search}/%" unless service_id

      "#{search}/#{service_id}/%"
    end
  end
end
