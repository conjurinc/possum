module DB
  module Repository
    class AuthenticatorRepository
      def initialize(data_object:, resource_repository: ::Resource, logger: Rails.logger)
        @resource_repository = resource_repository
        @data_object = data_object
        @logger = logger
      end

      def find_all(type:, account:)
        @resource_repository.where(
          Sequel.like(
            :resource_id,
            "#{account}:webservice:conjur/#{type}/%"
          )
        ).all.map do |webservice|
          hydrate_authenticator(
            authenticator_hash: load_authenticator_attributes(
              account: account,
              id: webservice.id.split(':').last,
              type: type
            )
          )
        end.compact
      end

      def find(type:, account:,  service_id:)
        webservice =  @resource_repository.where(
          Sequel.like(
            :resource_id,
            "#{account}:webservice:conjur/#{type}/#{service_id}"
          )
        ).first
        return unless webservice

        hydrate_authenticator(
          authenticator_hash: load_authenticator_attributes(
            type: type,
            account: account,
            id: webservice.id.split(':').last
          )
        )
        # load_authenticator(account: account, id: webservice.id.split(':').last, type: type)
      end

      def exists?(type:, account:, service_id:)
        @resource_repository.with_pk("#{account}:webservice:conjur/#{type}/#{service_id}") != nil
      end

      def valid?(type:, account:, service_id:)

      end

      private

      def load_authenticator_attributes(type:, account:, id:)
        service_id = id.split('/')[2]
        variables = @resource_repository.where(
          Sequel.like(
            :resource_id,
            "#{account}:variable:conjur/#{type}/#{service_id}/%"
          )
        ).eager(:secrets).all

        {}.tap do |args|
          args[:account] = account
          args[:service_id] = service_id
          variables.each do |variable|
            next unless variable.secret

            args[variable.resource_id.split('/')[-1].underscore.to_sym] = variable.secret.value
          end
        end
      end

      def hydrate_authenticator(authenticator_hash:)
        begin
          @data_object.new(**authenticator_hash)
        rescue ArgumentError => e
          @logger.debug("DB::Repository::AuthenticatorRepository.load_authenticator - exception: #{e}")
          # @logger.debug("DB::Repository::AuthenticatorRepository.load_authenticator - invalid: #{args_list.inspect}")
          nil
        end
      end
    end
  end
end
