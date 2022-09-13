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
          load_authenticator(account: account, id: webservice.id.split(':').last, type: type)
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

        load_authenticator(account: account, id: webservice.id.split(':').last, type: type)
      end

      def exists?(type:, account:, service_id:)
        @resource_repository.with_pk("#{account}:webservice:conjur/#{type}/#{service_id}") != nil
      end

      private

      def load_authenticator(type:, account:, id:)
        service_id = id.split('/')[2]
        variables = @resource_repository.where(
          Sequel.like(
            :resource_id,
            "#{account}:variable:conjur/#{type}/#{service_id}/%"
          )
        ).eager(:secrets).all

        args_list = {}.tap do |args|
          args[:account] = account
          args[:service_id] = service_id
          variables.each do |variable|
            next unless variable.secret

            args[variable.resource_id.split('/')[-1].underscore.to_sym] = variable.secret.value
          end
        end

        args = @data_object.const_get('CONJUR_VARIABLE_SCHEMA').(args_list)
        if args.success?
          @data_object.new(**args.to_h.merge(account: account, service_id: service_id))
        else
          args.errors.each do |error|
            @logger.debug("DB::Repository::AuthenticatorRepository.load_authenticator - exception: #{error.inspect}")
          end
          nil
        end

        # begin
        #   binding.pry
        #   @logger.info(args_list.inspect)
        #   @data_object.new(**args_list)
        # rescue ArgumentError => e
        #   @logger.debug("DB::Repository::AuthenticatorRepository.load_authenticator - exception: #{e}")
        #   nil
        # end
      end
    end
  end
end
