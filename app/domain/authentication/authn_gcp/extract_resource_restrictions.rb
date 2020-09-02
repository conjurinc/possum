require 'command_class'

module Authentication
  module AuthnGcp

    # This class is responsible of restrictions extraction that are set on a Conjur host or user as annotations.
    ExtractResourceRestrictions = CommandClass.new(
      dependencies: {
        role_class:              ::Role,
        resource_class:          ::Resource,
        validate_account_exists: ::Authentication::Security::ValidateAccountExists.new,
        logger:                  Rails.logger
      },
      inputs:       %i(account username extraction_prefix)
    ) do

      def call
        validate_account_exists
        extract_resource_restrictions
        resource_restrictions
      end

      private

      def validate_account_exists
        @validate_account_exists.(
          account: @account
        )
      end

      def extract_resource_restrictions
        @logger.debug(
          LogMessages::Authentication::AuthnGcp::ExtractingRestrictionsFromResource.new(
            @extraction_prefix,
            @username
          )
        )
        prefixed_resource_annotations.select do |a|
          annotation_name = a.values[:name]
          resource_value = annotation_value(annotation_name)
          next unless resource_value
          resource_restrictions.push(
            ResourceRestriction.new(
              type: annotation_name,
              value: resource_value
            )
          )
        end
        @logger.debug(LogMessages::Authentication::AuthnGcp::ExtractedResourceRestrictions.new(resource_restrictions.length))
      end

      def prefixed_resource_annotations
        @prefixed_resource_annotations ||= role.annotations.select do |a|
          annotation_name = a.values[:name]
          annotation_name.start_with?(@extraction_prefix)
        end
      end

      def resource_restrictions
        @resource_restrictions ||= []
      end

      def annotation_value(name)
        annotation = prefixed_resource_annotations.find {|a| a.values[:name] == name}

        # return the value of the annotation if it exists, nil otherwise
        if annotation
          @logger.debug(LogMessages::Authentication::RetrievedAnnotationValue.new(name))
          annotation[:value]
        end
      end

      def role
        return @role if @role

        @role = @resource_class[role_id]
        raise Errors::Authentication::Security::RoleNotFound, role_id unless @role
        @role
      end

      def role_id
        @role_id ||= @role_class.roleid_from_username(@account, @username)
      end
    end
  end
end
