require 'command_class'

module Authentication
  module ResourceRestrictions

    ExtractResourceRestrictions = CommandClass.new(
      dependencies: {
        resource_restrictions_class: Authentication::ResourceRestrictions::ResourceRestrictions,
        get_restriction_from_annotation: Authentication::ResourceRestrictions::GetRestrictionFromAnnotation,
        role_class: ::Role,
        resource_class: ::Resource,
        logger: Rails.logger
      },
      inputs: %i[authenticator_name service_id role_name account]
    ) do
      def call
        @logger.debug(
          LogMessages::Authentication::ResourceRestrictions::ExtractingRestrictionsFromResource.new(
            @authenticator_name,
            @role_name
          )
        )

        fetch_resource_annotations
        extract_resource_restrictions_from_annotations
        create_resource_restrictions_object

        @logger.debug(LogMessages::Authentication::ResourceRestrictions::ExtractedResourceRestrictions.new(resource_restrictions.names))

        resource_restrictions
      end

      private

      def fetch_resource_annotations
        resource_annotations
      end

      def resource_annotations
        @resource_annotations ||=
          resource.annotations.each_with_object({}) do |annotation, result|
            annotation_values = annotation.values
            value = annotation_values[:value]
            next if value.blank?

            result[annotation_values[:name]] = value
          end
      end

      def resource
        # Validate role exists, otherwise getting role annotations return empty hash.
        role_id_from_username = @role_class.roleid_from_username(@account, @role_name)
        role_id_from_host = @role_class.roleid_from_host(@account, @role_name)
        resource = @resource_class[role_id_from_host]
        resource = @resource_class[role_id_from_username] unless resource
        raise Errors::Authentication::Security::RoleNotFound, role_id unless resource

        resource
      end

      def extract_resource_restrictions_from_annotations
        resource_restrictions_hash
      end

      def resource_restrictions_hash
        @resource_restrictions_hash ||=
          resource_annotations.each_with_object({}) do |(annotation_name, annotation_value), resource_restrictions_hash|
            add_restriction_to_hash(annotation_name, annotation_value, resource_restrictions_hash)
          end
      end

      def add_restriction_to_hash(annotation_name, annotation_value, resource_restrictions_hash)
        restriction_name, is_general_restriction = @get_restriction_from_annotation.new.call(
          annotation_name: annotation_name,
          authenticator_name: @authenticator_name,
          service_id: @service_id
        )

        return unless restriction_name

        # General restriction should not override existing restriction
        return if is_general_restriction && resource_restrictions_hash.include?(restriction_name)

        @logger.debug(LogMessages::Authentication::ResourceRestrictions::RetrievedAnnotationValue.new(annotation_name))

        resource_restrictions_hash[restriction_name] = annotation_value
      end

      def create_resource_restrictions_object
        resource_restrictions
      end

      def resource_restrictions
        @resource_restrictions ||= @resource_restrictions_class.new(
          resource_restrictions_hash: @resource_restrictions_hash
        )
      end
    end
  end
end
