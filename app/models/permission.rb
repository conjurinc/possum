class Permission < Sequel::Model
  unrestrict_primary_key

  many_to_one :resource, reciprocal: :permissions
  many_to_one :role

  # Converts to JSON with given `options`
  def as_json options = {}
    super(options).tap do |response|
      %w(resource role policy).each do |field|
        write_id_to_json response, field
      end
    end
  end
end
