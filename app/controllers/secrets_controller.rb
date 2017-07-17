class SecretsController < RestController
  include FindResource
  include AuthorizeResource
  
  before_filter :current_user
  before_filter :find_resource, except: [:batch]
  
  def create
    authorize :update
    
    value = request.raw_post

    raise ArgumentError, "'value' may not be empty" if value.blank?

    Secret.create resource_id: @resource.id, value: value
    @resource.enforce_secrets_version_limit
          
    head :created
  end
  
  def show
    authorize :execute
    
    version = params[:version]
    secret = if version.is_a?(String) && version.to_i.to_s == version
      @resource.secrets.find{|s| s.version == version.to_i}
    elsif version.nil?
      @resource.secrets.last
    else
      raise ArgumentError, "invalid type for parameter 'version'"
    end
    raise Exceptions::RecordNotFound.new(@resource.id, message: "Requested version does not exist") if secret.nil?
    value = secret.value
    
    mime_type = if ( a = @resource.annotations_dataset.select(:value).where(name: 'conjur/mime_type').first )
      a[:value]
    end
    mime_type ||= 'application/octet-stream'

    render text: value, content_type: mime_type
  end

  def batch
    variable_ids = params[:variable_ids].split(',')
    variables = Resource.where(resource_id: variable_ids).all

    missing_variables =
      variable_ids - variables.map(&:resource_id)

    unless missing_variables.empty?
      raise Exceptions::RecordNotFound, missing_variables[0]
    end

    result = {}

    authorize_many variables, :execute
    
    variables.each do |variable|
      if variable.secrets.last.nil?
        raise Exceptions::RecordNotFound, variable.resource_id
      end
      
      result[variable.resource_id] = variable.secrets.last.value
    end

    render json: result
  end
end
