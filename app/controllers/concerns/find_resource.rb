# frozen_string_literal: true

module FindResource
  extend ActiveSupport::Concern

  def resource_id
    [ params[:account], params[:kind], params[:identifier] ].join(":")
  end

  protected

  def resource
    if resource_visible?
      resource!
    else
      raise Exceptions::RecordNotFound, resource_id
    end
  end

  def resource_exists?
    begin
      Resource[resource_id] ? true : false
    rescue NotFound
      false
    end
  end

  def resource_visible?
    @resource_visible ||= resource! && @resource.visible_to?(current_user)
  end

  private

  def resource!
    @resource ||= Resource[resource_id]
  end
end
