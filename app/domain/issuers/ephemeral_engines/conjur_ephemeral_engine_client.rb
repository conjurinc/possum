# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

require_relative('ephemeral_engine_client')

class ConjurEphemeralEngineClient
  include EphemeralEngineClient

  def initialize(logger:, request_id:, http_client: nil)
    if http_client
      @client = http_client
    else
      @client = Net::HTTP.new("http://127.0.0.1")
      @client.use_ssl = false  # Service mesh takes care of the TLS communication
    end
    @logger = logger
    @request_id = request_id
  end

  def get_ephemeral_secret(type, method, role_id, issuer_data, variable_data)
    request_body = {
      type: type,
      method: method,
      role: role_id,
      issuer: hash_keys_to_snake_case(issuer_data),
      secret: hash_keys_to_snake_case(variable_data)
    }

    # Create the POST request
    secret_request = Net::HTTP::Post.new("/secrets")
    secret_request.body = request_body.as_json

    # Add headers
    secret_request.add_field('Content-Type', 'application/json')
    secret_request.add_field('X-Request-ID', @request_id)
    secret_request.add_field('X-Tenant-ID', tenant_id)

    # Send the request and get the response
    @logger.info(LogMessages::Secrets::EphemeralSecretRemoteRequest.new(@request_id))
    begin
      response = @client.request(secret_request)
    rescue => e
      raise ApplicationController::InternalServerError, e.message
    end
    @logger.info(LogMessages::Secrets::EphemeralSecretRemoteResponse.new(@request_id, response.code))
    response_body = JSON.parse(response.body)

    case response.code.to_i
    when 200..299
      return JSON.parse(response.body)
    when 400..499
      raise ApplicationController::BadRequest, "Failed to create the ephemeral secret. Code: #{response_body['code']}, Message: #{response_body['message']}, description: #{response_body['description']}"
    else
      raise ApplicationController::InternalServerError, "Failed to create the ephemeral secret. Code: #{response_body['code']}, Message: #{response_body['message']}, description: #{response_body['description']}"
    end
  end

  protected

  def hash_keys_to_snake_case(hash, level = 0)
    result = {}
    hash.each do |key, value|
      transformed_key = key.to_s.gsub("-", "_").downcase

      # If the value is another hash, perform the same casting on that sub hash.
      # We don't want unexpected behavior so currently this is limited to one level of
      result[transformed_key] = if value.is_a?(Hash) && level.zero?
        hash_keys_to_snake_case(value, 1)
      else
        value
      end
    end
    result
  end

  def tenant_id
    Rails.application.config.conjur_config.tenant_id
  end
end