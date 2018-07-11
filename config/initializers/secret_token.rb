# frozen_string_literal: true

Possum::Application.config.secret_key_base = Object.new.tap do |o|
  def o.to_str
    fail "secret_key_base is intentionally not set for this application"
  end
end
