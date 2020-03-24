# frozen_string_literal: true

# See:
#   https://github.com/cucumber/cucumber/wiki/Step-Argument-Transforms
# for an explanation of this cucumber feature.
#
# TODO: Transform is now deprecated.  We should rewrite these as ParameterTypes:
#     https://cucumber.io/blog/2017/09/21/upgrading-to-cucumber-3

# Replaces:
#   @response_api_key@ with the actual @response_api_key
#
# Transform(/@response_api_key@/) do |item|
#   @response_api_key ? item.gsub("@response_api_key@", @response_api_key) : item
# end
ParameterType(
  name: 'response_api_key',
  regexp: /@response_api_key@/,
  prefer_for_regexp_match: true,
  transformer: ->(item) do
    @response_api_key ? item.gsub("@response_api_key@", @response_api_key) : item
  end
)

# Replaces:
#   @host_factory_token_expiration@ with an actual expiration time
#   @host_factory_token_token@ with an actual token
#
DummyToken = Struct.new(:token, :expiration)

# Transform(/@host_factory.+@/) do |item|
#   token = @host_factory_token || DummyToken.new(
#     @result[0]['token'], Time.parse(@result[0]['expiration'])
#   )
  
#   item.gsub("@host_factory_token_expiration@", token.expiration.utc.iso8601)
#       .gsub("@host_factory_token_token@", token.token)
# end

# TODO: perhaps fix this to take @host_factory_token as arg?
def render_hf_token(tmpl)
  return tmpl unless @result
  return tmpl unless @result[0]
  return tmpl unless @result[0]['token']
  tmpl.gsub("@host_factory_token@", @result[0]['token'])
end

def render_hf_token_expiration(tmpl)
  return tmpl unless @result
  return tmpl unless @result[0]
  return tmpl unless @result[0]['token']
  exp = parse_expiration(@result[0]['expiration'])
  tmpl.gsub("@host_factory_token_expiration@", exp)
end

def parse_expiration(exp)
  Time.parse(exp).utc.iso8601
end

def render_hf(tmpl)
  render_hf_token_expiration(render_hf_token(tmpl))
end

# TODO This should probably be two types
ParameterType(
  name: 'host_factory_token',
  regexp: /@host_factory_token@/,
  transformer: ->(item) do
    # TODO: This coupling to global state is terrible, but seems to be
    #       unvoidable using the cucumber World approach.
    # TODO: replace these bodies with functions above
    token = @host_factory_token || DummyToken.new(
      @result[0]['token'], parse_expiration(@result[0]['expiration'])
    )
    
    item.gsub("@host_factory_token@", token.token)
  end
)

ParameterType(
  name: 'host_factory_token_expiration',
  regexp: /@host_factory_token_expiration@/,
  transformer: ->(item) do
    # TODO: This coupling to global state is terrible, but seems to be
    #       unvoidable using the cucumber World approach.
    token = @host_factory_token || DummyToken.new(
      @result[0]['token'], parse_expiration(@result[0]['expiration'])
    )
    
    item.gsub("@host_factory_token_expiration@", token.expiration)
  end
)
