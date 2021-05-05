# frozen_string_literal: true

module Authentication
  module AuthnJwt

    # FetchJwtClaimsToValidate command class is responsible to return a list of JWT standard claims to
    # validate, according to the following logic:
    # For each optional claim (iss, exp, nbf, iat) that exists in the token - add to mandatory list
    # Note: the list also contains the value to validate if necessary (for example iss: cyberark.com)
    FetchJwtClaimsToValidate ||= CommandClass.new(
      dependencies: {
        fetch_issuer_value: ::Authentication::AuthnJwt::FetchIssuerValue.new,
        jwt_claim_class: ::Authentication::AuthnJwt::JwtClaim,
        logger: Rails.logger
      },
      inputs: %i[authentication_parameters]
    ) do

      def call
        @logger.debug(LogMessages::Authentication::AuthnJwt::FetchingJwtClaimsToValidate.new)
        fetch_jwt_claims_to_validate
        @logger.debug(LogMessages::Authentication::AuthnJwt::FetchedJwtClaimsToValidate.new)

        jwt_claims_to_validate
      end

      private

      OPTIONAL_CLAIMS = [ISS_CLAIM_NAME, EXP_CLAIM_NAME, NBF_CLAIM_NAME, IAT_CLAIM_NAME].freeze

      def fetch_jwt_claims_to_validate
        OPTIONAL_CLAIMS.each do |optional_claim|
          @logger.debug(LogMessages::Authentication::AuthnJwt::CheckingJwtClaimToValidate.new(optional_claim))

          if @authentication_parameters.decoded_token[optional_claim]
            add_to_jwt_claims_list(optional_claim)
          end
        end
      end

      def add_to_jwt_claims_list(claim)
        @logger.debug(LogMessages::Authentication::AuthnJwt::AddingJwtClaimToValidate.new(claim))

        jwt_claims_to_validate.push(
          @jwt_claim_class.new(
            name: claim,
            value: claim_value(claim)
          )
        )
      end

      def jwt_claims_to_validate
        @jwt_claims_to_validate ||= []
      end

      def claim_value(claim)
        case claim
        when ISS_CLAIM_NAME
          return @fetch_issuer_value.(@authentication_parameters)
        else
          # Claims that do not need an additional value to be validated will be set with nil value
          # For example: exp, nbf, iat
          nil
        end
      end
    end
  end
end
