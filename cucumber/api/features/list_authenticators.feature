@api
@authenticators
Feature: A user can view the various authenticators they can use.

  @smoke
  Scenario: List readable authenticators

    Given I load a policy:
    """
    - !policy
      id: conjur/authn-oidc/oidceast
      body:
      - !webservice

      - !variable provider-uri
      - !variable client-id
      - !variable client-secret

      - !variable claim-mapping

      - !variable nonce
      - !variable state

      - !group
        id: authenticatable
        annotations:
          description: Users who can authenticate using this authenticator

      - !permit
        role: !group authenticatable
        privilege: [ read, authenticate ]
        resource: !webservice
    """

    And I extend the policy with:
    """
    - !policy
      id: conjur/authn-oidc/okta
      body:
      - !webservice

      - !variable provider-uri
      - !variable client-id
      - !variable client-secret

      - !variable claim-mapping

      - !variable nonce
      - !variable state

      - !group
        id: authenticatable
        annotations:
          description: Users who can authenticate using this authenticator

      - !permit
        role: !group authenticatable
        privilege: [ read, authenticate ]
        resource: !webservice
    """
    Then I can add a secret to variable resource "conjur/authn-oidc/oidceast/provider-uri"
    Then I can add a secret to variable resource "conjur/authn-oidc/oidceast/client-id"
    Then I can add a secret to variable resource "conjur/authn-oidc/oidceast/client-secret"
    Then I can add a secret to variable resource "conjur/authn-oidc/oidceast/claim-mapping"
    Then I can add a secret to variable resource "conjur/authn-oidc/oidceast/nonce"
    Then I can add a secret to variable resource "conjur/authn-oidc/oidceast/state"
    Then I can add a secret to variable resource "conjur/authn-oidc/okta/provider-uri"
    Then I can add a secret to variable resource "conjur/authn-oidc/okta/client-id"
    Then I can add a secret to variable resource "conjur/authn-oidc/okta/client-secret"
    Then I can add a secret to variable resource "conjur/authn-oidc/okta/claim-mapping"
    Then I can add a secret to variable resource "conjur/authn-oidc/okta/nonce"
    Then I can add a secret to variable resource "conjur/authn-oidc/okta/state"
    Then the list of authenticators contains the service-id "oidceast"
    And I can fetch the authenticator by its service-id "oidceast"
    And it will return an empty array for "oidcwest"
