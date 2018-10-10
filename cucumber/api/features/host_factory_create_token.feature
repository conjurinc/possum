@logged-in
Feature: Create a host factory token.

  Background:
    Given I create a new user "alice"
    And I create a host factory for layer "the-layer"


  Scenario: A host factory is invisible without some permission on it
    Given I login as "alice"

    When I POST "/host_factory_tokens?host_factory=cucumber:host_factory:the-layer-factory&expiration=2050-12-31"
    Then the HTTP response status code is 404

  Scenario: Unauthorized users cannot create host factory tokens.
    Given I permit user "alice" to "read" it
    And I login as "alice"
    When I POST "/host_factory_tokens?host_factory=cucumber:host_factory:the-layer-factory&expiration=2050-12-31"
    Then the HTTP response status code is 403

  Scenario: A host factory token can be created by specifying an expiration time.
    Given I permit user "alice" to "execute" it
    And I login as "alice"
    When I successfully POST "/host_factory_tokens?host_factory=cucumber:host_factory:the-layer-factory&expiration=2050-12-31"
    Then the JSON should be:
    """
    [
      {
        "cidr": [],
        "expiration": "2050-12-31T00:00:00Z",
        "token": "@host_factory_token_token@"
      }
    ]
    """
