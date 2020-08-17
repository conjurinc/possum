Feature: GCP Authenticator - Hosts can authenticate with GCP authenticator

  In this feature we define a Google Cloud Platform authenticator in policy and perform authentication
  with Conjur.
  In successful scenarios we will also define a variable and permit the host to
  execute it, to verify not only that the host can authenticate with the GCP
  Authenticator, but that it can retrieve a secret using the Conjur access token.

  Background:
    Given a policy:
    """
    - !policy
      id: conjur/authn-gcp
      body:
      - !webservice

      - !group apps

      - !permit
        role: !group apps
        privilege: [ read, authenticate ]
        resource: !webservice
    """
    And I am the super-user
    And I have host "test-app"
    And I grant group "conjur/authn-gcp/apps" to host "test-app"

  Scenario: Hosts can authenticate with GCP authenticator and fetch secret
    Given I have a "variable" resource called "test-variable"
    And I add the secret value "test-secret" to the resource "cucumber:variable:test-variable"
    And I permit host "test-app" to "execute" it
    And I set authn-gcp/service-account-id annotation to host "test-app"
    And I set authn-gcp/service-account-email annotation to host "test-app"
    And I set authn-gcp/project-id annotation to host "test-app"
    And I set authn-gcp/instance-name annotation to host "test-app"
    And I obtain a GCE identity token in "full" format with audience claim value: "conjur/cucumber/host/test-app"
    And I save my place in the audit log file
    When I authenticate with authn-gcp using GCP identity token
    Then host "test-app" has been authorized by Conjur
    And I can GET "/secrets/cucumber/variable/test-variable" with authorized user
    And The following appears in the audit log after my savepoint:
    """
    cucumber:host:test-app successfully authenticated with authenticator authn-gcp service cucumber:webservice:conjur/authn-gcp
    """
