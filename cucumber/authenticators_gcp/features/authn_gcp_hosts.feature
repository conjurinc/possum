Feature: GCP Authenticator - Test hosts can authentication scenarios

  In this feature we define GCP authenticator in policy, test with different
  host configurations and perform authentication with Conjur.

  Background:
    Given I load a policy:
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
    And I have host "test-app"
    And I obtain a valid GCP identity token
    And I grant group "conjur/authn-gcp/apps" to host "test-app"


  Scenario: Host with all valid annotations except for project-id is denied
    Given I set invalid "authn-gcp/project-id" annotation to host "test-app"
    And I set "authn-gcp/service-account-id" annotation to host "test-app"
    And I set "authn-gcp/service-account-email" annotation to host "test-app"
    And I set "authn-gcp/instance-name" annotation to host "test-app"
    And I save my place in the log file
    When I authenticate with authn-gcp using valid token and existing account
    Then it is unauthorized
    And The following appears in the log after my savepoint:
    """
    CONJ00049E Resource restriction 'authn-gcp/project-id' does not match resource in JWT token
    """

  Scenario: Host with all valid annotations except for instance-name is denied
    Given I set invalid "authn-gcp/instance-name" annotation to host "test-app"
    And I set "authn-gcp/project-id" annotation to host "test-app"
    And I set "authn-gcp/service-account-id" annotation to host "test-app"
    And I set "authn-gcp/service-account-email" annotation to host "test-app"
    And I save my place in the log file
    When I authenticate with authn-gcp using valid token and existing account
    Then it is unauthorized
    And The following appears in the log after my savepoint:
    """
    CONJ00049E Resource restriction 'authn-gcp/instance-name' does not match resource in JWT token
    """

  Scenario: Host with all valid annotations except for service-account-email is denied
    Given I set invalid "authn-gcp/service-account-email" annotation to host "test-app"
    And I set "authn-gcp/project-id" annotation to host "test-app"
    And I set "authn-gcp/service-account-id" annotation to host "test-app"
    And I set "authn-gcp/instance-name" annotation to host "test-app"
    And I save my place in the log file
    When I authenticate with authn-gcp using valid token and existing account
    Then it is unauthorized
    And The following appears in the log after my savepoint:
    """
    CONJ00049E Resource restriction 'authn-gcp/service-account-email' does not match resource in JWT token
    """

  Scenario: Host with all valid annotations except for service-account-id is denied
    Given I set invalid "authn-gcp/service-account-id" annotation to host "test-app"
    And I set "authn-gcp/project-id" annotation to host "test-app"
    And I set "authn-gcp/service-account-email" annotation to host "test-app"
    And I set "authn-gcp/instance-name" annotation to host "test-app"
    And I save my place in the log file
    When I authenticate with authn-gcp using valid token and existing account
    Then it is unauthorized
    And The following appears in the log after my savepoint:
    """
    CONJ00049E Resource restriction 'authn-gcp/service-account-id' does not match resource in JWT token
    """

  Scenario: Host with all valid annotations and an illegal annotation key is denied
    Given I set "authn-gcp/invalid-key" annotation to host "test-app"
    And I set all valid GCP annotations to host "test-app"
    And I save my place in the log file
    When I authenticate with authn-gcp using valid token and existing account
    Then it is unauthorized
    And The following appears in the log after my savepoint:
    """
    CONJ00050E Resource type 'authn-gcp/invalid-key' is not a supported resource restriction
    """

  Scenario: Users can authenticate with GCP authenticator and fetch secret
    Given I have user "test-app"
    And I grant group "conjur/authn-gcp/apps" to user "test-app"
    And I have a "variable" resource called "test-variable"
    And I add the secret value "test-secret" to the resource "cucumber:variable:test-variable"
    And I permit user "test-app" to "execute" it
    And I set all valid GCP annotations to user "test-app"
    And I obtain a user_audience GCP identity token
    And I save my place in the log file
    When I authenticate with authn-gcp using obtained token and existing account
    Then user "test-app" has been authorized by Conjur
    And I can GET "/secrets/cucumber/variable/test-variable" with authorized user
    And The following appears in the audit log after my savepoint:
    """
    cucumber:user:test-app successfully authenticated with authenticator authn-gcp service cucumber:webservice:conjur/authn-gcp
    """

  Scenario: Non-existing host is denied
    Given I obtain a non_existing_host GCP identity token
    And I save my place in the log file
    When I authenticate with authn-gcp using obtained token and existing account
    Then it is unauthorized
    And The following appears in the log after my savepoint:
    """
    CONJ00007E 'host/non-existing' not found
    """

  Scenario: Hosts defined outside of root can authenticate with GCP authenticator and fetch secret
    Given I have host "non-rooted/test-app"
    And I set all valid GCP annotations to host "non-rooted/test-app"
    And I grant group "conjur/authn-gcp/apps" to host "non-rooted/test-app"
    And I have a "variable" resource called "test-variable"
    And I add the secret value "test-secret" to the resource "cucumber:variable:test-variable"
    And I permit host "non-rooted/test-app" to "execute" it
    And I set all valid GCP annotations to host "test-app"
    Given I obtain a non_rooted_host GCP identity token
    And I save my place in the log file
    When I authenticate with authn-gcp using obtained token and existing account
    Then host "non-rooted/test-app" has been authorized by Conjur
    And I can GET "/secrets/cucumber/variable/test-variable" with authorized user
    And The following appears in the audit log after my savepoint:
    """
    cucumber:host:non-rooted/test-app successfully authenticated with authenticator authn-gcp service cucumber:webservice:conjur/authn-gcp
    """
