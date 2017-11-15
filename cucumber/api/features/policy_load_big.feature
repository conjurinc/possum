Feature: Loading big policies

  The API can be used to load large policies (>= 2k roles)

  Scenario: I load a policy with 2k users, 2k groups
    Given I am the super-user
    Then I can PUT "/policies/cucumber/policy/root" with body from file "1k-users-1k-groups.yml"
