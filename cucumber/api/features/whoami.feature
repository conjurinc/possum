Feature: Who Am I

  Scenario: Audit entry

    Given I am a user named "alice"
    When I successfully GET "/whoami"
    Then there is an audit record matching:
    """
      <38>1 * * conjur * identity-check
      [subject@43868 role="cucumber:user:alice"]
      [auth@43868 user="cucumber:user:alice"]
      [client@43868 ip="*"]
      [action@43868 result="success" operation="check"]
      * *
      cucumber:user:alice checked its identity using whoami
    """