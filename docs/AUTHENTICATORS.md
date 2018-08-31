# Using, securing, and creating authenticators

## Existing Authenticators

Links to the current Authenticator Feature specs:
* [Authn-LDAP](https://github.com/cyberark/conjur/issues/524)
* [Authn-IAM](https://github.com/cyberark/conjur/issues/542)

## Using authenticators

Successful authentication returns a new **Conjur token**, which you can use to
make subsequent requests to protected Conjur services.

To authenticate and receive this token, `POST` to:
```
/:authenticator-type/:optional-service-id/:conjur-account/:username/authenticate
```
with the password (or other credential relevant to your authenticator) as plain
text in the request body.

Let's break down the required pieces of this request:

- **authenticator-type:** The default Conjur authenticator type is `authn`, and
  all other authenticator types begin with the prefix `authn-`. For example,
  `authn-ldap` or `authn-my-awesome-authenticator`.
- **optional-service-id:** This is useful when you have two different
  "instances" of the same authenticator type.  For example, your company might
  have two LDAP directories, one for system administrators and one for
  developers.  These could both be enabled and accessed at the URLs
  `/authn-ldap/sysadmins/...` and `/authn-ldap/developers/...`.
- **conjur-account:** The Conjur account you'll be issued a token for.
- **username:** The username (from the point of view of the authenticator) of
  the person (or machine) requesting authentication.  In the case of default
  Conjur authentication, this would be your Conjur username.  In the case of
  LDAP authentication, this would be your LDAP username.
- **request body:** The plain text password or other credential relevant to
  your authenticator.  This could be an ordinary password, an API key, an
  OAuth token, etc -- depending on the type of authenticator.

## Security requirements

### Must whitelist before using

With the exception of the default Conjur authenticator named `authn`, all
authenticators must be explicitly whitelisted via the environment variable
`CONJUR_AUTHENTICATORS`.

1. If the environment variable `CONJUR_AUTHENTICATORS` is *not* set, the
   default Conjur authenticator will be automatically whitelisted and ready for
   use.  No other authenticators will be available in this case.
2. If the environment variable `CONJUR_AUTHENTICATORS` *is* set, then only the
   authenticators listed will be whitelisted.  This means that if
   `CONJUR_AUTHENTICATORS` is set and `authn` is not in the list, default
   Conjur authentication will not be available.

Here is an example `CONJUR_AUTHENTICATORS` which whitelists an LDAP
authenticator as well as the default Conjur authenticator:
```
CONJUR_AUTHENTICATORS=authn-ldap/sysadmins,authn
```

Note that this is a comma-separated list.

### Create webservice and authorize users 

Except for the default Conjur authenticator, authenticators must be listed as
webservices in your Conjur policy, and users must be authorized to use them.
This requires two steps:

1. Add the authenticator as a webservice in your conjur policy:
```yaml
- !policy
  id: conjur/my-authenticator/optional-service-id
```
2. Add any users that need to access it to your policy, and grant them the
   `authenticate` privilege.


## Creating custom authenticators:

1. Create a new directory under `/app/domain/authentication`.  For example:
```
/app/domain/authentication/my_authenticator
```
2. That directory must contain a file named `authenticator.rb`, with the
   following structure:
```ruby
module Authentication
  module MyAuthenticator
    
    class Authenticator
      def initialize(env:)
        # initialization code based on ENV config
      end

      def valid?(input)
        # input has 5 attributes:
        #
        #     input.authenticator_name
        #     input.service_id
        #     input.account
        #     input.username
        #     input.password
        #
        # return true for valid credentials, false otherwise
      end
    end

  end
end
```

### Other Notes

1. Your authenticator directory can contain other supporting files used by your
   authenticator.
2. Conjur will instantiate your authenticator at bootup.  By default, when your
   authenticator is instantiated by conjur, it will be passed the `ENV` through
   the kwarg `env`.  If you don't need any configuration from the environment,
   you can opt out like so:
```ruby
module Authentication
  module MyAuthenticator
    
    class Authenticator
      def self.requires_env_arg?
        false
      end

      def initialize
        # you could also omit this altogether
      end

      def valid?(input)
        # same as before
      end
    end

  end
end
```

### Technical Notes

This section should only be relevant to Conjur developers.  These are notes on
the design of authenticator system itself:

- The architecture is objects nested like Russian dolls.  All dependencies are
  passed explicitly through the constructor.
- It also uses `Dry::Struct` quite a bit.  You can think of this like an
  `ostruct` with built-in type checking, which cleans up what would otherwise
  be verbose validation and initialization code.
