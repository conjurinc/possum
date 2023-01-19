module Audit
  module Event
    # Note: Breaking this class up further would harm clarity.
    # :reek:TooManyInstanceVariables and :reek:TooManyParameters
    class Policy

      def initialize(
        operation:,
        subject:,
        user: nil,
        policy_version: nil,
        client_ip: nil
      )
        @operation = operation
        @subject = subject
        @user = user
        @policy_version = policy_version
        @client_ip = client_ip
      end

      # Note: We want this class to be responsible for providing `progname`.
      # At the same time, `progname` is currently always "conjur" and this is
      # unlikely to change.  Moving `progname` into the constructor now
      # feels like premature optimization, so we ignore reek here.
      # :reek:UtilityFunction
      def progname
        Event.progname
      end

      def severity
        Syslog::LOG_NOTICE
      end

      def to_s
        message
      end

      # TODO: See issue https://github.com/cyberark/conjur/issues/1608
      # :reek:NilCheck
      def message
        past_tense_verb = @operation.to_s.chomp('e') + "ed"
        "#{@user&.id} #{past_tense_verb} #{@subject}"
      end

      def message_id
        "policy"
      end

      # TODO: See issue https://github.com/cyberark/conjur/issues/1608
      # :reek:NilCheck
      def structured_data
        {
          SDID::AUTH => { user: @user&.id },
          SDID::SUBJECT => @subject.to_h,
          SDID::ACTION => { operation: @operation },
          SDID::CLIENT => { ip: client_ip }
        }.tap do |sd|
          if @policy_version
            sd[SDID::POLICY] = {
              id: @policy_version.id,
              version: @policy_version.version
            }
          end
        end
      end

      def facility
        # Security or authorization messages which should be kept private. See:
        # https://github.com/ruby/ruby/blob/b753929806d0e42cdfde3f1a8dcdbf678f937e44/ext/syslog/syslog.c#L109
        # Note: Changed this to from LOG_AUTH to LOG_AUTHPRIV because the former
        # is deprecated.
        Syslog::LOG_AUTHPRIV
      end

      private

      def user
        @user || @policy_version.role
      end

      def client_ip
        @client_ip || @policy_version.client_ip
      end
    end
  end
end
