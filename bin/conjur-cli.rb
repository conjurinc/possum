require 'gli'

include GLI::App

program_desc "Command and control application for Conjur"
version File.read(File.expand_path("../VERSION", File.dirname(__FILE__)))
arguments :strict
subcommand_option_handling :normal

# Attempt to connect to the database.
def connect
  require 'sequel'

  def test_select
    fail "DATABASE_URL not set" unless ENV['DATABASE_URL']
    begin
      db = Sequel::Model.db = Sequel.connect(ENV['DATABASE_URL'])
      db['select 1'].first
    rescue
      false
    end
  end

  30.times do
    break if test_select
    $stderr.write '.'
    sleep 1
  end

  raise "Database is still unavailable. Aborting!" unless test_select

  true
end

desc 'Run the application server'
command :server do |c|
  c.desc 'Account to initialize'
  c.arg_name :name
  c.flag [ :a, :account ]

  c.desc 'Policy file to load into the server'
  c.arg_name :path
  c.flag [ :f, :file ]

  c.desc 'Server listen port'
  c.arg_name :port
  c.default_value ENV['PORT'] || '80'
  c.flag [ :p, :port ]

  c.desc 'Server bind address'
  c.default_value ENV['BIND_ADDRESS'] || '0.0.0.0'
  c.arg_name :ip
  c.flag [ :b, :'bind-address' ]

  c.action do |global_options,options,args|

    account = options[:account]

    connect

    system "rake db:migrate" or exit $?.exitstatus
    if account
      system "rake account:create[#{account}]" or exit $?.exitstatus
    end

    if file_name = options[:file]
      raise "account option is required with file option" unless account
      system "rake policy:load[#{account},#{file_name}]" or exit $?.exitstatus
    end


    Process.fork do
      exec "rails server -p #{options[:port]} -b #{options[:'bind-address']}"
    end
    Process.fork do
      exec "rake authn_local:run"
    end

    Process.waitall
  end
end

desc "Manage the policy"
command :policy do |cgrp|
  cgrp.desc "Load MAML policy from file(s)"
  cgrp.arg :account
  cgrp.arg :filename, :multiple
  cgrp.command :load do |c|
    c.action do |global_options,options,args|
      account, *file_names = args
      connect

      fail 'policy load failed' unless file_names.map { |file_name|
        system "rake policy:load[#{account},#{file_name}]"
      }.all?
    end
  end

  cgrp.desc "Watch a file and reload the policy if it's modified"
  cgrp.long_desc <<-DESC
To trigger a reload of the policy, replace the contents of the watched file with the path to
the policy. Of course, the path must be visible to the container which is running "conjurctl watch".
This can be a separate container from the application server. Both the application server and the
policy watcher should share the same backing database.


Example:


$ conjurctl watch /run/conjur/policy/load)"
  DESC

  cgrp.arg :account
  cgrp.arg :filename
  cgrp.command :watch do |c|
    c.action do |global_options,options,args|
      account, file_name = args
      connect

      exec "rake policy:watch[#{account},#{file_name}]"
    end
  end
end

desc "Manage the data encryption key"
command :"data-key" do |cgrp|
  cgrp.desc "Generate a data encryption key"
  cgrp.long_desc <<-DESC
Use this command to generate a new Base64-encoded 256 bit data encrytion key.
Once generated, this key should be placed into the environment of the Conjur
server. It will be used to encrypt all sensitive data which is stored in the
database, including the token-signing private key.


Example:


$ export CONJUR_DATA_KEY="$(conjurctl data-key generate)"
  DESC
  cgrp.command :generate do |c|
    c.action do |global_options,options,args|
      exec "rake data-key:generate"
    end
  end
end

desc "Manage accounts"
command :account do |cgrp|
  cgrp.desc "Create an organization account"
  cgrp.long_desc <<-DESC
Use this command to generate and store a new account, along with its 2048-bit RSA private key,
used to sign auth tokens, as well as the "admin" user API key.
The CONJUR_DATA_KEY must be available in the environment
when this command is called, since it's used to encrypt the token-signing key
in the database.

Example:

$ conjurctl account create myorg
  DESC
  cgrp.arg :account
  cgrp.command :create do |c|
    c.action do |global_options,options,args|
      account = args.first
      connect

      exec "rake account:create[#{account}]"
    end
  end

  cgrp.desc "Delete an organization account"
  cgrp.arg :account
  cgrp.command :delete do |c|
    c.action do |global_options,options,args|
      account = args.first
      connect

      exec "rake account:delete[#{account}]"
    end
  end
end

desc "Manage the database"
command :db do |cgrp|
  cgrp.desc "Create and/or upgrade the database schema"
  cgrp.command :migrate do |c|
    c.action do |global_options,options,args|

      connect

      exec "rake db:migrate"
    end
  end
end

desc "Manage roles"
command :role do |cgrp|
  cgrp.desc "Retrieve a role's API key"
  cgrp.arg :role_id, :multiple
  cgrp.command :"retrieve-key" do |c|
    c.action do |global_options,options,args|

      connect

      fail 'key retrieval failed' unless args.map { |id|
        system "rake role:retrieve-key[#{id}]"
      }.all?
    end
  end
end

exit run(ARGV)
