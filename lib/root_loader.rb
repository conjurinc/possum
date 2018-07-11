# frozen_string_literal: true

# BootstrapLoader is used to load an initial "root" policy when the database is completely empty.
class RootLoader
  class << self
    # Load a policy into the specified account.
    # 
    # The policy will be owned by the 'user:admin' role. If the environment variable CONJUR_ADMIN_PASSWORD
    # exists, it will be used as the admin password (potentially resetting the existing password).
    #
    # The policy id is "root". The role and resource records for the policy will be created automatically
    # if they don't already exist. 
    def load account, filename
      start_t = Time.now
      Sequel::Model.db.transaction do
        admin_id = "#{account}:user:admin"
        admin = ::Role[admin_id] || ::Role.create(role_id: admin_id)
        if admin_password = ENV['CONJUR_ADMIN_PASSWORD']
          $stderr.puts "Setting 'admin' password"
          admin_credentials = Credentials[role: admin] || Credentials.create(role: admin)
          admin_credentials.password = admin_password
          admin_credentials.save
        end

        root_policy_resource = Loader::Types.find_or_create_root_policy(account)

        policy_version = PolicyVersion.new role: admin, policy: root_policy_resource, policy_text: File.read(filename)
        policy_version.policy_filename = filename
        policy_version.perform_automatic_deletion = true
        policy_version.delete_permitted = true
        policy_version.update_permitted = true
        policy_version.save

        loader = Loader::Orchestrate.new policy_version
        loader.load
      end
      end_t = Time.now
      $stderr.puts "Loaded policy in #{end_t - start_t} seconds"
    end
  end
end
