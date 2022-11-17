# frozen_string_literal: true

require 'app/models/loader/orchestrate'
require 'app/domain/logs'
require 'app/models/policy_version'

class PolicyExporter
  def initialize(policy_version: PolicyVersion)
    @policy_version = policy_version
  end

  def export(format:)
    if format == "stream"
      puts policy_list.map{ |p| p.strip }.join("\n")
    else
      create_files
    end
  end

  private

  def add_policy_comment(policy)
    <<~POLICY
    ---
    # policy for branch #{policy.policy_branch_name} automatically generated
    # by rake policy:export at #{Time.now}
    #
    # Load this policy into conjur using the cli with
    #     conur policy load root #{policy.policy_branch_name}.yaml
    #{policy.working_policy_text}
    POLICY
  end

  def policy_list
    all_current_policies.map do |policy|
       add_policy_comment(policy)
    end
  end

  def all_current_policies
    PolicyVersion.distinct(:resource_id).reverse_order(:resource_id, :version).all.sort do |a, b|
      b.created_at - a.created_at
    end
  end
  
  def create_files
    PolicyVersion.all_current_policies.each_with_index do |policy, index|
      File.open("#{policy.policy_branch_name}.policy.yaml", "w") { |f| f.write policy.working_policy_text }
    end
  end
end
