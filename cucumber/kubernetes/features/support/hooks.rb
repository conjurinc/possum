Before('@skip') do
  skip_this_scenario
end

Before('@k8s_skip') do
  skip_this_scenario if ENV['PLATFORM'] == 'kubernetes'
end

Before do
  # Erase the certificates and keys from each container.
  kubectl_client.get_pods(namespace: namespace).select{|p| p.metadata.namespace == namespace}.each do |pod|
    next unless ready_status = pod.status.conditions.find{|c| c.type == "Ready"}
    next unless ready_status.status == "True"
    next if pod.metadata.name =~ /conjur\-authn\-k8s/

    exec = Authentication::AuthnK8s::KubectlExec.new

    pod.spec.containers.each do |container|
      response = exec.execute(
        pod_namespace: pod.metadata.namespace,
        pod_name: pod.metadata.name,
        container: container.name,
        cmds: %w(ls /etc/conjur/ssl)
      )

      if response[:error] && response[:error].join =~ /command terminated with non-zero exit code/
      else
        # $stderr.puts "Cleaning /etc/conjur/ssl on container #{container.name} of Pod #{pod.metadata.name}"
        exec.execute(
          pod_namespace: pod.metadata.namespace,
          pod_name: pod.metadata.name,
          container: container.name,
          cmds: %w(rm /etc/conjur/ssl)
        )
      end
    end
  end
end
