# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::K8sResourceValidator) do
  subject {
    described_class.new(k8s_object_lookup: k8s_object_lookup, pod: pod)
  }

  let(:k8s_object_lookup) { double("k8s_object_lookup") }
  let(:pod) { double("pod") }

  context "#valid_namespace?" do
    it 'raises error on empty label selector' do
      expect { subject.valid_namespace?(label_selector: "") }.to(
        raise_error(
          ::Errors::Authentication::AuthnK8s::InvalidLabelSelector
        )
      )
    end

    it 'raises error on invalid label selector' do
      # No key-value pair
      expect { subject.valid_namespace?(label_selector: "key,") }.to(
        raise_error(
          ::Errors::Authentication::AuthnK8s::InvalidLabelSelector
        )
      )

      # Unsupported operator
      expect { subject.valid_namespace?(label_selector: "key!=value") }.to(
        raise_error(
          ::Errors::Authentication::AuthnK8s::InvalidLabelSelector
        )
      )
    end

    it 'returns true for labels matching label-selector' do
      pod.stub_chain("metadata.namespace").and_return("namespace_name")
      allow(k8s_object_lookup).to receive(:namespace_labels_hash)
        .with("namespace_name")
        .and_return({ :key1 => "value1", :key2 => "value2"})

      # Single key, single equals format
      expect(
        subject.valid_namespace?(label_selector: "key1=value1")
      ).to be true
      # Single key, double equals format
      expect(
        subject.valid_namespace?(label_selector: "key2==value2")
      ).to be true
      # Multiple keys
      expect(
        subject.valid_namespace?(label_selector: "key1=value1,key2=value2")
      ).to be true
    end

    it 'throws an error for labels not matching label-selector' do
      pod.stub_chain("metadata.namespace").and_return("namespace_name")
      allow(k8s_object_lookup).to receive(:namespace_labels_hash)
        .with("namespace_name")
        .and_return({ :key1 => "value1", :key2 => "value2"})

      # Value mismatch
      expect { subject.valid_namespace?(label_selector: "key1=notvalue") }.to(
        raise_error(
          ::Errors::Authentication::AuthnK8s::LabelSelectorMismatch
        )
      )
      # Key not found
      expect { subject.valid_namespace?(label_selector: "notfoundkey=value") }.to(
        raise_error(
          ::Errors::Authentication::AuthnK8s::LabelSelectorMismatch
        )
      )
      # One of multiple keys does not match
      expect { subject.valid_namespace?(label_selector: "key1=value1,notfoundkey=value") }.to(
        raise_error(
          ::Errors::Authentication::AuthnK8s::LabelSelectorMismatch
        )
      )
    end
  end
end
