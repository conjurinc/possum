# frozen_string_literal: true

RSpec.describe Authentication::AuthnOidc::AuthenticateIdToken::DiscoverOIDCProvider do

  let (:test_provider_uri) { "test-provider-uri" }
  let (:test_error) { "test-error" }
  let (:mock_provider) { "test-provider" }

  def mock_discovery_provider(error:)
    double('discovery_provider').tap do |discovery_provider|
      if error
        allow(discovery_provider).to receive(:discover!)
                                       .and_raise(error)
      else
        allow(discovery_provider).to receive(:discover!)
                                       .and_return(mock_provider)
      end
    end
  end

  context "A discoverable Oidc provider" do
    subject do
      Authentication::AuthnOidc::AuthenticateIdToken::DiscoverOIDCProvider.new(
        open_id_discovery_service: mock_discovery_provider(error: nil)
      ).(
        provider_uri: test_provider_uri
      )
    end

    it "does not raise an error" do
      expect { subject }.to_not raise_error
    end

    it "returns the discovered provider" do
      expect(subject).to eq(mock_provider)
    end
  end

  context "A non-discoverable Oidc provider" do
    context "fails on timeout error" do
      subject do
        Authentication::AuthnOidc::AuthenticateIdToken::DiscoverOIDCProvider.new(
          open_id_discovery_service: mock_discovery_provider(error: HTTPClient::ConnectTimeoutError)
        ).(
          provider_uri: test_provider_uri
        )
      end

      it "returns a ProviderDiscoveryTimeout error" do
        expect { subject }.to raise_error(Errors::Authentication::AuthnOidc::ProviderDiscoveryTimeout)
      end

      context "fails on general error" do
        subject do
          Authentication::AuthnOidc::AuthenticateIdToken::DiscoverOIDCProvider.new(
            open_id_discovery_service: mock_discovery_provider(error: test_error)
          ).(
            provider_uri: test_provider_uri
          )
        end

        it "returns a ProviderDiscoveryFailed error" do
          expect { subject }.to raise_error(Errors::Authentication::AuthnOidc::ProviderDiscoveryFailed)
        end
      end
    end
  end
end