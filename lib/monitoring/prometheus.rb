require 'prometheus/client'
require 'prometheus/client/data_stores/direct_file_store'
require_relative './metrics/resource_count.rb'
require_relative './metrics/endpoint.rb'


module Monitoring
  class Prometheus
    class << self

      def registry
        @registry ||= ::Prometheus::Client.registry
      end

      def metrics
        @metrics ||= [
          Metrics::ResourceCount.new,
          Metrics::Endpoint.new
        ]
      end

      def metrics_dir_path
        @metrics_dir_path ||= ENV['CONJUR_METRICS_DIR'] || '/tmp/prometheus'
      end

      def configure_data_store
        ::Prometheus::Client.config.data_store = ::Prometheus::Client::DataStores::DirectFileStore.new(
          dir: ENV['CONJUR_METRICS_DIR'] || '/tmp/prometheus'
        )
      end

      def clear_data_store
        Dir[File.join(metrics_dir_path, '*.bin')].each do |file_path|
          File.unlink(file_path)
        end
      end

      def define_metrics
        metrics.each do |metric|
          metric.define_metric(registry)
        end
      end

      def init_metrics
        metrics.each do |metric|
          metric.init_metric(registry)
        end
      end
    end
  end
end