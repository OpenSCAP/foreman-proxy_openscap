require 'smart_proxy_openscap/openscap_exception'

module Proxy
  module OpenSCAP
    class PolicyGuide
      include ::Proxy::Log

      def generate_guide(file_content, policy_id)
        file = Tempfile.new
        file.write file_content
        file.rewind
        `oscap xccdf generate #{profile_opt policy_id} guide #{file.path}`
      rescue => e
        logger.debug e.message
        logger.debug e.backtrace.join("\n\t")
        raise OpenSCAPException, "Failed to generate policy guide, cause: #{e.message}"
      ensure
        file.close
        file.unlink
      end

      def profile_opt(policy_id)
        policy_id ? "--profile #{policy_id}" : ''
      end
    end
  end
end
