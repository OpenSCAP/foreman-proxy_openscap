require 'smart_proxy_openscap/storage_fs'
require 'smart_proxy_openscap/openscap_exception'

module Proxy
  module OpenSCAP
    class ArfHtml
      include ::Proxy::Log

      def generate(cname, id, date, digest)
        file_path = file_path_in_storage cname, id, date, digest
        as_html file_path
      end

      def as_html(file_in_storage)
        `oscap xccdf generate report #{file_in_storage}`
      rescue => e
        logger.debug e.message
        logger.debug e.backtrace.join("\n\t")
        raise Proxy::OpenSCAP::ReportDecompressError, "Failed to generate report HTML, cause: #{e.message}"
      end

      def file_path_in_storage(cname, id, date, digest)
        path_to_dir = Proxy::OpenSCAP::Plugin.settings.reportsdir
        storage = Proxy::OpenSCAP::StorageFS.new(path_to_dir, cname, id, date)
        storage.get_path(digest)
      end
    end
  end
end
