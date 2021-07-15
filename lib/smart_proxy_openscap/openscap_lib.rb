#
# Copyright (c) 2014 Red Hat Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv3
# along with this software; if not, see http://www.gnu.org/licenses/gpl.txt
#

require 'digest'
require 'fileutils'
require 'pathname'
require 'json'
require 'proxy/error'
require 'yaml'
require 'ostruct'
require 'proxy/request'
require 'smart_proxy_openscap/foreman_arf_forwarder'
require 'smart_proxy_openscap/foreman_oval_forwarder'
require 'smart_proxy_openscap/content_parser'
require 'smart_proxy_openscap/openscap_exception'
require 'smart_proxy_openscap/arf_html'
require 'smart_proxy_openscap/arf_parser'
require 'smart_proxy_openscap/spool_forwarder'
require 'smart_proxy_openscap/policy_guide'
require 'smart_proxy_openscap/profiles_parser'
require 'smart_proxy_openscap/oval_report_storage_fs'
require 'smart_proxy_openscap/oval_report_parser'
require 'smart_proxy_openscap/fetch_scap_file'

module Proxy::OpenSCAP
  extend ::Proxy::Log

  def self.plugin_settings
    @@settings ||= OpenStruct.new(read_settings)
  end

  def self.read_settings
    ::Proxy::OpenSCAP::Plugin.default_settings.merge(
      YAML.load_file(File.join(::Proxy::SETTINGS.settings_directory, ::Proxy::OpenSCAP::Plugin.settings_file)))
  end

  def self.common_name(request)
    client_cert = request.env['SSL_CLIENT_CERT']
    raise Proxy::Error::Unauthorized, "Client certificate required!" if client_cert.to_s.empty?

    begin
      client_cert = OpenSSL::X509::Certificate.new(client_cert)
    rescue OpenSSL::OpenSSLError => e
      raise Proxy::Error::Unauthorized, e.message
    end
    cn = client_cert.subject.to_a.detect { |name, value| name == 'CN' }
    cn = cn[1] unless cn.nil?
    raise Proxy::Error::Unauthorized, "Common Name not found in the certificate" unless cn
    cn
  end

  def self.send_spool_to_foreman(loaded_settings)
    arf_dir = File.join(loaded_settings.spooldir, "/arf")
    return unless File.exist? arf_dir
    SpoolForwarder.new(loaded_settings).post_arf_from_spool(arf_dir)
  end

  def self.fullpath(path = Proxy::OpenSCAP::Plugin.settings.contentdir)
    pathname = Pathname.new(path)
    pathname.relative? ? pathname.expand_path(Sinatra::Base.root).to_s : path
  end
end
