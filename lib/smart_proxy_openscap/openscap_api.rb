#
# Copyright (c) 2014--2015 Red Hat Inc.
#
# This software is licensed to you under the GNU General Public License,
# version 3 (GPLv3). There is NO WARRANTY for this software, express or
# implied, including the implied warranties of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv3
# along with this software; if not, see http://www.gnu.org/licenses/gpl.txt
#

require 'smart_proxy_openscap/openscap_lib'

module Proxy::OpenSCAP
  class Api < ::Sinatra::Base
    include ::Proxy::Log
    helpers ::Proxy::Helpers
    authorize_with_trusted_hosts

    put "/arf/:policy" do
      # first let's verify client's certificate
      begin
        cn = Proxy::OpenSCAP::common_name request
      rescue Proxy::Error::Unauthorized => e
        log_halt 403, "Client authentication failed: #{e.message}"
      end

      # validate the url (i.e. avoid malformed :policy)
      begin
        target_dir = Proxy::OpenSCAP::spool_arf_dir(cn, params[:policy])
      rescue Proxy::Error::BadRequest => e
        log_halt 400, "Requested URI is malformed: #{e.message}"
      rescue StandardError => e
        log_halt 500, "Could not fulfill request: #{e.message}"
      end

      begin
        target_path = Proxy::OpenSCAP::store_arf(target_dir, request.body.string)
      rescue StandardError => e
        log_halt 500, "Could not store file: #{e.message}"
      end

      logger.debug "File #{target_path} stored successfully."

      {"created" => true}.to_json
    end

    get "/policies/:policy_id/content" do
      content_type 'application/xml'
      begin
        Proxy::OpenSCAP::get_policy_content(params[:policy_id])
      rescue OpenSCAPException => e
        log_halt e.http_code, "Error fetching xml file: #{e.message}"
      rescue StandardError => e
        log_halt 500, "Error occurred: #{e.message}"
      end
    end
  end
end
