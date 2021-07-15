require 'test_helper'
require 'smart_proxy_openscap/arf_html'

class ArfHtmlTest < Test::Unit::TestCase
  def test_html_report
    obj = Proxy::OpenSCAP::ArfHtml.new
    obj.stubs(:file_path_in_storage).returns("#{Dir.getwd}/test/data/arf_report")
    html = obj.generate('consumer-uuid', 5, 523455, 'digest')

    assert html.start_with?('<!DOCTYPE'), "File should be html"
  end
end
