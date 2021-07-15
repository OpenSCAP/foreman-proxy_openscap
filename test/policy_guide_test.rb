require 'test_helper'
require 'smart_proxy_openscap/policy_guide'

class PolicyGuideTest < Test::Unit::TestCase
  def test_policy_guide
    profile = "xccdf_org.ssgproject.content_profile_rht-ccp"
    policy_data = File.read "#{Dir.getwd}/test/data/ssg-rhel7-ds.xml"
    guide = Proxy::OpenSCAP::PolicyGuide.new.generate_guide(policy_data, profile)
    assert guide.start_with?('<!DOCTYPE'), "File should be html"
  end
end
