require 'spec_helper'
require_relative '../lib/sql_injection_detection'  # Adjust the path if needed

RSpec.describe SqlInjectionDetection::Checker do
  it "detects a basic SQL injection attempt" do
    expect(SqlInjectionDetection::Checker.check("' OR 1=1 --")).to be true
  end

  it "does not flag safe input" do
    expect(SqlInjectionDetection::Checker.check("safe_input")).to be false
  end
end
