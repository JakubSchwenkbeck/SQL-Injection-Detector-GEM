# frozen_string_literal: true
require 'sql_injection_detection'
RSpec.describe SqlInjectionDetection do
  it "has a version number" do
    expect(SqlInjectionDetection::VERSION).not_to be nil
  end

  it "does something useful" do
    expect(false).to eq(true)
  end
end
