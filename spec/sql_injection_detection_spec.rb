require 'spec_helper'
require_relative '../lib/sql_injection_detection'

RSpec.describe SqlInjectionDetection::Checker do
  it "detects a basic SQL injection attempt" do
    expect(SqlInjectionDetection::Checker.check("' OR 1=1 --")).to be true
  end

  it "detects SQL comment-based injection" do
    expect(SqlInjectionDetection::Checker.check("SELECT * FROM users; --")).to be true
  end

  it "detects SQL injection using UNION keyword" do
    expect(SqlInjectionDetection::Checker.check("UNION SELECT * FROM users")).to be true
  end

  it "detects SQL injection using semicolons" do
    expect(SqlInjectionDetection::Checker.check("SELECT * FROM users; DROP TABLE users;")).to be true
  end

  it "detects SQL injection using DROP keyword" do
    expect(SqlInjectionDetection::Checker.check("DROP TABLE users")).to be true
  end

  it "detects encoded SQL characters" do
    expect(SqlInjectionDetection::Checker.check("%23 DROP TABLE users")).to be true
  end

  it "detects SQL injection using INSERT keyword" do
    expect(SqlInjectionDetection::Checker.check("INSERT INTO users (username) VALUES ('admin')")).to be true
  end

  it "detects SQL injection using DELETE keyword" do
    expect(SqlInjectionDetection::Checker.check("DELETE FROM users WHERE id = 1")).to be true
  end

  it "does not flag safe input" do
    expect(SqlInjectionDetection::Checker.check("safe_input")).to be false
  end

  it "does not flag a simple sentence" do
    expect(SqlInjectionDetection::Checker.check("This is a simple test sentence.")).to be false
  end

  it "does not flag a numeric input" do
    expect(SqlInjectionDetection::Checker.check("12345")).to be false
  end
end
