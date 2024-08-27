require 'spec_helper'
require_relative '../lib/sql_injection_detection'

RSpec.describe SqlInjectionDetection::Checker do
  # Basic SQL injection tests
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

  # Encoded and special character-based injections
  it "detects encoded SQL characters" do
    expect(SqlInjectionDetection::Checker.check("%23 DROP TABLE users")).to be true
  end

  it "detects encoded SQL injection using hexadecimal" do
    expect(SqlInjectionDetection::Checker.check("0x53514c20494e4a454354494f4e")).to be true
  end

  # SQL keyword-based injections
  it "detects SQL injection using INSERT keyword" do
    expect(SqlInjectionDetection::Checker.check("INSERT INTO users (username) VALUES ('admin')")).to be true
  end

  it "detects SQL injection using DELETE keyword" do
    expect(SqlInjectionDetection::Checker.check("DELETE FROM users WHERE id = 1")).to be true
  end

  it "detects SQL injection using UPDATE keyword" do
    expect(SqlInjectionDetection::Checker.check("UPDATE users SET password = 'password' WHERE id = 1")).to be true
  end

  it "detects SQL injection using EXEC keyword" do
    expect(SqlInjectionDetection::Checker.check("EXEC sp_executesql N'SELECT * FROM users'")).to be true
  end

  it "detects SQL injection using XP_CMDSHELL" do
    expect(SqlInjectionDetection::Checker.check("XP_CMDSHELL 'dir'")).to be true
  end

  it "detects SQL injection using sp_ stored procedure" do
    expect(SqlInjectionDetection::Checker.check("sp_password NULL, 'password', 'admin'")).to be true
  end

  it "detects SQL injection using LIKE wildcard" do
    expect(SqlInjectionDetection::Checker.check("SELECT * FROM users WHERE username LIKE '%admin%'")).to be true
  end

  # Time-based and blind SQL injection
  it "detects time-based SQL injection using SLEEP" do
    expect(SqlInjectionDetection::Checker.check("SLEEP(10)")).to be true
  end

  it "detects time-based SQL injection using PG_SLEEP" do
    expect(SqlInjectionDetection::Checker.check("PG_SLEEP(10)")).to be true
  end

  it "detects blind SQL injection using WAITFOR" do
    expect(SqlInjectionDetection::Checker.check("WAITFOR DELAY '00:00:10'")).to be true
  end

  it "detects blind SQL injection using BENCHMARK" do
    expect(SqlInjectionDetection::Checker.check("SELECT BENCHMARK(1000000, MD5('test'))")).to be true
  end

  # Special injection techniques
  it "detects SQL injection using null-byte" do
    expect(SqlInjectionDetection::Checker.check("SELECT * FROM users\x00")).to be true
  end

  it "detects SQL injection using concatenation" do
    expect(SqlInjectionDetection::Checker.check("SELECT * FROM users WHERE username = 'admin' || '1'='1'")).to be true
  end

  it "detects MySQL-specific SQL injection using LOAD_FILE" do
    expect(SqlInjectionDetection::Checker.check("SELECT LOAD_FILE('/etc/passwd')")).to be true
  end

  # Tests for safe inputs
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
