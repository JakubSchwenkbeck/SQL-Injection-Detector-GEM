# frozen_string_literal: true

require_relative "lib/sql_injection_detection/version"

Gem::Specification.new do |spec|
  spec.name = "sql_injection_detection"
  spec.version = SqlInjectionDetection::VERSION
  spec.authors = ["Jakub Schwenkbe.de"]
  spec.email = ["Jakub@Schwenkbeck.com"]

  spec.summary = "A simple gem to detect potential SQL injection attacks in input strings."
  spec.description = "The sql_injection_detection gem provides a basic yet effective way to detect common SQL injection attempts by matching input strings against known malicious patterns. It can be used in Ruby on Rails applications or any Ruby-based projects to help prevent SQL injection vulnerabilities."
  spec.homepage = "https://github.com/JakubSchwenkbeck/SQL-Injection-Detector-GEM"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"
  spec.add_development_dependency "rspec"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/JakubSchwenkbeck/SQL-Injection-Detector-GEM"
  # Since you don't have a changelog, this field is omitted
  # spec.metadata["changelog_uri"] = "https://github.com/JakubSchwenkbeck/SQL-Injection-Detector-GEM/blob/main/CHANGELOG.md"

  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == File.basename(__FILE__)) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

end
