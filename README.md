# SQL Injection Detection Gem

[![Gem Version](https://badge.fury.io/rb/sql_injection_detection.svg)](https://badge.fury.io/rb/sql_injection_detection)


## Overview

The `sql_injection_detection` gem is a lightweight Ruby library designed to detect potential SQL injection attempts in input strings. It can be used to enhance the security of Ruby on Rails applications or any Ruby-based projects by identifying and flagging suspicious input patterns that are commonly used in SQL injection attacks.

## Features

- Detects common SQL injection patterns, such as:
  - Single quotes and encoded characters
  - SQL comments (`--`)
  - SQL keywords like `UNION`, `SELECT`, `DROP`, `INSERT`, and `DELETE`
  - Boolean-based injections using `OR` and `AND`
- Simple API: one method call to check for SQL injection
- Lightweight and easy to integrate into existing projects

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'sql_injection_detection'
```
And then execute:

```bash
bundle install
```
Or install it yourself as:

```bash
gem install sql_injection_detection
```
## Usage
You can use the gem by requiring it in your project and calling the SqlInjectionDetection::Checker.check method with the input string you want to validate:

```ruby
require 'sql_injection_detection'

input = "' OR 1=1 --"
if SqlInjectionDetection::Checker.check(input)
  puts "Potential SQL injection detected!"
else
  puts "Input is safe."
end
```
### Example Usage
```ruby
input = "SELECT * FROM users WHERE username = 'admin' --"
if SqlInjectionDetection::Checker.check(input)
  puts "Warning: SQL Injection attempt detected!"
else
  puts "Input is safe."
end
```
## Development
After checking out the repo, run bin/setup to install dependencies. Then, run rake spec to run the tests. You can also run bin/console for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run bundle exec rake install. To release a new version, update the version number in version.rb, and then run bundle exec rake release, which will create a git tag for the version, push git commits and the tag, and push the .gem file to rubygems.org.

## Contributing
Bug reports and pull requests are welcome on GitHub at https://github.com/JakubSchwenkbeck/SQL-Injection-Detector-GEM. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the code of conduct.

## License
The gem is available as open source under the terms of the MIT License.

## Acknowledgements
This project was created to provide a simple yet effective tool for detecting SQL injection vulnerabilities in Ruby applications. Contributions and feedback are greatly appreciated!
