# lib/sql_injection_detection.rb
module SqlInjectionDetection
  class Checker
    # Regex patterns to detect common SQL injection techniques
    PATTERNS = [
      # Detects the usage of single quotes, often used to escape SQL strings
      /(%27)|(')/i,

      # Detects SQL comments, which can be used to bypass certain SQL queries
      /(--)/i,

      # Detects the usage of semicolons, which can be used to terminate SQL statements and inject new ones
      /(;)/i,

      # Detects the usage of SQL keywords like UNION, used to combine results from multiple SELECT statements
      /\bUNION\b/i,

      # Detects the SQL keyword SELECT, often used in SQL injection to fetch data
      /\bSELECT\b/i,

      # Detects boolean-based SQL injections (OR/AND) to manipulate conditional queries
      /\b(OR|AND)\b/i,

      # Detects the keyword DROP, which could be used to drop tables or databases
      /\bDROP\b/i,

      # Detects the usage of encoded SQL characters
      /(%23)/i,  # Encoded '#', often used for inline comments

      # Detects the keyword INSERT, which could be used to inject data into tables
      /\bINSERT\b/i,

      # Detects the keyword DELETE, which could be used to remove data
      /\bDELETE\b/i
    ]

    # Method to check if the input string contains SQL injection patterns
    def self.check(input)
      return false if input.nil? || input.strip.empty?

      PATTERNS.any? { |pattern| pattern.match?(input) }
    end
  end
end
