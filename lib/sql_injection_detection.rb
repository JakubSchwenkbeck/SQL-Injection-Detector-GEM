module SqlInjectionDetection
  class Checker
    # Combined regex patterns to detect common SQL injection techniques
    PATTERNS = [
      # Detects single quotes or encoded single quotes, which are often used to escape SQL strings
      /(%27)|(')/i, 

      # Detects SQL comments (inline comments using --), which can be used to bypass certain SQL queries
      /(--)/i,

      # Detects encoded characters for inline comments (e.g., %23 for #)
      /(%23)/i,

      # Detects boolean-based SQL injections using OR/AND to manipulate conditional queries
      /\b(OR|AND)\b\s+(\d+|'[^']*'|NULL|TRUE|FALSE)/i,

      # Detects UNION and SELECT keywords, often used to fetch data by combining results from multiple SELECT statements
      /\b(UNION|SELECT)\b/i,

      # Detects the usage of semicolons, which can be used to terminate SQL statements and inject new ones
      /(;)/,

      # Detects common SQL keywords that could be used in injection attacks
      # DROP: Used to drop tables or databases
      # INSERT: Used to inject data into tables
      # DELETE: Used to remove data
      # UPDATE: Used to modify data
      /\b(DROP|INSERT|DELETE|UPDATE)\b/i,

      # Detects potential SQL keywords with a potential for code injection (e.g., EXEC for executing stored procedures)
      /\b(EXEC|EXECUTE)\b/i,

      # Detects SQL wildcards and patterns often used in LIKE-based attacks
      /\bLIKE\b\s+('|")[^'"]+('|")/i,

      # Detects the use of null-byte injections (used in various bypass techniques)
      /\x00/i
    ]

    # Method to check if the input string contains SQL injection patterns
    def self.check(input)
      return false if input.nil? || input.strip.empty?

      PATTERNS.any? { |pattern| pattern.match?(input) }
    end
  end
end
