module SqlInjectionDetection
  class Checker
    # Common patterns for SQL Injection
    PATTERNS = [
      /(\%27)|(\')|(\-\-)|(\%23)|(#)/ix, # SQL meta-characters
      /\b(OR|AND)\b/i,                   # Boolean operators
      /\b(UNION)\b/i,                    # UNION keyword
      /\b(SELECT)\b/i                    # SELECT keyword
    ]

    def self.check(input)
      return false if input.nil? || input.strip.empty?

      PATTERNS.any? { |pattern| pattern.match?(input) }
    end
  end
end
