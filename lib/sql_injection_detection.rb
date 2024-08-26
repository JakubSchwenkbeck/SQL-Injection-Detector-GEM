module SqlInjectionDetection
  class Checker
    # Common patterns for SQL Injection
    PATTERNS = [
  /(%27)|(')|(--)|(%23)|(#[^\d]*)/i,  # Updated to handle edge cases and unnecessary escapes
  /\b(OR|AND)\b/i,
  /\bUNION\b/i,
  /\bSELECT\b/i
]


    def self.check(input)
      return false if input.nil? || input.strip.empty?

      PATTERNS.any? { |pattern| pattern.match?(input) }
    end
  end
end
