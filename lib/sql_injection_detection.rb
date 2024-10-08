module SqlInjectionDetection
  class Checker
    # Combined regex patterns to detect a wide range of SQL injection techniques
    PATTERNS = [
      # Detects single quotes or encoded single quotes, often used to escape SQL strings
      /(%27)|(')/i,

      # Detects SQL comments (inline comments using --) and block comments (/* */)
      /(--|\/\*)/i,

      # Detects encoded characters for inline comments (e.g., %23 for #)
      /(%23|%2F%2A)/i,

      # Detects boolean-based SQL injections using OR/AND with numbers, strings, NULL, or boolean values
      /\b(OR|AND)\b\s+(\d+|'[^']*'|NULL|TRUE|FALSE)/i,

      # Detects UNION and SELECT keywords, often used to combine results from multiple SELECT statements
      /\b(UNION|SELECT)\b/i,

      # Detects the usage of semicolons, used to terminate SQL statements and inject new ones
      /(;)/,

      # Detects common SQL keywords for data manipulation and structure changes
      # DROP: Used to drop tables or databases
      # INSERT: Used to inject data into tables
      # DELETE: Used to remove data
      # UPDATE: Used to modify data
      /\b(DROP|INSERT|DELETE|UPDATE)\b/i,

      # Detects potential SQL keywords with a high risk for code injection
      # EXEC: Execute a stored procedure or dynamic SQL
      # EXECUTE: Same as EXEC
      /\b(EXEC|EXECUTE)\b/i,

      # Detects SQL wildcards and patterns in LIKE-based attacks
      # LIKE: Used with wildcards to match patterns in SQL
      /\bLIKE\b\s+('|")[^'"]+('|")/i,

      # Detects null-byte injections, used in various bypass techniques
      /\x00/i,

      # Detects SQL injections that use concatenation to bypass filters
      # ||: SQL concatenation operator
      /\|\|/,

      # Detects encoded and decoded SQL keywords using hexadecimal or binary representations
      # e.g., 0x53514c20494e4a454354494f4e represents "SQL INJECTION"
      /0x[0-9A-Fa-f]+/,

      # Detects encoded comments using the %2D (dash) and %2F (slash) patterns
      /(%2D){2}|(%2F%2A)/i,

      # Detects SQL keywords that interact with metadata, which could be exploited
      # INFORMATION_SCHEMA: A schema containing information about database objects
      # SYSOBJECTS: A system table containing information about objects within the database
      /\b(INFORMATION_SCHEMA|SYSOBJECTS)\b/i,

      # Detects blind SQL injection techniques, which rely on timing to infer database information
      # WAITFOR: SQL Server keyword used to delay execution
      # BENCHMARK: MySQL function to run a specified number of loops
      /\b(WAITFOR|BENCHMARK)\b\s+/i,

      # Detects time-based SQL injection techniques, commonly used to exploit delays
      # SLEEP: MySQL function to delay execution
      # PG_SLEEP: PostgreSQL function to delay execution
      /\b(SLEEP|PG_SLEEP)\b\s*\(\s*\d+\s*\)/i,

      # Detects SQL Server specific injections for stacked queries
      # XP_CMDSHELL: Executes command shell commands
      /\bXP_CMDSHELL\b/i,

      # Detects MySQL-specific injections for loading external files
      # LOAD_FILE: Loads a file into a string in MySQL
      /\bLOAD_FILE\b\s*\(/i,

      # Detects SQL Server injection keywords for accessing system procedures
      # sp_: Stored procedure prefix in SQL Server
      /\bsp_[a-zA-Z0-9_]+\b/i,

      # Detects SQL injection attempts using the ALTER keyword to change database structure
      /\bALTER\b/i,

      # Detects usage of subqueries which could be exploited in certain contexts
      /\b(SELECT\s+\*\s+FROM)\b/i,

      # Detects complex UNION SELECT attempts that combine multiple SELECTs
      /UNION\s+(ALL\s+)?SELECT\s+/i,

      # Detects SQL keywords that could be used to read from or write to files in the database
      # OUTFILE: Writes query results to a file in MySQL
      # INTO OUTFILE: Writes to a file in SQL
      /\b(INTO\s+OUTFILE|OUTFILE)\b/i,

      # Detects SQL functions that could be used to bypass typical sanitization checks
      # ASCII: Returns ASCII value of the first character
      # CHAR: Returns the character for each integer passed
      /\b(ASCII|CHAR)\b\s*\(\s*[^\)]*\s*\)/i,

      # Detects SQL injection techniques that attempt to execute multiple queries
      # Semicolon (;) to chain queries together
      /\;/,

      # Detects SQL injection techniques that make use of the CONCAT function to merge strings
      /\bCONCAT\b\s*\(/i,

      # Detects SQL keywords related to database schema manipulation that might be dangerous
      # CREATE: Used to create new tables, databases, or users
      # ALTER: Used to change database structures
      /\b(CREATE|ALTER)\b/i,

      # Detects SQL injection techniques that rely on the RAND function to bypass unique constraints
      /\bRAND\b\s*\(\s*\)/i,

      # Detects SQL injection techniques that use mathematical functions to manipulate results
      # SQRT: Returns the square root of a number
      /\bSQRT\b\s*\(\s*\d+\s*\)/i,

      # Detects SQL injection techniques that use encryption functions to manipulate queries
      # AES_ENCRYPT: Encrypts data using AES
      /\bAES_ENCRYPT\b\s*\(\s*[^\)]*\s*\)/i
    ]

    # Method to check if the input string contains SQL injection patterns
    def self.check(input)
      return false if input.nil? || input.strip.empty?

      PATTERNS.any? { |pattern| pattern.match?(input) }
    end
  end
end
