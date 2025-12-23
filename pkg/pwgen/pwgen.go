package pwgen

import (
	"crypto/rand"
	"math"
	"math/big"
	"strings"
)

const (
	// DefaultLength is the default password length
	DefaultLength = 24

	// Character sets
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits    = "0123456789"
	symbols   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// Options configures password generation
type Options struct {
	Length     int
	Uppercase  bool
	Lowercase  bool
	Digits     bool
	Symbols    bool
	Exclude    string // Characters to exclude
	MinUpper   int    // Minimum uppercase characters
	MinLower   int    // Minimum lowercase characters
	MinDigits  int    // Minimum digit characters
	MinSymbols int    // Minimum symbol characters
}

// DefaultOptions returns sensible defaults
func DefaultOptions() Options {
	return Options{
		Length:    DefaultLength,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   true,
	}
}

// AlphanumericOptions returns options for alphanumeric passwords only
func AlphanumericOptions() Options {
	return Options{
		Length:    DefaultLength,
		Uppercase: true,
		Lowercase: true,
		Digits:    true,
		Symbols:   false,
	}
}

// Generate generates a random password with the given options
func Generate(opts Options) (string, error) {
	if opts.Length <= 0 {
		opts.Length = DefaultLength
	}

	// Build character set
	var charset strings.Builder
	if opts.Lowercase {
		charset.WriteString(lowercase)
	}
	if opts.Uppercase {
		charset.WriteString(uppercase)
	}
	if opts.Digits {
		charset.WriteString(digits)
	}
	if opts.Symbols {
		charset.WriteString(symbols)
	}

	// Remove excluded characters
	charsetStr := charset.String()
	if opts.Exclude != "" {
		for _, c := range opts.Exclude {
			charsetStr = strings.ReplaceAll(charsetStr, string(c), "")
		}
	}

	if len(charsetStr) == 0 {
		charsetStr = lowercase + uppercase + digits // Fallback
	}

	// Generate password
	password := make([]byte, opts.Length)
	for i := range password {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charsetStr))))
		if err != nil {
			return "", err
		}
		password[i] = charsetStr[n.Int64()]
	}

	// Ensure minimum requirements
	result := string(password)
	if opts.MinUpper > 0 || opts.MinLower > 0 || opts.MinDigits > 0 || opts.MinSymbols > 0 {
		result = ensureMinimums(result, opts)
	}

	return result, nil
}

// GenerateSimple generates a password with default options
func GenerateSimple(length int) (string, error) {
	opts := DefaultOptions()
	opts.Length = length
	return Generate(opts)
}

// GenerateAlphanumeric generates an alphanumeric password
func GenerateAlphanumeric(length int) (string, error) {
	opts := AlphanumericOptions()
	opts.Length = length
	return Generate(opts)
}

// GeneratePin generates a numeric PIN
func GeneratePin(length int) (string, error) {
	opts := Options{
		Length: length,
		Digits: true,
	}
	return Generate(opts)
}

// ensureMinimums ensures minimum character type requirements
func ensureMinimums(password string, opts Options) string {
	chars := []byte(password)

	// Count current character types
	upperCount := countChars(password, uppercase)
	lowerCount := countChars(password, lowercase)
	digitCount := countChars(password, digits)
	symbolCount := countChars(password, symbols)

	// Replace characters as needed
	pos := 0
	if opts.MinUpper > upperCount {
		for i := 0; i < opts.MinUpper-upperCount && pos < len(chars); i++ {
			c, _ := randomChar(uppercase)
			chars[pos] = c
			pos++
		}
	}
	if opts.MinLower > lowerCount {
		for i := 0; i < opts.MinLower-lowerCount && pos < len(chars); i++ {
			c, _ := randomChar(lowercase)
			chars[pos] = c
			pos++
		}
	}
	if opts.MinDigits > digitCount {
		for i := 0; i < opts.MinDigits-digitCount && pos < len(chars); i++ {
			c, _ := randomChar(digits)
			chars[pos] = c
			pos++
		}
	}
	if opts.MinSymbols > symbolCount {
		for i := 0; i < opts.MinSymbols-symbolCount && pos < len(chars); i++ {
			c, _ := randomChar(symbols)
			chars[pos] = c
			pos++
		}
	}

	// Shuffle
	shuffle(chars)

	return string(chars)
}

// countChars counts characters from a set in the string
func countChars(s, charset string) int {
	count := 0
	for _, c := range s {
		if strings.ContainsRune(charset, c) {
			count++
		}
	}
	return count
}

// randomChar returns a random character from the charset
func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

// shuffle shuffles a byte slice in place
func shuffle(chars []byte) {
	for i := len(chars) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}
		j := n.Int64()
		chars[i], chars[j] = chars[j], chars[i]
	}
}

// Entropy calculates the entropy of a password in bits
func Entropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	// Count character types
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	poolSize := 0
	if hasLower {
		poolSize += 26
	}
	if hasUpper {
		poolSize += 26
	}
	if hasDigit {
		poolSize += 10
	}
	if hasSymbol {
		poolSize += 32
	}

	if poolSize == 0 {
		return 0
	}

	// Entropy = log2(poolSize^length) = length * log2(poolSize)
	return float64(len(password)) * math.Log2(float64(poolSize))
}
