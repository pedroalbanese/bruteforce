package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/crypto/pbkdf2"
)

// --- Configuration ---
type Config struct {
	FilePath         string
	MinLen           int
	MaxLen           int
	Prefix           string
	Suffix           string
	Charset          string
	Threads          int
	VerboseInterval  int
	MagicBytes       string
	PreviewBytes     int
	UseSalt          bool
	UsePBKDF2        bool
	PBKDF2Iterations int
	AutoDetect       bool
	StrictMode       bool
}

// --- Key Derivation Functions ---

func evpBytesToKeyMD5(password, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	key = make([]byte, keyLen)
	iv = make([]byte, ivLen)

	var hasher = md5.New()
	var derived = []byte{}
	var lastHash []byte

	for len(derived) < keyLen+ivLen {
		hasher.Reset()
		if len(lastHash) > 0 {
			hasher.Write(lastHash)
		}
		hasher.Write(password)
		if len(salt) > 0 {
			hasher.Write(salt)
		}
		lastHash = hasher.Sum(nil)
		derived = append(derived, lastHash...)
	}

	copy(key, derived[:keyLen])
	copy(iv, derived[keyLen:keyLen+ivLen])
	return
}

func deriveKeyPBKDF2(password, salt []byte, keyLen, ivLen, iterations int) (key, iv []byte) {
	derived := pbkdf2.Key(password, salt, iterations, keyLen+ivLen, sha256.New)
	key = derived[:keyLen]
	iv = derived[keyLen:keyLen+ivLen]
	return
}

// --- Decryption Attempt ---
func decryptAttempt(ciphertext, salt, password []byte, config *Config) ([]byte, error) {
	var key, iv []byte
	keyLen := 32
	ivLen := 16

	if config.UsePBKDF2 {
		key, iv = deriveKeyPBKDF2(password, salt, keyLen, ivLen, config.PBKDF2Iterations)
	} else {
		key, iv = evpBytesToKeyMD5(password, salt, keyLen, ivLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}

	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen == 0 || paddingLen > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := len(plaintext) - paddingLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	plaintext = plaintext[:len(plaintext)-paddingLen]

	if config.MagicBytes != "" {
		if !bytes.HasPrefix(plaintext, []byte(config.MagicBytes)) {
			return nil, fmt.Errorf("magic bytes not found")
		}
		return plaintext, nil
	}

	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}

	printableCount := 0
	for _, b := range plaintext {
		if unicode.IsPrint(rune(b)) || b == '\n' || b == '\r' || b == '\t' || b == ' ' {
			printableCount++
		}
	}

	threshold := 0.90
	if config.StrictMode {
		threshold = 0.95
	}

	ratio := float64(printableCount) / float64(len(plaintext))
	if ratio < threshold {
		return nil, fmt.Errorf("low printable ASCII content: %.2f%%", ratio*100)
	}

	if len(plaintext) < 100 && config.StrictMode {
		if ratio < 0.98 {
			return nil, fmt.Errorf("small file with low printable ratio: %.2f%%", ratio*100)
		}
	}

	return plaintext, nil
}

// --- File Parsing ---
func readEncryptedFile(filePath string, useSalt bool) (salt []byte, ciphertext []byte, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	if !useSalt {
		return nil, data, nil
	}

	if len(data) >= 16 && string(data[:8]) == "Salted__" {
		salt = data[8:16]
		ciphertext = data[16:]
		return salt, ciphertext, nil
	}

	return nil, data, nil
}

// --- Password Generator ---
type PasswordGenerator struct {
	charset  []rune
	prefix   string
	suffix   string
	minLen   int
	maxLen   int
	current  []int
	firstRun bool
	count    uint64
}

func NewPasswordGenerator(config *Config) *PasswordGenerator {
	charset := []rune(config.Charset)
	if len(charset) == 0 {
		charset = []rune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	}

	middleLen := config.MinLen - len(config.Prefix) - len(config.Suffix)
	if middleLen < 0 {
		middleLen = 0
	}

	return &PasswordGenerator{
		charset:  charset,
		prefix:   config.Prefix,
		suffix:   config.Suffix,
		minLen:   config.MinLen,
		maxLen:   config.MaxLen,
		current:  make([]int, middleLen),
		firstRun: true,
		count:    0,
	}
}

func (pg *PasswordGenerator) Next() (string, bool) {
	if pg.firstRun {
		pg.firstRun = false
		for i := range pg.current {
			pg.current[i] = 0
		}
		pg.count++
		return pg.buildPassword(), true
	}

	for i := len(pg.current) - 1; i >= 0; i-- {
		pg.current[i]++
		if pg.current[i] < len(pg.charset) {
			pg.count++
			return pg.buildPassword(), true
		}
		pg.current[i] = 0

		if i == 0 {
			currentTotalLen := len(pg.prefix) + len(pg.suffix) + len(pg.current)
			if currentTotalLen < pg.maxLen {
				pg.current = append(pg.current, 0)
				pg.count++
				return pg.buildPassword(), true
			}
			return "", false
		}
	}
	return "", false
}

func (pg *PasswordGenerator) buildPassword() string {
	middle := make([]rune, len(pg.current))
	for i, idx := range pg.current {
		middle[i] = pg.charset[idx]
	}
	return pg.prefix + string(middle) + pg.suffix
}

func (pg *PasswordGenerator) GetTotalCount() uint64 {
	var total uint64 = 0
	base := uint64(len(pg.charset))
	prefixLen := len(pg.prefix)
	suffixLen := len(pg.suffix)

	for length := pg.minLen; length <= pg.maxLen; length++ {
		middleLen := length - prefixLen - suffixLen
		if middleLen < 0 {
			continue
		}
		var combinations uint64 = 1
		for i := 0; i < middleLen; i++ {
			combinations *= base
		}
		total += combinations
	}
	return total
}

// --- Worker Function ---
func worker(id int, config *Config, salt, ciphertext []byte, passwordChan <-chan string, results chan<- string, wg *sync.WaitGroup, stopFlag *atomic.Bool, attempts *uint64, method string) {
	defer wg.Done()

	for password := range passwordChan {
		if stopFlag.Load() {
			return
		}

		atomic.AddUint64(attempts, 1)

		if atomic.LoadUint64(attempts)%10000 == 0 {
			fmt.Printf("\r[%s] Testing: %-20s | Attempts: %d", method, password, atomic.LoadUint64(attempts))
		}

		_, err := decryptAttempt(ciphertext, salt, []byte(password), config)
		if err == nil {
			results <- password
			stopFlag.Store(true)
			return
		}
	}
}

// --- Progress Reporter ---
func progressReporter(config *Config, attempts *uint64, total uint64, stopFlag *atomic.Bool) {
	if config.VerboseInterval <= 0 {
		return
	}

	ticker := time.NewTicker(time.Duration(config.VerboseInterval) * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	for range ticker.C {
		if stopFlag.Load() {
			return
		}

		current := atomic.LoadUint64(attempts)
		elapsed := time.Since(startTime).Seconds()
		rate := float64(current) / elapsed

		var percent float64
		if total > 0 {
			percent = float64(current) / float64(total) * 100
		}

		fmt.Printf("\r[Progress] Tested: %d passwords (%.2f%%) | Rate: %.0f pwd/s | Elapsed: %.0fs",
			current, percent, rate, elapsed)
	}
}

// --- Try both methods ---
func tryBothMethods(config *Config, salt, ciphertext []byte) string {
	fmt.Println("\nAuto-detecting key derivation method...")

	configPBKDF2 := *config
	configPBKDF2.UsePBKDF2 = true
	configPBKDF2.PBKDF2Iterations = 10000

	fmt.Println("  - Testing with PBKDF2 (iterations: 10000)...")
	result := bruteForceWithMethod(&configPBKDF2, salt, ciphertext, "PBKDF2")
	if result != "" {
		return result
	}

	configMD5 := *config
	configMD5.UsePBKDF2 = false

	fmt.Println("  - PBKDF2 failed, trying MD5 (legacy)...")
	result = bruteForceWithMethod(&configMD5, salt, ciphertext, "MD5")
	if result != "" {
		return result
	}

	return ""
}

func bruteForceWithMethod(config *Config, salt, ciphertext []byte, method string) string {
	gen := NewPasswordGenerator(config)
	totalCombinations := gen.GetTotalCount()

	fmt.Printf("\n%s Mode:\n", method)
	fmt.Printf("  - Total combinations: %d\n", totalCombinations)
	fmt.Printf("  - Strict mode: %v\n", config.StrictMode)

	passwordChan := make(chan string, 10000)
	go func() {
		defer close(passwordChan)
		for {
			pwd, ok := gen.Next()
			if !ok {
				break
			}
			passwordChan <- pwd
		}
	}()

	var wg sync.WaitGroup
	results := make(chan string, 10)
	stopFlag := &atomic.Bool{}
	var attempts uint64 = 0

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(i, config, salt, ciphertext, passwordChan, results, &wg, stopFlag, &attempts, method)
	}

	go progressReporter(config, &attempts, totalCombinations, stopFlag)

	go func() {
		wg.Wait()
		close(results)
		fmt.Println()
	}()

	select {
	case pwd, ok := <-results:
		if ok {
			return pwd
		}
	case <-time.After(24 * time.Hour):
		stopFlag.Store(true)
		return ""
	}

	return ""
}

// --- Main ---
func main() {
	var config Config

	flag.StringVar(&config.FilePath, "file", "", "Path to the encrypted file (required)")
	flag.IntVar(&config.MinLen, "min", 1, "Minimum password length")
	flag.IntVar(&config.MaxLen, "max", 8, "Maximum password length")
	flag.StringVar(&config.Prefix, "prefix", "", "Password prefix (known beginning)")
	flag.StringVar(&config.Suffix, "suffix", "", "Password suffix (known ending)")
	flag.StringVar(&config.Charset, "charset", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "Character set for brute-force")
	flag.IntVar(&config.Threads, "threads", runtime.NumCPU(), "Number of worker threads")
	flag.IntVar(&config.VerboseInterval, "verbose", 3, "Print progress every N seconds (0 = off)")
	flag.StringVar(&config.MagicBytes, "magic", "", "Magic bytes to look for (e.g., '\\x1f\\x8b' for gzip)")
	flag.IntVar(&config.PreviewBytes, "preview", 1024, "Number of bytes to preview for validation (DEPRECATED - now validates entire file)")
	flag.BoolVar(&config.UseSalt, "salt", true, "Use salt (OpenSSL salted format)")
	flag.BoolVar(&config.UsePBKDF2, "pbkdf2", false, "Use PBKDF2 key derivation (modern OpenSSL)")
	flag.IntVar(&config.PBKDF2Iterations, "iter", 10000, "PBKDF2 iteration count")
	flag.BoolVar(&config.AutoDetect, "auto", true, "Auto-detect key derivation method (try both)")
	flag.BoolVar(&config.StrictMode, "strict", true, "Use strict validation (95%% printable, validate small files)")
	flag.Parse()

	if config.FilePath == "" {
		fmt.Println("ERROR: -file is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("Reading encrypted file: %s\n", config.FilePath)
	salt, ciphertext, err := readEncryptedFile(config.FilePath, config.UseSalt)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}
	if config.UseSalt && salt == nil {
		fmt.Println("Warning: File does not have OpenSSL salted header, continuing without salt.")
	}

	fmt.Printf("Password space:\n")
	fmt.Printf("  - Length: %d to %d characters\n", config.MinLen, config.MaxLen)
	fmt.Printf("  - Prefix: '%s'\n", config.Prefix)
	fmt.Printf("  - Suffix: '%s'\n", config.Suffix)
	fmt.Printf("  - Charset: %d characters\n", len(config.Charset))
	fmt.Printf("  - Using %d threads\n", config.Threads)
	fmt.Printf("  - Strict validation: %v\n", config.StrictMode)
	fmt.Println()

	var foundPassword string

	if config.AutoDetect {
		foundPassword = tryBothMethods(&config, salt, ciphertext)
	} else {
		method := "MD5 (legacy)"
		if config.UsePBKDF2 {
			method = fmt.Sprintf("PBKDF2 (iterations: %d)", config.PBKDF2Iterations)
		}
		fmt.Printf("Using key derivation: %s\n", method)
		foundPassword = bruteForceWithMethod(&config, salt, ciphertext, method)
	}

	if foundPassword != "" {
		fmt.Printf("\nSUCCESS! Password found: %s\n", foundPassword)
		fmt.Println("\nVerifying with OpenSSL command:")
		fmt.Printf("openssl enc -d -aes-256-cbc -pbkdf2 -in %s -k \"%s\"\n", config.FilePath, foundPassword)
	} else {
		fmt.Printf("\nPassword not found.\n")
	}
}
