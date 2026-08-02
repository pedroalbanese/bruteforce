package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
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
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"

	"github.com/pedroalbanese/camellia"
	"github.com/RyuaNerin/go-krypto/aria"
	"github.com/emmansun/gmsm/sm4"
	"github.com/pedroalbanese/rc2"
)

// Author: Pedro F. Albanese

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
	UseSalt          bool
	UsePBKDF2        bool
	PBKDF2Iterations int
	AutoDetect       bool
	StrictMode       bool
	Cipher           string
}

// --- Cipher Registry ---
type CipherInfo struct {
	Name      string
	KeyLen    int
	IVLen     int
	BlockLen  int
	NewCipher func(key []byte) (cipher.Block, error)
	IsStream  bool // Indica se é um cipher de fluxo (stream cipher)
}

// Wrappers para compatibilidade com cipher.Block
func blowfishNewCipher(key []byte) (cipher.Block, error) {
	return blowfish.NewCipher(key)
}

func cast5NewCipher(key []byte) (cipher.Block, error) {
	return cast5.NewCipher(key)
}

func rc2NewCipher(key []byte) (cipher.Block, error) {
	return rc2.NewCipher(key)
}

func sm4NewCipher(key []byte) (cipher.Block, error) {
	return sm4.NewCipher(key)
}

// RC4 não implementa cipher.Block, então usamos uma estrutura wrapper
type rc4Cipher struct {
	rc4 *rc4.Cipher
}

func (r *rc4Cipher) BlockSize() int {
	return 1 // RC4 é um stream cipher, block size é 1
}

func (r *rc4Cipher) Encrypt(dst, src []byte) {
	// RC4 é simétrico, então Encrypt e Decrypt são a mesma coisa
	r.rc4.XORKeyStream(dst, src)
}

func (r *rc4Cipher) Decrypt(dst, src []byte) {
	r.rc4.XORKeyStream(dst, src)
}

func rc4NewCipher(key []byte) (cipher.Block, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &rc4Cipher{rc4: c}, nil
}

var cipherRegistry = map[string]CipherInfo{
	// AES
	"aes-128-cbc": {"aes-128-cbc", 16, 16, 16, aes.NewCipher, false},
	"aes-192-cbc": {"aes-192-cbc", 24, 16, 16, aes.NewCipher, false},
	"aes-256-cbc": {"aes-256-cbc", 32, 16, 16, aes.NewCipher, false},
	"aes-128-ctr": {"aes-128-ctr", 16, 16, 16, aes.NewCipher, false},
	"aes-192-ctr": {"aes-192-ctr", 24, 16, 16, aes.NewCipher, false},
	"aes-256-ctr": {"aes-256-ctr", 32, 16, 16, aes.NewCipher, false},
	"aes-128-ecb": {"aes-128-ecb", 16, 0, 16, aes.NewCipher, false},
	"aes-192-ecb": {"aes-192-ecb", 24, 0, 16, aes.NewCipher, false},
	"aes-256-ecb": {"aes-256-ecb", 32, 0, 16, aes.NewCipher, false},
	"aes-128-ofb": {"aes-128-ofb", 16, 16, 16, aes.NewCipher, false},
	"aes-192-ofb": {"aes-192-ofb", 24, 16, 16, aes.NewCipher, false},
	"aes-256-ofb": {"aes-256-ofb", 32, 16, 16, aes.NewCipher, false},
	"aes-128-cfb": {"aes-128-cfb", 16, 16, 16, aes.NewCipher, false},
	"aes-192-cfb": {"aes-192-cfb", 24, 16, 16, aes.NewCipher, false},
	"aes-256-cfb": {"aes-256-cfb", 32, 16, 16, aes.NewCipher, false},
	"aes-128-cfb1": {"aes-128-cfb1", 16, 16, 16, aes.NewCipher, false},
	"aes-192-cfb1": {"aes-192-cfb1", 24, 16, 16, aes.NewCipher, false},
	"aes-256-cfb1": {"aes-256-cfb1", 32, 16, 16, aes.NewCipher, false},
	"aes-128-cfb8": {"aes-128-cfb8", 16, 16, 16, aes.NewCipher, false},
	"aes-192-cfb8": {"aes-192-cfb8", 24, 16, 16, aes.NewCipher, false},
	"aes-256-cfb8": {"aes-256-cfb8", 32, 16, 16, aes.NewCipher, false},
	"aes128": {"aes-128-cbc", 16, 16, 16, aes.NewCipher, false},
	"aes192": {"aes-192-cbc", 24, 16, 16, aes.NewCipher, false},
	"aes256": {"aes-256-cbc", 32, 16, 16, aes.NewCipher, false},

	// ARIA
	"aria-128-cbc": {"aria-128-cbc", 16, 16, 16, aria.NewCipher, false},
	"aria-192-cbc": {"aria-192-cbc", 24, 16, 16, aria.NewCipher, false},
	"aria-256-cbc": {"aria-256-cbc", 32, 16, 16, aria.NewCipher, false},
	"aria-128-ctr": {"aria-128-ctr", 16, 16, 16, aria.NewCipher, false},
	"aria-192-ctr": {"aria-192-ctr", 24, 16, 16, aria.NewCipher, false},
	"aria-256-ctr": {"aria-256-ctr", 32, 16, 16, aria.NewCipher, false},
	"aria-128-ecb": {"aria-128-ecb", 16, 0, 16, aria.NewCipher, false},
	"aria-192-ecb": {"aria-192-ecb", 24, 0, 16, aria.NewCipher, false},
	"aria-256-ecb": {"aria-256-ecb", 32, 0, 16, aria.NewCipher, false},
	"aria-128-ofb": {"aria-128-ofb", 16, 16, 16, aria.NewCipher, false},
	"aria-192-ofb": {"aria-192-ofb", 24, 16, 16, aria.NewCipher, false},
	"aria-256-ofb": {"aria-256-ofb", 32, 16, 16, aria.NewCipher, false},
	"aria-128-cfb": {"aria-128-cfb", 16, 16, 16, aria.NewCipher, false},
	"aria-192-cfb": {"aria-192-cfb", 24, 16, 16, aria.NewCipher, false},
	"aria-256-cfb": {"aria-256-cfb", 32, 16, 16, aria.NewCipher, false},
	"aria128": {"aria-128-cbc", 16, 16, 16, aria.NewCipher, false},
	"aria192": {"aria-192-cbc", 24, 16, 16, aria.NewCipher, false},
	"aria256": {"aria-256-cbc", 32, 16, 16, aria.NewCipher, false},

	// Camellia
	"camellia-128-cbc": {"camellia-128-cbc", 16, 16, 16, camellia.NewCipher, false},
	"camellia-192-cbc": {"camellia-192-cbc", 24, 16, 16, camellia.NewCipher, false},
	"camellia-256-cbc": {"camellia-256-cbc", 32, 16, 16, camellia.NewCipher, false},
	"camellia-128-ctr": {"camellia-128-ctr", 16, 16, 16, camellia.NewCipher, false},
	"camellia-192-ctr": {"camellia-192-ctr", 24, 16, 16, camellia.NewCipher, false},
	"camellia-256-ctr": {"camellia-256-ctr", 32, 16, 16, camellia.NewCipher, false},
	"camellia-128-ecb": {"camellia-128-ecb", 16, 0, 16, camellia.NewCipher, false},
	"camellia-192-ecb": {"camellia-192-ecb", 24, 0, 16, camellia.NewCipher, false},
	"camellia-256-ecb": {"camellia-256-ecb", 32, 0, 16, camellia.NewCipher, false},
	"camellia-128-ofb": {"camellia-128-ofb", 16, 16, 16, camellia.NewCipher, false},
	"camellia-192-ofb": {"camellia-192-ofb", 24, 16, 16, camellia.NewCipher, false},
	"camellia-256-ofb": {"camellia-256-ofb", 32, 16, 16, camellia.NewCipher, false},
	"camellia-128-cfb": {"camellia-128-cfb", 16, 16, 16, camellia.NewCipher, false},
	"camellia-192-cfb": {"camellia-192-cfb", 24, 16, 16, camellia.NewCipher, false},
	"camellia-256-cfb": {"camellia-256-cfb", 32, 16, 16, camellia.NewCipher, false},
	"camellia128": {"camellia-128-cbc", 16, 16, 16, camellia.NewCipher, false},
	"camellia192": {"camellia-192-cbc", 24, 16, 16, camellia.NewCipher, false},
	"camellia256": {"camellia-256-cbc", 32, 16, 16, camellia.NewCipher, false},

	// SM4
	"sm4":     {"sm4", 16, 16, 16, sm4NewCipher, false},
	"sm4-cbc": {"sm4-cbc", 16, 16, 16, sm4NewCipher, false},
	"sm4-ctr": {"sm4-ctr", 16, 16, 16, sm4NewCipher, false},
	"sm4-ecb": {"sm4-ecb", 16, 0, 16, sm4NewCipher, false},
	"sm4-cfb": {"sm4-cfb", 16, 16, 16, sm4NewCipher, false},
	"sm4-ofb": {"sm4-ofb", 16, 16, 16, sm4NewCipher, false},

	// Blowfish
	"bf":       {"blowfish", 16, 8, 8, blowfishNewCipher, false},
	"bf-cbc":   {"blowfish-cbc", 16, 8, 8, blowfishNewCipher, false},
	"bf-ecb":   {"blowfish-ecb", 16, 0, 8, blowfishNewCipher, false},
	"bf-cfb":   {"blowfish-cfb", 16, 8, 8, blowfishNewCipher, false},
	"bf-ofb":   {"blowfish-ofb", 16, 8, 8, blowfishNewCipher, false},
	"blowfish": {"blowfish", 16, 8, 8, blowfishNewCipher, false},

	// DES
	"des":      {"des", 8, 8, 8, des.NewCipher, false},
	"des-cbc":  {"des-cbc", 8, 8, 8, des.NewCipher, false},
	"des-ecb":  {"des-ecb", 8, 0, 8, des.NewCipher, false},
	"des-cfb":  {"des-cfb", 8, 8, 8, des.NewCipher, false},
	"des-ofb":  {"des-ofb", 8, 8, 8, des.NewCipher, false},
	"des-cfb1": {"des-cfb1", 8, 8, 8, des.NewCipher, false},
	"des-cfb8": {"des-cfb8", 8, 8, 8, des.NewCipher, false},

	// 3DES
	"des-ede":       {"des-ede", 16, 8, 8, des.NewTripleDESCipher, false},
	"des-ede-cbc":   {"des-ede-cbc", 16, 8, 8, des.NewTripleDESCipher, false},
	"des-ede-cfb":   {"des-ede-cfb", 16, 8, 8, des.NewTripleDESCipher, false},
	"des-ede-ofb":   {"des-ede-ofb", 16, 8, 8, des.NewTripleDESCipher, false},
	"des-ede3":      {"des-ede3", 24, 8, 8, des.NewTripleDESCipher, false},
	"des-ede3-cbc":  {"des-ede3-cbc", 24, 8, 8, des.NewTripleDESCipher, false},
	"des-ede3-cfb":  {"des-ede3-cfb", 24, 8, 8, des.NewTripleDESCipher, false},
	"des-ede3-cfb1": {"des-ede3-cfb1", 24, 8, 8, des.NewTripleDESCipher, false},
	"des-ede3-cfb8": {"des-ede3-cfb8", 24, 8, 8, des.NewTripleDESCipher, false},
	"des-ede3-ofb":  {"des-ede3-ofb", 24, 8, 8, des.NewTripleDESCipher, false},
	"des3":          {"des3", 24, 8, 8, des.NewTripleDESCipher, false},

	// CAST5
	"cast":      {"cast5", 16, 8, 8, cast5NewCipher, false},
	"cast-cbc":  {"cast5-cbc", 16, 8, 8, cast5NewCipher, false},
	"cast5-cbc": {"cast5-cbc", 16, 8, 8, cast5NewCipher, false},
	"cast5-ecb": {"cast5-ecb", 16, 0, 8, cast5NewCipher, false},
	"cast5-cfb": {"cast5-cfb", 16, 8, 8, cast5NewCipher, false},
	"cast5-ofb": {"cast5-ofb", 16, 8, 8, cast5NewCipher, false},

	// RC2
	"rc2":        {"rc2", 16, 8, 8, rc2NewCipher, false},
	"rc2-cbc":    {"rc2-cbc", 16, 8, 8, rc2NewCipher, false},
	"rc2-ecb":    {"rc2-ecb", 16, 0, 8, rc2NewCipher, false},
	"rc2-cfb":    {"rc2-cfb", 16, 8, 8, rc2NewCipher, false},
	"rc2-ofb":    {"rc2-ofb", 16, 8, 8, rc2NewCipher, false},
	"rc2-40":     {"rc2-40", 5, 8, 8, rc2NewCipher, false},
	"rc2-40-cbc": {"rc2-40-cbc", 5, 8, 8, rc2NewCipher, false},
	"rc2-64":     {"rc2-64", 8, 8, 8, rc2NewCipher, false},
	"rc2-64-cbc": {"rc2-64-cbc", 8, 8, 8, rc2NewCipher, false},
	"rc2-128":    {"rc2-128", 16, 8, 8, rc2NewCipher, false},

	// RC4 - Stream Cipher
	"rc4":      {"rc4", 16, 0, 1, rc4NewCipher, true},
	"rc4-40":   {"rc4-40", 5, 0, 1, rc4NewCipher, true},
	"rc4-64":   {"rc4-64", 8, 0, 1, rc4NewCipher, true},
	"rc4-128":  {"rc4-128", 16, 0, 1, rc4NewCipher, true},
	"arc4":     {"arc4", 16, 0, 1, rc4NewCipher, true},
	"rc4-40-cbc": {"rc4-40", 5, 8, 1, rc4NewCipher, true}, // Algumas implementações usam IV com RC4
	"rc4-64-cbc":  {"rc4-64", 8, 8, 1, rc4NewCipher, true},
	"rc4-128-cbc": {"rc4-128", 16, 8, 1, rc4NewCipher, true},

	// Aliases
	"aes-256": {"aes-256-cbc", 32, 16, 16, aes.NewCipher, false},
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
func decryptAttempt(ciphertext, salt, password []byte, config *Config, cipherInfo CipherInfo) ([]byte, error) {
	var key, iv []byte
	if config.UsePBKDF2 {
		key, iv = deriveKeyPBKDF2(password, salt, cipherInfo.KeyLen, cipherInfo.IVLen, config.PBKDF2Iterations)
	} else {
		key, iv = evpBytesToKeyMD5(password, salt, cipherInfo.KeyLen, cipherInfo.IVLen)
	}

	// Verifica se o NewCipher é nil
	if cipherInfo.NewCipher == nil {
		return nil, fmt.Errorf("cipher %s not properly registered", config.Cipher)
	}

	block, err := cipherInfo.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var plaintext []byte

	// Para stream ciphers (como RC4)
	if cipherInfo.IsStream {
		plaintext = make([]byte, len(ciphertext))
		// RC4 é simétrico - XOR com a keystream
		// Se tiver IV, inicializa o cipher com o IV (algumas implementações)
		if cipherInfo.IVLen > 0 && len(iv) > 0 {
			// Para RC4 com IV, algumas implementações prefixam o IV
			// ou usam IV + key. Vamos tentar ambas as abordagens.
			// Primeiro tenta com key + iv combinados
			combinedKey := make([]byte, len(key)+len(iv))
			copy(combinedKey, key)
			copy(combinedKey[len(key):], iv)
			block2, err2 := cipherInfo.NewCipher(combinedKey)
			if err2 == nil {
				block2.Decrypt(plaintext, ciphertext)
				plaintext2, err2 := validatePlaintext(plaintext, config)
				if err2 == nil {
					return plaintext2, nil
				}
			}
		}
		// Fallback: usa apenas a chave
		block.Decrypt(plaintext, ciphertext)
		return validatePlaintext(plaintext, config)
	}

	// Detectar modo baseado no nome da cifra para block ciphers
	cipherName := config.Cipher
	isECB := stringsHasSuffix(cipherName, "-ecb") || cipherName == "des-ecb" || cipherName == "aes-128-ecb" || cipherName == "aes-192-ecb" || cipherName == "aes-256-ecb" || cipherName == "bf-ecb" || cipherName == "cast5-ecb" || cipherName == "rc2-ecb" || cipherName == "aria-128-ecb" || cipherName == "aria-192-ecb" || cipherName == "aria-256-ecb" || cipherName == "camellia-128-ecb" || cipherName == "camellia-192-ecb" || cipherName == "camellia-256-ecb" || cipherName == "sm4-ecb"
	isCTR := stringsHasSuffix(cipherName, "-ctr") || cipherName == "aes-128-ctr" || cipherName == "aes-192-ctr" || cipherName == "aes-256-ctr" || cipherName == "aria-128-ctr" || cipherName == "aria-192-ctr" || cipherName == "aria-256-ctr" || cipherName == "camellia-128-ctr" || cipherName == "camellia-192-ctr" || cipherName == "camellia-256-ctr" || cipherName == "sm4-ctr"
	isCFB := stringsHasSuffix(cipherName, "-cfb") || stringsHasSuffix(cipherName, "-cfb1") || stringsHasSuffix(cipherName, "-cfb8") || cipherName == "des-cfb" || cipherName == "des-cfb1" || cipherName == "des-cfb8" || cipherName == "bf-cfb" || cipherName == "cast5-cfb" || cipherName == "rc2-cfb" || cipherName == "aria-128-cfb" || cipherName == "aria-192-cfb" || cipherName == "aria-256-cfb" || cipherName == "camellia-128-cfb" || cipherName == "camellia-192-cfb" || cipherName == "camellia-256-cfb" || cipherName == "sm4-cfb"
	isOFB := stringsHasSuffix(cipherName, "-ofb") || cipherName == "des-ofb" || cipherName == "bf-ofb" || cipherName == "cast5-ofb" || cipherName == "rc2-ofb" || cipherName == "aria-128-ofb" || cipherName == "aria-192-ofb" || cipherName == "aria-256-ofb" || cipherName == "camellia-128-ofb" || cipherName == "camellia-192-ofb" || cipherName == "camellia-256-ofb" || cipherName == "sm4-ofb"

	switch {
	case isECB:
		plaintext = make([]byte, len(ciphertext))
		if len(ciphertext)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of block size")
		}
		for i := 0; i < len(ciphertext); i += block.BlockSize() {
			block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
		}
	case isCTR:
		stream := cipher.NewCTR(block, iv)
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
	case isCFB:
		stream := cipher.NewCFBDecrypter(block, iv)
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
	case isOFB:
		stream := cipher.NewOFB(block, iv)
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
	default:
		// CBC mode
		if len(ciphertext)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		plaintext = make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
	}

	// Remove PKCS#7 padding (apenas para modos CBC e ECB)
	if !isCTR && !isCFB && !isOFB {
		if len(plaintext) == 0 {
			return nil, fmt.Errorf("empty plaintext")
		}

		paddingLen := int(plaintext[len(plaintext)-1])
		if paddingLen == 0 || paddingLen > cipherInfo.BlockLen {
			return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
		}

		if paddingLen <= len(plaintext) {
			for i := len(plaintext) - paddingLen; i < len(plaintext); i++ {
				if plaintext[i] != byte(paddingLen) {
					return nil, fmt.Errorf("invalid padding bytes")
				}
			}
		} else {
			return nil, fmt.Errorf("padding length exceeds plaintext length")
		}
		plaintext = plaintext[:len(plaintext)-paddingLen]
	}

	return validatePlaintext(plaintext, config)
}

// --- Validação de Conteúdo ---
func validatePlaintext(plaintext []byte, config *Config) ([]byte, error) {
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

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
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
func worker(id int, config *Config, salt, ciphertext []byte, passwordChan <-chan string, results chan<- string, wg *sync.WaitGroup, stopFlag *atomic.Bool, attempts *uint64, method string, cipherInfo CipherInfo) {
	defer wg.Done()

	for password := range passwordChan {
		if stopFlag.Load() {
			return
		}

		atomic.AddUint64(attempts, 1)

		if atomic.LoadUint64(attempts)%10000 == 0 {
			fmt.Printf("\r[%s] Testing: %-20s | Attempts: %d", method, password, atomic.LoadUint64(attempts))
		}

		_, err := decryptAttempt(ciphertext, salt, []byte(password), config, cipherInfo)
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
func tryBothMethods(config *Config, salt, ciphertext []byte, cipherInfo CipherInfo) string {
	fmt.Println("\nAuto-detecting key derivation method...")

	configPBKDF2 := *config
	configPBKDF2.UsePBKDF2 = true
	configPBKDF2.PBKDF2Iterations = 10000

	fmt.Println("  - Testing with PBKDF2 (iterations: 10000)...")
	result := bruteForceWithMethod(&configPBKDF2, salt, ciphertext, "PBKDF2", cipherInfo)
	if result != "" {
		return result
	}

	configMD5 := *config
	configMD5.UsePBKDF2 = false

	fmt.Println("  - PBKDF2 failed, trying MD5 (legacy)...")
	result = bruteForceWithMethod(&configMD5, salt, ciphertext, "MD5", cipherInfo)
	if result != "" {
		return result
	}

	return ""
}

func bruteForceWithMethod(config *Config, salt, ciphertext []byte, method string, cipherInfo CipherInfo) string {
	gen := NewPasswordGenerator(config)
	totalCombinations := gen.GetTotalCount()

	fmt.Printf("\n%s Mode:\n", method)
	fmt.Printf("  - Cipher: %s\n", config.Cipher)
	fmt.Printf("  - Key length: %d bytes\n", cipherInfo.KeyLen)
	fmt.Printf("  - Total combinations: %d\n", totalCombinations)
	fmt.Printf("  - Strict mode: %v\n", config.StrictMode)
	if cipherInfo.IsStream {
		fmt.Printf("  - Stream cipher: Yes\n")
	}

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
		go worker(i, config, salt, ciphertext, passwordChan, results, &wg, stopFlag, &attempts, method, cipherInfo)
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
	flag.BoolVar(&config.UseSalt, "salt", true, "Use salt (OpenSSL salted format)")
	flag.BoolVar(&config.UsePBKDF2, "pbkdf2", false, "Use PBKDF2 key derivation (modern OpenSSL)")
	flag.IntVar(&config.PBKDF2Iterations, "iter", 10000, "PBKDF2 iteration count")
	flag.BoolVar(&config.AutoDetect, "auto", true, "Auto-detect key derivation method (try both)")
	flag.BoolVar(&config.StrictMode, "strict", true, "Use strict validation (95%% printable, validate small files)")
	flag.StringVar(&config.Cipher, "cipher", "aes-256-cbc", "Cipher algorithm (e.g., aes-256-cbc, des3, bf, rc4)")
	flag.Parse()

	if config.FilePath == "" {
		fmt.Println("ERROR: -file is required")
		flag.Usage()
		os.Exit(1)
	}

	// Get cipher info
	cipherInfo, ok := cipherRegistry[config.Cipher]
	if !ok {
		fmt.Printf("ERROR: Unsupported cipher: %s\n", config.Cipher)
		fmt.Println("\nSupported ciphers:")
		fmt.Println("\nAES:")
		fmt.Println("  - aes-128-cbc, aes-192-cbc, aes-256-cbc")
		fmt.Println("  - aes-128-ctr, aes-192-ctr, aes-256-ctr")
		fmt.Println("  - aes-128-ecb, aes-192-ecb, aes-256-ecb")
		fmt.Println("  - aes-128-ofb, aes-192-ofb, aes-256-ofb")
		fmt.Println("  - aes-128-cfb, aes-192-cfb, aes-256-cfb")
		fmt.Println("  - aes-128-cfb1, aes-192-cfb1, aes-256-cfb1")
		fmt.Println("  - aes-128-cfb8, aes-192-cfb8, aes-256-cfb8")
		fmt.Println("\nARIA:")
		fmt.Println("  - aria-128-cbc, aria-192-cbc, aria-256-cbc")
		fmt.Println("  - aria-128-ctr, aria-192-ctr, aria-256-ctr")
		fmt.Println("  - aria-128-ecb, aria-192-ecb, aria-256-ecb")
		fmt.Println("  - aria-128-ofb, aria-192-ofb, aria-256-ofb")
		fmt.Println("  - aria-128-cfb, aria-192-cfb, aria-256-cfb")
		fmt.Println("\nCamellia:")
		fmt.Println("  - camellia-128-cbc, camellia-192-cbc, camellia-256-cbc")
		fmt.Println("  - camellia-128-ctr, camellia-192-ctr, camellia-256-ctr")
		fmt.Println("  - camellia-128-ecb, camellia-192-ecb, camellia-256-ecb")
		fmt.Println("  - camellia-128-ofb, camellia-192-ofb, camellia-256-ofb")
		fmt.Println("  - camellia-128-cfb, camellia-192-cfb, camellia-256-cfb")
		fmt.Println("\nSM4 (requer a biblioteca gmsm):")
		fmt.Println("  - sm4, sm4-cbc, sm4-ctr, sm4-ecb, sm4-cfb, sm4-ofb")
		fmt.Println("\nBlowfish:")
		fmt.Println("  - bf, bf-cbc, bf-ecb, bf-cfb, bf-ofb, blowfish")
		fmt.Println("\nDES:")
		fmt.Println("  - des, des-cbc, des-ecb, des-cfb, des-ofb, des-cfb1, des-cfb8")
		fmt.Println("\n3DES:")
		fmt.Println("  - des-ede, des-ede-cbc, des-ede-cfb, des-ede-ofb")
		fmt.Println("  - des-ede3, des-ede3-cbc, des-ede3-cfb, des-ede3-ofb, des3")
		fmt.Println("\nCAST5:")
		fmt.Println("  - cast, cast-cbc, cast5-cbc, cast5-ecb, cast5-cfb, cast5-ofb")
		fmt.Println("\nRC2:")
		fmt.Println("  - rc2, rc2-cbc, rc2-ecb, rc2-cfb, rc2-ofb")
		fmt.Println("  - rc2-40, rc2-40-cbc, rc2-64, rc2-64-cbc, rc2-128")
		fmt.Println("\nRC4 (Stream Cipher):")
		fmt.Println("  - rc4, rc4-40, rc4-64, rc4-128, arc4")
		fmt.Println("  - rc4-40-cbc, rc4-64-cbc, rc4-128-cbc (with IV)")
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
	fmt.Printf("  - Cipher: %s\n", config.Cipher)
	fmt.Printf("  - Length: %d to %d characters\n", config.MinLen, config.MaxLen)
	fmt.Printf("  - Prefix: '%s'\n", config.Prefix)
	fmt.Printf("  - Suffix: '%s'\n", config.Suffix)
	fmt.Printf("  - Charset: %d characters\n", len(config.Charset))
	fmt.Printf("  - Using %d threads\n", config.Threads)
	fmt.Printf("  - Strict validation: %v\n", config.StrictMode)
	fmt.Println()

	var foundPassword string

	if config.AutoDetect {
		foundPassword = tryBothMethods(&config, salt, ciphertext, cipherInfo)
	} else {
		method := "MD5 (legacy)"
		if config.UsePBKDF2 {
			method = fmt.Sprintf("PBKDF2 (iterations: %d)", config.PBKDF2Iterations)
		}
		fmt.Printf("Using key derivation: %s\n", method)
		foundPassword = bruteForceWithMethod(&config, salt, ciphertext, method, cipherInfo)
	}

	if foundPassword != "" {
		fmt.Printf("\nSUCCESS! Password found: %s\n", foundPassword)
		fmt.Println("\nVerifying with OpenSSL command:")
		fmt.Printf("openssl enc -d -%s -in %s -k \"%s\"\n", config.Cipher, config.FilePath, foundPassword)
	} else {
		fmt.Printf("\nPassword not found.\n")
	}
}
