# BruteForce-Salted-OpenSSL
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/bruteforce-salted-openssl/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/bruteforce-salted-openssl?status.png)](http://godoc.org/github.com/pedroalbanese/bruteforce-salted-openssl)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/bruteforce-salted-openssl/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/bruteforce-salted-openssl/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/bruteforce-salted-openssl)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/bruteforce-salted-openssl)](https://github.com/pedroalbanese/bruteforce/releases)

Password recovery tool for OpenSSL encrypted files, written in pure Go.

## Features

- Support for MD5 (legacy) and PBKDF2 (modern) with auto-detection
- Brute-force with customizable charset, prefix and suffix
- Parallel processing with multiple threads
- Rigorous validation (PKCS#7 padding, printable ASCII content)
- Real-time progress reporting

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-file` | (required) | Encrypted file |
| `-min` | 1 | Minimum password length |
| `-max` | 8 | Maximum password length |
| `-prefix` | "" | Known prefix |
| `-suffix` | "" | Known suffix |
| `-charset` | alphanumeric | Character set |
| `-threads` | NumCPU | Number of threads |
| `-verbose` | 3 | Progress interval (seconds) |
| `-magic` | "" | Magic bytes (e.g., `\x1f\x8b` for gzip) |
| `-pbkdf2` | false | Use PBKDF2 (modern OpenSSL) |
| `-iter` | 10000 | PBKDF2 iterations |
| `-auto` | true | Auto-detection of method |
| `-strict` | true | Strict validation (95% printable) |
| `-cipher` | aes-256-cbc | Cipher algorithm |

## Supported Ciphers

AES, ARIA, Camellia, SEED, SM4, Blowfish, DES, 3DES, CAST5, RC2, RC4

```bash
# Brute-force with 3 lowercase characters
./bruteforce -file secret.enc -charset "abcdefghijklmnopqrstuvwxyz" -min 3 -max 3

# With known prefix
./bruteforce -file secret.enc -prefix "abc" -min 6 -max 6

# Binary file (gzip)
./bruteforce -file backup.enc -magic "\x1f\x8b" -min 5 -max 8

# Using PBKDF2
./bruteforce -file secret.enc -pbkdf2 -min 4 -max 6

# Using a specific cipher
./bruteforce -file secret.enc -cipher seed-cbc -min 4 -max 8

# With custom character set
./bruteforce -file secret.enc -charset "0123456789" -min 4 -max 6

# Using all available threads
./bruteforce -file secret.enc -threads 16 -min 4 -max 8
```

Check also: https://github.com/pedroalbanese/bruteforce-hash-openssl

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
