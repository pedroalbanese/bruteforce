# BruteForce-Salted-OpenSSL
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/bruteforce/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/bruteforce?status.png)](http://godoc.org/github.com/pedroalbanese/bruteforce)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/bruteforce/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/bruteforce/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/bruteforce)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/bruteforce)](https://github.com/pedroalbanese/bruteforce/releases)

Ferramenta de recuperação de senhas para arquivos criptografados com OpenSSL, escrita em Go puro.

## Características

- Suporte a MD5 (legado) e PBKDF2 (moderno) com detecção automática
- Força bruta com charset personalizável, prefixo e sufixo
- Processamento paralelo com múltiplas threads
- Validação rigorosa (padding PKCS#7, conteúdo ASCII imprimível)
- Relatório de progresso em tempo real

## Parâmetros

| Parâmetro | Padrão | Descrição |
|-----------|--------|-----------|
| `-file` | (obrigatório) | Arquivo criptografado |
| `-min` | 1 | Tamanho mínimo da senha |
| `-max` | 8 | Tamanho máximo da senha |
| `-prefix` | "" | Prefixo conhecido |
| `-suffix` | "" | Sufixo conhecido |
| `-charset` | alfanumérico | Conjunto de caracteres |
| `-threads` | NumCPU | Número de threads |
| `-verbose` | 3 | Intervalo do progresso (segundos) |
| `-magic` | "" | Bytes mágicos (ex: `\x1f\x8b` para gzip) |
| `-pbkdf2` | false | Usar PBKDF2 (OpenSSL moderno) |
| `-iter` | 10000 | Iterações do PBKDF2 |
| `-auto` | true | Detecção automática do método |
| `-strict` | true | Validação rigorosa (95% imprimível) |

## Exemplos

```bash
# Força bruta com 3 caracteres minúsculos
./bruteforce -file segredo.enc -charset "abcdefghijklmnopqrstuvwxyz" -min 3 -max 3

# Com prefixo conhecido
./bruteforce -file segredo.enc -prefix "abc" -min 6 -max 6

# Arquivo binário (gzip)
./bruteforce -file backup.enc -magic "\x1f\x8b" -min 5 -max 8

# Usando PBKDF2
./bruteforce -file segredo.enc -pbkdf2 -min 4 -max 6
```

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
