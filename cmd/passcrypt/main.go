package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/st-kuptsov/passcrypt/cmd/passcrypt/generator"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	var outputDir string
	flagSet := flag.NewFlagSet(command, flag.ExitOnError)
	flagSet.StringVar(&outputDir, "output-dir", "internal/passcrypt", "Directory to generate PassCrypt library")
	flagSet.Parse(os.Args[2:])

	switch command {
	case "init":
		if err := generator.FullInit(outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "Init failed: %v\n", err)
			os.Exit(1)
		}
		printSuccessMessage(outputDir)

	case "update":
		if err := generator.UpdateCodeOnly(outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
			os.Exit(1)
		}
		printUpdateMessage(outputDir)

	case "rekey":
		if err := generator.Rekey(outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "Rekey failed: %v\n", err)
			os.Exit(1)
		}
		printRekeyMessage(outputDir)

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// printUsage выводит справку по использованию утилиты
func printUsage() {
	fmt.Println(`PassCrypt - secure embedded password encryption library

Usage:
  passcrypt init     [-output-dir=path]    Full generation (code + keys)
  passcrypt update   [-output-dir=path]    Update code only (keys stay)
  passcrypt rekey    [-output-dir=path]    Generate new keys only
  passcrypt help                           Show this help

Examples:
  passcrypt init
  passcrypt update -output-dir=internal/auth
  passcrypt rekey

Description:
  PassCrypt uses RSA + AES-GCM with Argon2id-derived fragment keys.
  Keys are split into 50 shuffled fragments (with dummies) for obfuscation.
  Designed for servers without KMS: protects against source leaks and binary theft.

Security:
  - Fragments: AES-GCM encrypted, Argon2id-derived keys (64MiB memory-hard)
  - Build with: garble -tiny -literals -seed=$(head -c48 /dev/urandom | base64) build -ldflags='-s -w' .
  - DO NOT commit embedded_keys.go - add to .gitignore!
`)
}

// printSuccessMessage выводит сообщение об успешной генерации
func printSuccessMessage(outputDir string) {
	fmt.Println()
	fmt.Println("Done! PassCrypt generated successfully.")
	fmt.Println()
	fmt.Printf("Generated key file: %s/embedded_keys.go\n", outputDir)
	printSecurityNotes(outputDir)
}

// printUpdateMessage выводит сообщение об успешном обновлении кода
func printUpdateMessage(outputDir string) {
	fmt.Println()
	fmt.Println("Code updated successfully.")
	fmt.Println()
	fmt.Printf("Key file preserved: %s/embedded_keys.go\n", outputDir)
	printSecurityNotes(outputDir)
}

// printRekeyMessage выводит сообщение об успешной генерации новых ключей
func printRekeyMessage(outputDir string) {
	fmt.Println()
	fmt.Println("New encryption keys generated successfully.")
	fmt.Println()
	fmt.Printf("Updated key file: %s/embedded_keys.go\n", outputDir)
	printSecurityNotes(outputDir)
}

// printSecurityNotes выводит важные замечания по безопасности
func printSecurityNotes(outputDir string) {
	fmt.Println()
	fmt.Println("IMPORTANT SECURITY NOTES:")
	fmt.Println("1. Add to .gitignore:")
	fmt.Printf("   %s/embedded_keys.go\n", outputDir)
	fmt.Println()
	fmt.Println("2. For production builds, use garble:")
	fmt.Println("   garble -tiny -literals -seed=$(head -c48 /dev/urandom | base64) build -ldflags='-s -w' .")
	fmt.Println()
}
