package generator

var LibraryTemplates = map[string]string{
	"passcrypt.go": `package passcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Encrypt выполняет гибридное шифрование пароля с использованием AES-GCM и RSA-OAEP.
// Сначала генерируется случайный AES-ключ, которым шифруется пароль.
// Затем AES-ключ шифруется с помощью публичного RSA-ключа.
// Возвращает зашифрованный пароль в формате Base64 или ошибку.
func Encrypt(password string) (string, error) {
	// Проверяем, что ключи инициализированы
	if err := ensureInit(); err != nil {
		return "", err
	}
	
	// Проверяем, что пароль не пустой
	if password == "" {
		return "", errors.New("empty password")
	}

	// Генерируем случайный 256-битный AES-ключ
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", err
	}

	// Шифруем пароль с помощью AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// Генерируем nonce для AES-GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	
	// Шифруем пароль
	ciphertext := gcm.Seal(nil, nonce, []byte(password), nil)

	// Шифруем AES-ключ с помощью публичного RSA-ключа
	pub := &getPrivateKey().PublicKey
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("RSA enc: %w", err)
	}

	// Объединяем зашифрованный AES-ключ, nonce и зашифрованный пароль
	result := append(encKey, append(nonce, ciphertext...)...)
	
	// Кодируем результат в Base64 и возвращаем
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt выполняет гибридное дешифрование пароля.
// Сначала дешифрует AES-ключ с помощью приватного RSA-ключа.
// Затем дешифрует пароль с помощью AES-GCM.
// Принимает зашифрованный пароль в формате Base64.
// Возвращает расшифрованный пароль или ошибку.
func Decrypt(encryptedB64 string) (string, error) {
	// Проверяем, что ключи инициализированы
	if err := ensureInit(); err != nil {
		return "", err
	}
	
	// Декодируем зашифрованный пароль из Base64
	data, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	
	// Проверяем минимальную длину данных (256 байт RSA + 12 байт nonce)
	if len(data) < 256+12 {
		return "", errors.New("invalid ciphertext")
	}

	// Получаем приватный ключ
	priv := getPrivateKey()
	
	// Извлекаем зашифрованный AES-ключ (первые 256 байт)
	encKey := data[:256]
	
	// Извлекаем остальные данные (nonce и зашифрованный пароль)
	rest := data[256:]

	// Дешифруем AES-ключ с помощью приватного RSA-ключа
	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, priv, encKey, nil)
	if err != nil {
		return "", fmt.Errorf("RSA dec: %w", err)
	}

	// Создаем AES-шифр для дешифрования пароля
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Извлекаем nonce (первые gcm.NonceSize() байт)
	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return "", errors.New("invalid nonce")
	}
	nonce := rest[:nonceSize]
	
	// Извлекаем зашифрованный пароль
	ct := rest[nonceSize:]

	// Дешифруем пароль с помощью AES-GCM
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("GCM open: %w", err)
	}
	
	// Возвращаем расшифрованный пароль
	return string(plain), nil
}

// initErr хранит ошибку инициализации ключей
var initErr error

// ensureInit проверяет, что ключи были успешно инициализированы.
// Возвращает ошибку, если инициализация не удалась.
func ensureInit() error {
	return initErr
}

// init выполняется при инициализации пакета.
// Обрабатывает возможные паники при инициализации ключей.
func init() {
	// Восстанавливаемся после паники, если она произошла
	if err := recover(); err != nil {
		initErr = fmt.Errorf("key init: %v", err)
	}
}
`,
	"secure_embed.go": `package passcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
    "crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/argon2"
	"sync"
)

// cachedPriv хранит кэшированный приватный ключ
// initOnce обеспечивает однократную инициализацию
var (
	cachedPriv *rsa.PrivateKey
	initOnce   sync.Once
)

// getPrivateKey возвращает кэшированный приватный ключ.
// При первом вызове выполняет сборку ключа из фрагментов.
// Если сборка не удалась, вызывает панику.
func getPrivateKey() *rsa.PrivateKey {
	// Выполняем сборку ключа только один раз
	initOnce.Do(assembleSecureKeys)
	
	// Если ключ не был собран, вызываем панику
	if cachedPriv == nil {
		panic("PassCrypt: key assembly failed")
	}
	
	return cachedPriv
}

// deriveAESKey генерирует ключ для AES-шифрования фрагмента с использованием Argon2id.
// idx - индекс фрагмента
// Возвращает 32-байтный ключ для AES-256.
// Механизм реализации fragmentPasswordSeed:
// 1. Использует fragmentPasswordSeed как основу для генерации пароля фрагмента
// 2. Комбинирует fragmentPasswordSeed с deriveSalt и магическими константами
// 3. Генерирует 16-байтный пароль на основе этих данных
// 4. Использует Argon2id для создания 32-байтного ключа из пароля
func deriveAESKey(idx int) []byte {
    h := sha256.New()
	h.Write(fragmentPasswordSeed[:]) // используем секретный seed как основу
	h.Write(deriveSalt[:]) // добавляем соль для дополнительной случайности
	binary.Write(h, binary.LittleEndian, magicConstants[idx%8]) // добавляем магическую константу
	binary.Write(h, binary.LittleEndian, uint64(idx)) // добавляем индекс фрагмента
	password := h.Sum(nil)[:16] // получаем 16-байтный пароль

	// Используем первое магическое значение как "перец" для соли
	pepper := make([]byte, 8)
	binary.LittleEndian.PutUint64(pepper, magicConstants[0])
	
	// Генерируем ключ с помощью Argon2id
	// Параметры: 4 итерации, 64MiB памяти, 4 потока, 32 байта выхода
	return argon2.IDKey(
		append(deriveSalt[:], pepper...),                    // соль + перец
		password,   // пароль (идентификатор фрагмента)
		4,    // итерации
		64*1024, // память (64 MiB)
		4,    // потоки
		32,   // длина ключа (32 байта для AES-256)
	)
}

// assembleSecureKeys собирает приватный ключ из фрагментов.
// Выполняет дешифрование фрагментов, восстанавливает XOR-маску и приватный ключ.
// Результат кэшируется в cachedPriv.
func assembleSecureKeys() {
	// Инициализируем буферы для XOR-маски и зашифрованного приватного ключа
	xorMask := make([]byte, 512)
	encryptedPriv := make([]byte, 0, privPEMSize)

	// Счетчики заполненных байт маски и реальных фрагментов
	maskFilled := 0
	realFilled := 0

	// Обрабатываем фрагменты в порядке, определенном fragmentOrder
	for _, pos := range fragmentOrder {
		// Получаем фрагмент по позиции
		f := encryptedFragments[pos]
		
		// Генерируем ключ для дешифрования фрагмента
		key := deriveAESKey(pos)

		// Создаем AES-шифр для дешифрования фрагмента
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)

		// Декодируем данные и nonce фрагмента из Base64
		data, _ := base64.StdEncoding.DecodeString(f.Data)
		nonce, _ := base64.StdEncoding.DecodeString(f.Nonce)
		
		// Пытаемся дешифровать фрагмент
		pt, err := gcm.Open(nil, nonce, data, nil)
		if err != nil {
			// Пропускаем поврежденные или dummy фрагменты
			continue
		}

		// Обрабатываем фрагмент в зависимости от того, заполнена ли маска
		if maskFilled < len(xorMask) {
			// Заполняем XOR-маску (первые 16 фрагментов по 32 байта)
			toCopy := 32
			if len(pt) < toCopy {
				toCopy = len(pt)
			}
			
			// Копируем данные в маску
			n := copy(xorMask[maskFilled:], pt[:toCopy])
			maskFilled += n

			// Если в фрагменте остались данные, добавляем их в зашифрованный ключ
			if len(pt) > toCopy {
				encryptedPriv = append(encryptedPriv, pt[toCopy:]...)
			}
		} else {
			// Добавляем данные в зашифрованный ключ
			encryptedPriv = append(encryptedPriv, pt...)
		}

		// Увеличиваем счетчик обработанных фрагментов
		realFilled++
		
		// Прекращаем обработку, если собраны все фрагменты
		if realFilled >= fragmentCount {
			break
		}
	}

	// Проверяем, что все данные собраны корректно
	if maskFilled != len(xorMask) || len(encryptedPriv) < privPEMSize {
		panic("PassCrypt: incomplete key reconstruction")
	}
	
	// Обрезаем зашифрованный ключ до нужного размера
	encryptedPriv = encryptedPriv[:privPEMSize]

	// Выполняем XOR-дешифрование приватного ключа
	privPEM := make([]byte, len(encryptedPriv))
	for i := range encryptedPriv {
		privPEM[i] = encryptedPriv[i] ^ xorMask[i%len(xorMask)]
	}

	// Декодируем PEM-блок приватного ключа
	block, _ := pem.Decode(privPEM)
	if block == nil {
		panic("PassCrypt: invalid PEM")
	}
	
	// Парсим приватный ключ
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("PassCrypt: parse key: %%v", err))
	}
	
	// Кэшируем приватный ключ
	cachedPriv = priv
}

// init выполняется при инициализации пакета.
// Выполняет сборку ключей при запуске.
func init() {
	assembleSecureKeys()
}
`,
}
