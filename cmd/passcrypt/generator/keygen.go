package generator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	mathRand "math/rand"

	"golang.org/x/crypto/argon2"
)

// GenerateKeys генерирует RSA-пару ключей и XOR-маску.
// Возвращает приватный ключ, XOR-маску и ошибку (если возникла).
func GenerateKeys() (*rsa.PrivateKey, []byte, error) {
	// Генерируем RSA-пару ключей длиной 2048 бит
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Генерируем XOR-маску длиной 512 байт
	xorMask := make([]byte, 512)
	_, err = rand.Read(xorMask)
	if err != nil {
		return nil, nil, err
	}

	return priv, xorMask, nil
}

// EncryptPrivateKey выполняет XOR-шифрование PEM-представления приватного ключа.
// Возвращает зашифрованный ключ, его размер и ошибку (если возникла).
func EncryptPrivateKey(priv *rsa.PrivateKey, xorMask []byte) ([]byte, int, error) {
	// Кодируем приватный ключ в PEM-формат
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Сохраняем размер PEM-представления
	size := len(privPEM)

	// Выполняем XOR-шифрование каждого байта ключа
	encryptedPriv := make([]byte, size)
	for i := range privPEM {
		encryptedPriv[i] = privPEM[i] ^ xorMask[i%512]
	}

	return encryptedPriv, size, nil
}

// chunkData разбивает данные на фрагменты фиксированного размера.
// Возвращает массив фрагментов.
func chunkData(data []byte, size int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += size {
		end := i + size
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// DeriveFragmentKey генерирует ключ для шифрования фрагмента с использованием Argon2id.
// idx - индекс фрагмента
// magic - магические константы для деривации
// salt - соль для деривации
// seed - секретный seed для вычисления пароля фрагмента
// Возвращает 32-байтный ключ для AES-256.
func DeriveFragmentKey(idx int, magic [8]uint64, salt [32]byte, seed [32]byte) []byte {
	h := sha256.New()
	h.Write(seed[:]) // ← главный секрет
	h.Write(salt[:])
	binary.Write(h, binary.LittleEndian, magic[idx%8])
	binary.Write(h, binary.LittleEndian, uint64(idx))
	password := h.Sum(nil)[:16]

	// Используем первое магическое значение как "перец" для соли
	pepper := make([]byte, 8)
	binary.LittleEndian.PutUint64(pepper, magic[0])

	// Генерируем ключ с помощью Argon2id
	// Параметры: 4 итерации, 64MiB памяти, 4 потока, 32 байта выхода
	return argon2.IDKey(
		append(salt[:], pepper...), // соль + перец
		password,                   // пароль (идентификатор фрагмента)
		4,                          // итерации
		64*1024,                    // память (64 MiB)
		4,                          // потоки
		32,                         // длина ключа (32 байта для AES-256)
	)
}

// GenerateFragments создает зашифрованные, перемешанные фрагменты с dummy-фрагментами.
// xorMask - XOR-маска для шифрования приватного ключа
// encryptedPriv - зашифрованный приватный ключ
// Возвращает фрагменты, магические константы, соль, порядок реальных фрагментов, seed и ошибку (если возникла).
func GenerateFragments(xorMask, encryptedPriv []byte) ([FragmentCount]struct{ Data, Nonce string }, [8]uint64, [32]byte, []int, [32]byte, error) {
	// Инициализируем структуры для возврата
	var frags [FragmentCount]struct{ Data, Nonce string }
	var magic [8]uint64
	var deriveSalt [32]byte
	var realOrder []int

	seed := [32]byte{}
	rand.Read(seed[:])

	// Генерируем магические константы (8 штук по 8 байт)
	for i := range magic {
		var b [8]byte
		rand.Read(b[:])
		magic[i] = binary.LittleEndian.Uint64(b[:])
	}

	// Генерируем соль для деривации ключей фрагментов
	rand.Read(deriveSalt[:])

	// Разбиваем данные на фрагменты
	// Маска разбивается на 16 фрагментов по 32 байта
	maskChunks := chunkData(xorMask, 32)
	// Зашифрованный ключ разбивается на фрагменты по 97 байт
	privChunks := chunkData(encryptedPriv, 97)
	// Объединяем все реальные фрагменты
	realChunks := append(maskChunks, privChunks...)

	// Создаем массив позиций и перемешиваем его
	positions := make([]int, FragmentCount)
	for i := range positions {
		positions[i] = i
	}
	mathRand.Shuffle(FragmentCount, func(i, j int) {
		positions[i], positions[j] = positions[j], positions[i]
	})

	// Заполняем фрагменты
	realIdx := 0
	for _, pos := range positions {
		var chunk []byte
		// Если это реальный фрагмент
		if realIdx < len(realChunks) {
			chunk = realChunks[realIdx]
			// Сохраняем позицию реального фрагмента
			realOrder = append(realOrder, pos)
			realIdx++
		} else {
			// Создаем dummy-фрагмент
			chunk = make([]byte, 97)
			rand.Read(chunk)
		}

		// Генерируем ключ для шифрования фрагмента
		key := DeriveFragmentKey(pos, magic, deriveSalt, seed)

		// Создаем AES-шифр
		block, err := aes.NewCipher(key)
		if err != nil {
			return frags, magic, deriveSalt, nil, seed, err
		}

		// Создаем GCM
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return frags, magic, deriveSalt, nil, seed, err
		}

		// Генерируем nonce
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)

		// Шифруем фрагмент
		ct := gcm.Seal(nil, nonce, chunk, nil)

		// Сохраняем фрагмент
		frags[pos] = struct{ Data, Nonce string }{
			Data:  base64.StdEncoding.EncodeToString(ct),
			Nonce: base64.StdEncoding.EncodeToString(nonce),
		}
	}

	return frags, magic, deriveSalt, realOrder, seed, nil
}
