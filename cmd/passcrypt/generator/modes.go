package generator

import "fmt"

// FullInit выполняет полную генерацию библиотеки с новыми ключами.
// Генерирует RSA-ключи, XOR-маску, фрагменты и записывает все файлы.
// outputDir - директория для генерации библиотеки
// Возвращает ошибку, если генерация не удалась.
// При генерации фрагментов также создается fragmentPasswordSeed -
// секретный seed для вычисления пароля фрагмента, который используется
// в механизме шифрования фрагментов.
func FullInit(outputDir string) error {
	// Выводим сообщение о начале генерации
	fmt.Printf("Generating PassCrypt in: %s\n", outputDir)

	// Генерируем RSA-ключи и XOR-маску
	priv, xorMask, err := GenerateKeys()
	if err != nil {
		return fmt.Errorf("key gen: %w", err)
	}

	// Шифруем приватный ключ с помощью XOR-маски
	encryptedPriv, size, err := EncryptPrivateKey(priv, xorMask)
	if err != nil {
		return fmt.Errorf("encrypt priv: %w", err)
	}

	// Генерируем фрагменты
	frags, magic, salt, order, seed, err := GenerateFragments(xorMask, encryptedPriv)
	if err != nil {
		return fmt.Errorf("fragments: %w", err)
	}

	// Записываем файлы шаблонов
	if err := WriteLibraryFiles(outputDir); err != nil {
		return fmt.Errorf("write files: %w", err)
	}

	// Записываем файл с ключами
	if err := WriteEmbeddedKeysFile(frags, magic, salt, size, order, seed, outputDir); err != nil {
		return fmt.Errorf("write keys: %w", err)
	}

	return nil
}

// UpdateCodeOnly обновляет только файлы шаблонов, сохраняя существующие ключи.
// outputDir - директория для обновления библиотеки
// Возвращает ошибку, если обновление не удалось.
func UpdateCodeOnly(outputDir string) error {
	// Выводим сообщение об обновлении
	fmt.Printf("Updating code only → %s\n", outputDir)

	// Записываем файлы шаблонов
	return WriteLibraryFiles(outputDir)
}

// Rekey генерирует новые ключи, сохраняя существующие файлы шаблонов.
// outputDir - директория для генерации новых ключей
// Возвращает ошибку, если генерация не удалась.
func Rekey(outputDir string) error {
	// Выводим сообщение о перевыпуске ключей
	fmt.Printf("Rekeying → %s\n", outputDir)

	// Генерируем новые RSA-ключи и XOR-маску
	priv, xorMask, err := GenerateKeys()
	if err != nil {
		return fmt.Errorf("new keys: %w", err)
	}

	// Шифруем новый приватный ключ с помощью XOR-маски
	encryptedPriv, size, err := EncryptPrivateKey(priv, xorMask)
	if err != nil {
		return fmt.Errorf("encrypt new priv: %w", err)
	}

	// Генерируем новые фрагменты
	frags, magic, salt, order, seed, err := GenerateFragments(xorMask, encryptedPriv)
	if err != nil {
		return fmt.Errorf("new fragments: %w", err)
	}

	// Записываем файл с новыми ключами
	return WriteEmbeddedKeysFile(frags, magic, salt, size, order, seed, outputDir)
}
