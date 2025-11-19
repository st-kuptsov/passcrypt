package generator

import (
	"os"
	"path/filepath"
	"strings"
)

// WriteLibraryFiles записывает файлы шаблонов библиотеки в указанную директорию.
// outputDir - директория для записи файлов
// Возвращает ошибку, если запись не удалась.
func WriteLibraryFiles(outputDir string) error {
	// Создаем директорию вывода, если она не существует
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// Записываем все файлы шаблонов
	for path, content := range LibraryTemplates {
		// Формируем полный путь к файлу
		fullPath := filepath.Join(outputDir, strings.ReplaceAll(path, "/", string(filepath.Separator)))

		// Создаем директорию для файла, если она не существует
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return err
		}

		// Записываем файл
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}

// WriteEmbeddedKeysFile генерирует и записывает файл с встроенными ключами.
// frags - зашифрованные фрагменты
// magic - магические константы
// salt - соль для деривации
// size - размер PEM-представления приватного ключа
// order - порядок фрагментов
// seed - секретный seed для вычисления пароля фрагмента
// outputDir - директория для записи файла
// Возвращает ошибку, если запись не удалась.
// seed используется в механизме шифрования фрагментов для вычисления
// пароля фрагмента, который затем используется для генерации ключа
// шифрования каждого фрагмента.
func WriteEmbeddedKeysFile(frags [FragmentCount]struct{ Data, Nonce string }, magic [8]uint64, salt [32]byte, size int, order []int, seed [32]byte, outputDir string) error {
	// Генерируем код для файла с ключами
	code := GenerateEmbeddedKeysCode(frags, magic, salt, size, seed, order)

	// Формируем путь к файлу
	path := filepath.Join(outputDir, "embedded_keys.go")

	// Создаем директорию для файла, если она не существует
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	// Записываем файл с правами 0600 (только владелец может читать/писать)
	return os.WriteFile(path, []byte(code), 0600)
}
