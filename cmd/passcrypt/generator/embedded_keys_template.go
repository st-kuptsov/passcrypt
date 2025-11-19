package generator

import (
	"fmt"
	"strings"
	"time"
)

// GenerateEmbeddedKeysCode генерирует содержимое файла embedded_keys.go.
// frags - зашифрованные фрагменты
// magic - магические константы для деривации ключей
// salt - соль для деривации ключей
// size - размер PEM-представления приватного ключа
// seed - секретный seed для вычисления пароля фрагмента
// order - порядок реальных фрагментов
// Возвращает строку с содержимым файла.
func GenerateEmbeddedKeysCode(
	frags [FragmentCount]struct{ Data, Nonce string },
	magic [8]uint64,
	salt [32]byte,
	size int,
	seed [32]byte,
	order []int,
) string {
	// Генерируем строки для фрагментов
	fragLines := make([]string, FragmentCount)
	for i, f := range frags {
		fragLines[i] = fmt.Sprintf("\t{%q, %q},", f.Data, f.Nonce)
	}

	// Генерируем строки для магических констант
	magicLines := make([]string, 8)
	for i, m := range magic {
		magicLines[i] = fmt.Sprintf("\t0x%016x,", m)
	}

	// Генерируем строку для соли
	saltLine := "var deriveSalt = [32]byte{\n"
	for i := 0; i < 32; i++ {
		if i%12 == 0 && i > 0 {
			saltLine += "\n"
		}
		saltLine += fmt.Sprintf("\t0x%02x, ", salt[i])
	}
	saltLine += "\n}"

	// Генерируем строку для порядка фрагментов
	orderLine := "var fragmentOrder = [...]int{"
	for i, idx := range order {
		if i%12 == 0 && i > 0 {
			orderLine += "\n\t"
		}
		orderLine += fmt.Sprintf("%d, ", idx)
	}
	orderLine += "\n}"

	seedLine := "var fragmentPasswordSeed = [32]byte{\n"
	for i, b := range seed {
		if i%12 == 0 && i > 0 {
			seedLine += "\n"
		}
		seedLine += fmt.Sprintf("\t0x%02x,", b)
	}
	seedLine += "\n}"

	// Добавляем комментарий о механизме реализации fragmentPasswordSeed
	seedLine = "// fragmentPasswordSeed - секретный seed для вычисления пароля фрагмента\n" + seedLine

	// Формируем полный код файла
	code := fmt.Sprintf(`// embedded_keys.go -- AUTO-GENERATED -- DO NOT COMMIT!
// Generated: %s

package passcrypt

// fragmentCount определяет общее количество фрагментов
const fragmentCount = %d

// encryptedFragments содержит зашифрованные фрагменты ключей
var encryptedFragments = [fragmentCount]struct{ Data string; Nonce string }{
%s
}

// magicConstants содержит магические константы для деривации ключей фрагментов
var magicConstants = [8]uint64{
%s
}

// deriveSalt содержит соль для деривации ключей фрагментов
%s

// fragmentOrder определяет порядок реальных фрагментов
%s

// privPEMSize содержит размер PEM-представления приватного ключа
var privPEMSize = %d

// fragmentPasswordSeed — секретный seed для вычисления пароля фрагмента
%s


`, time.Now().Format("2006-01-02 15:04:05"), FragmentCount,
		strings.Join(fragLines, "\n"),
		strings.Join(magicLines, "\n"),
		saltLine,
		orderLine,
		size,
		seedLine,
	)

	return code
}
