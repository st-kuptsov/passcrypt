package generator

const (
	FragmentCount  = 50                            // 16 (маска) + 34 (ключ) + 10 фиктивных
	MaskFragments  = 16                            // количество фрагментов маски
	KeyFragments   = 34                            // количество фрагментов ключа
	RealFragments  = MaskFragments + KeyFragments  // общее количество реальных фрагментов
	DummyFragments = FragmentCount - RealFragments // количество фиктивных фрагментов
)
