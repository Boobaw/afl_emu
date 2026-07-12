#ifndef CONFIG_H
#define CONFIG_H

// --- Настройки памяти (выровнены по 4KB / 0x1000) ---

// Адрес, по которому мы будем загружать бинарный дамп (.text, .data и т.д.)
#define CODE_ADDRESS      0x100000
// Выделяем 2 MB под код (этого с запасом хватит для парсера)
#define CODE_SIZE         (2 * 1024 * 1024) 

// Адрес и размер стека
#define STACK_ADDRESS     0x80000000
#define STACK_SIZE        (2 * 1024 * 1024)

// Точка входа - адрес функции парсинга ASN.1, которую мы будем фаззить
// (Пока ставим заглушку, потом поменяешь на реальный оффсет из IDA)
#define TARGET_FUNC_ADDR  0x824 

// Куча
#define HEAP_START 0x80000000 
#define HEAP_SIZE  (16 * 1024 * 1024)

// Размер карты AFL (обычно 64KB, то есть 0x10000)
#define MAP_SIZE 65536

#endif // CONFIG_H