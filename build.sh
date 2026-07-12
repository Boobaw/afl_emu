#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Запуск Dual-Build конвейера...${NC}"

# Очистка
rm -f harness harness_debug *.o

# =================================================================
# СБОРКА 1: БОЕВАЯ ВЕРСИЯ ДЛЯ AFL++ (harness)
# =================================================================
echo -e "${YELLOW}[*] Собираем БОЕВУЮ версию для фаззинга...${NC}"

# ГОВОРИМ КОМПИЛЯТОРУ ЗАШИТЬ В БИНАРНИК КАРТУ НА 64KB!
export AFL_MAP_SIZE=65536 

gcc -O2 -Wall -D__AFL_COMPILER -c src/emu_init.c -o emu_init.o
gcc -O2 -Wall -D__AFL_COMPILER -c src/hook.c -o hook.o
afl-cc -O2 -Wall src/main.c emu_init.o hook.o -o harness -lunicorn -lpthread

rm -f emu_init.o hook.o

# =================================================================
# СБОРКА 2: ОТЛАДОЧНАЯ ВЕРСИЯ ДЛЯ РУЧНОГО ЗАПУСКА (harness_debug)
# =================================================================
echo -e "${YELLOW}[*] Собираем ОТЛАДОЧНУЮ версию со всеми логами...${NC}"
# Компилируем обычным gcc БЕЗ флага __AFL_COMPILER (код отладки остается!)
gcc -O2 -Wall -c src/emu_init.c -o emu_init.o
gcc -O2 -Wall -c src/hook.c -o hook.o
gcc -O2 -Wall src/main.c emu_init.o hook.o -o harness_debug -lunicorn -lpthread

rm -f emu_init.o hook.o

echo -e "${GREEN}[+] Готово! Создано два бинарника:${NC}"
echo -e "    ->  ${GREEN}harness${NC}        (для запуска внутри afl-fuzz)"
echo -e "    ->  ${GREEN}harness_debug${NC}  (для ручной отладки крашей)"