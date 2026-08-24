#!/usr/bin/env bash

# Настройка core_pattern (требует sudo)
echo core | sudo tee /proc/sys/kernel/core_pattern > /dev/null

# Переменные окружения AFL++
export AFL_MAP_SIZE=65536
export AFL_SYNC_TIME=1
export AFL_IMPORT_FIRST=1

# Конфигурация по умолчанию
TARGET_BIN="./harness"
TARGET_ARG="target/keymaster_9pro.elf"
OUT_DIR="fuzz_out"
NUM_SLAVES=3
INPUT_DIR="-" # По умолчанию продолжаем работу (-i -)
ENABLE_AI=false

# Пути для AI-мутатора
AI_PYTHON_PATH="$HOME/AI_fuzz/src"
AI_MODULE_NAME="ai_mutator"

# Справка по использованию
usage() {
    echo "Использование: $0 [-c] [-s num_slaves] [-a] [-h]"
    echo "  -c             Запустить с cmin_queue/ вместо режима возобновления (-i -)"
    echo "  -s num_slaves  Количество стандартных slave-воркеров (по умолчанию: 3)"
    echo "  -a             Включить дополнительный AI Slave (slave_ai с Ollama)"
    echo "  -h             Показать эту справку"
    exit 1
}

# Разбор флагов командной строки
while getopts "cs:ah" opt; do
    case ${opt} in
        c)
            INPUT_DIR="cmin_queue"
            ;;
        s)
            NUM_SLAVES=${OPTARG}
            ;;
        a)
            ENABLE_AI=true
            ;;
        h)
            usage
            ;;
        \?)
            usage
            ;;
    esac
done

# Проверка наличия папки cmin_queue, если передан флаг -c
if [ "$INPUT_DIR" = "cmin_queue" ] && [ ! -d "cmin_queue" ]; then
    echo "[!] Ошибка: Папка 'cmin_queue' не существует!"
    exit 1
fi

# Проверка на то, не запущены ли уже воркеры
if pgrep -f "afl-fuzz.*-M main" > /dev/null; then
    echo "[!] Ошибка: Похоже, главная сессия AFL++ уже запущена!"
    exit 1
fi

echo "[+] Запуск AFL++ (1 Main + $NUM_SLAVES Slaves)..."
[ "$ENABLE_AI" = true ] && echo "[+] AI Slave: ВКЛЮЧЕН (-S slave_ai)"
echo "[+] Режим ввода (-i): $INPUT_DIR"

# 1. Запуск Main в фоновом режиме
echo "[+] Запуск -M main..."
afl-fuzz -m none -i "$INPUT_DIR" -o "$OUT_DIR" -M main -- "$TARGET_BIN" "$TARGET_ARG" > /dev/null 2>&1 &

# Ждем инициализации структуры папок
sleep 1

# 2. Запуск стандартных Slaves в цикле
for i in $(seq 1 $NUM_SLAVES); do
    SLAVE_NAME="slave$i"
    echo "[+] Запуск -S $SLAVE_NAME..."
    afl-fuzz -m none -i "$INPUT_DIR" -o "$OUT_DIR" -S "$SLAVE_NAME" -- "$TARGET_BIN" "$TARGET_ARG" > /dev/null 2>&1 &
done

# 3. Запуск AI Slave при наличии флага -a
if [ "$ENABLE_AI" = true ]; then
    echo "[+] Запуск -S slave_ai (Python Mutator: $AI_MODULE_NAME)..."
    AFL_PYTHON_MODULE="$AI_MODULE_NAME" \
    PYTHONPATH="$AI_PYTHON_PATH:$PYTHONPATH" \
    afl-fuzz -m none -i "$INPUT_DIR" -o "$OUT_DIR" -S slave_ai -d -- "$TARGET_BIN" "$TARGET_ARG" > /dev/null 2>&1 &
fi

echo ""
echo "[✔] Все процессы успешно запущены в фоне!"
echo "[i] Для проверки статуса используй: ./status_fuzz.sh"
echo "[i] Для корректной остановки используй: ./stop_fuzz.sh"