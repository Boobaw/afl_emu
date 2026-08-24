#!/usr/bin/env bash

echo "[+] Начинаем корректную остановку сессий AFL++..."

# Отправляем SIGINT (Ctrl+C) всем процессам afl-fuzz
pkill -INT -f "afl-fuzz.*-o fuzz_out"

if [ $? -eq 0 ]; then
    echo "[+] Сигнал завершения (SIGINT) отправлен."
    echo "[*] Ожидаем корректного сохранения данных на диск..."
    
    # Ждем, пока все процессы действительно завершатся
    while pgrep -f "afl-fuzz.*-o fuzz_out" > /dev/null; do
        sleep 1
    done
    
    echo "[✔] Все процессы AFL++ успешно завершены. Данные сохранены в папке fuzz_out/."
else
    echo "[-] Активные процессы afl-fuzz не найдены."
fi