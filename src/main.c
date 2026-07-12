#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <unicorn/unicorn.h>
#include "../include/config.h"

// Размер буфера для чтения мутированных данных (например, 4KB)
#define MAX_PAYLOAD_SIZE 4096

// Адреса из твоего Python-скрипта (нужно вынести их в config.h позже)
#define REQ_BUFFER 0x10000000
#define RSP_BUFFER 0x20000000
#define MAGIC_EXIT 0x99990000


// Объявления функций из других файлов
uc_err init_emu(uc_engine **uc, const char *target_bin);

void setup_hooks(uc_engine *uc); // Раскомментируем на следующем шаге

#ifdef __AFL_COMPILER
extern int coverage_enabled;
#endif

int main(int argc, char **argv) {
    uc_engine *uc;
    uc_err err;
    uint8_t payload[MAX_PAYLOAD_SIZE];

    if (argc < 2) {
        printf("Использование: %s <путь_к_бинарнику>\n", argv[0]);
        return -1;
    }

    // 1. Тяжелая инициализация (выполняется ОДИН РАЗ)
    err = init_emu(&uc, argv[1]);
    if (err != UC_ERR_OK) {
        printf("[-] Ошибка инициализации эмулятора: %s\n", uc_strerror(err));
        return -1;
    }

    // Подготовка буферов для пейлоада (мапим их в память эмулятора)
    uc_mem_map(uc, REQ_BUFFER, 0x1000, UC_PROT_ALL);
    uc_mem_map(uc, RSP_BUFFER, 0x1000, UC_PROT_ALL);
    uc_mem_map(uc, MAGIC_EXIT, 0x1000, UC_PROT_ALL); // Магический адрес выхода

    // Выделяем кучу
    uc_mem_map(uc, HEAP_START, HEAP_SIZE, UC_PROT_ALL);

    uint8_t val_true = 0x01;

    uc_mem_write(uc, 0x32100, &val_true, sizeof(val_true));
    uc_mem_write(uc, 0x32104, &val_true, sizeof(val_true));
    uc_mem_write(uc, 0x32209, &val_true, sizeof(val_true));

    // Здесь мы подключим хуки для отлова крашей
    setup_hooks(uc);

    // =================================================================
    // ЗАПУСК FORK SERVER'а AFL++
    // Всё, что выше этой строки, выполнится 1 раз.
    // Всё, что ниже - будет клонироваться (fork) тысячи раз в секунду.
    // =================================================================
#ifdef __AFL_COMPILER
    __AFL_INIT();
    coverage_enabled = 1;
#endif

    // 2. Читаем мутированные данные от AFL++
    ssize_t actual_size = read(STDIN_FILENO, payload, MAX_PAYLOAD_SIZE);
    
    // Если AFL++ сгенерировал мусор короче 4 байт (размера нашего заголовка),
    // нам нет смысла это эмулировать. Сразу выходим.
    if (actual_size < 4) {
        return 0;
    }

    // =================================================================
    // HARNESS-LEVEL FIXUP: Принудительное восстановление заголовка
    // =================================================================
    // Кастуем начало буфера к указателю на 32-битное число и пишем 0x10B.
    // Так как ARM64 обычно работает в режиме Little-Endian,
    // в памяти это автоматически запишется как байты: 0x0B 0x01 0x00 0x00.
    *(uint32_t *)payload = 0x0000010B; 

    // 3. Загружаем исправленные данные в виртуальную память Unicorn
    err = uc_mem_write(uc, REQ_BUFFER, payload, actual_size);
    if (err) return -1;

    // 4. Настраиваем регистры, как в твоем Python скрипте
    uc_reg_write(uc, UC_ARM64_REG_X0, &(uint64_t){REQ_BUFFER});
    uc_reg_write(uc, UC_ARM64_REG_X1, &(uint64_t){actual_size});
    uc_reg_write(uc, UC_ARM64_REG_X2, &(uint64_t){RSP_BUFFER});
    uc_reg_write(uc, UC_ARM64_REG_X3, &(uint64_t){0x1000});

    // Устанавливаем адрес возврата (Link Register) на магический адрес
    uc_reg_write(uc, UC_ARM64_REG_LR, &(uint64_t){MAGIC_EXIT});

    // 5. Запуск эмуляции!
    // Мы стартуем с TARGET_FUNC_ADDR и эмулируем до тех пор, пока PC не станет равен MAGIC_EXIT.
    err = uc_emu_start(uc, TARGET_FUNC_ADDR, MAGIC_EXIT, 10000, 50000);

    // 6. Обработка результатов (Связь с AFL++)
    if (err != UC_ERR_OK) {
        uint64_t pc, x0, x1, x2, lr;
            uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
        // Если движок упал с ошибкой памяти, мы ВЫЗЫВАЕМ ЖЕСТКОЕ ПАДЕНИЕ (abort).
        // AFL++ перехватывает сигнал SIGABRT и понимает: "Ага, этот пейлоад вызвал краш!".
        // Он автоматически сохранит этот пейлоад в папку fuzz_data/output/crashes.
        if (err == UC_ERR_READ_UNMAPPED || err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED) {
            printf("\n[!] КРАШ ЭМУЛЯТОРА!\n");
            printf("    Причина: %s\n", uc_strerror(err));
            abort(); 
        }
        else {
            printf("Ошибка без abort: %s\n", uc_strerror(err));
            
        }

        uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
        uc_reg_read(uc, UC_ARM64_REG_X0, &x0); // dst
        uc_reg_read(uc, UC_ARM64_REG_X1, &x1); // value
        uc_reg_read(uc, UC_ARM64_REG_X2, &x2); // size
        uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

        printf("    Адрес (PC): 0x%lx\n", pc);
        printf("    (X0): 0x%lx\n", x0);
        printf("    (X1): 0x%lx\n", x1);
        printf("    (X2): 0x%lx (в десятичном: %lu)\n", x2, x2);
        printf("    (LR): 0x%lx\n", lr);
#ifndef __AFL_COMPILER
        void print_pc_history();
        print_pc_history();
#endif
    }

    // Завершаем клонированный процесс чисто. 
    // AFL++ поймет, что этот пейлоад отработал штатно.
    return 0;
}