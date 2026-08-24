#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <unicorn/unicorn.h>
#include "../include/config.h"

#define MAX_PAYLOAD_SIZE 4096

#define REQ_BUFFER 0x10000000
#define RSP_BUFFER 0x20000000
#define MAGIC_EXIT 0x99990000

#define DATA_START 0x30000
#define DATA_SIZE  0x8000

// Объявления функций
uc_err init_emu(uc_engine **uc, const char *target_bin);
void setup_hooks(uc_engine *uc);
void reset_heap(uc_engine *uc);
void reset_prng();

#ifdef __AFL_COMPILER
extern int coverage_enabled;
int __afl_persistent_loop(unsigned int max_cnt);
#else
void print_pc_history(void);
#endif

int main(int argc, char **argv) {
    uc_engine *uc;
    uc_err err;
    uc_context *clean_context;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    uint8_t data_snapshot[DATA_SIZE];

    if (argc < 2) {
        printf("Использование: %s <путь_к_бинарнику>\n", argv[0]);
        return -1;
    }

    // 1. Инициализация ELF и Unicorn (ОДИН РАЗ)
    err = init_emu(&uc, argv[1]);
    if (err != UC_ERR_OK) {
        printf("[-] Ошибка инициализации эмулятора: %s\n", uc_strerror(err));
        return -1;
    }

    // Подготовка буферов
    uc_mem_map(uc, REQ_BUFFER, 0x1000, UC_PROT_ALL);
    uc_mem_map(uc, RSP_BUFFER, 0x1000, UC_PROT_ALL);
    uc_mem_map(uc, MAGIC_EXIT, 0x1000, UC_PROT_ALL);

    // Выделяем кучу
    uc_mem_map(uc, HEAP_START, HEAP_SIZE, UC_PROT_ALL);

    uint8_t val_true = 0x01;
    uc_mem_write(uc, 0x32100, &val_true, sizeof(val_true));
    uc_mem_write(uc, 0x32104, &val_true, sizeof(val_true));
    uc_mem_write(uc, 0x32184, &val_true, sizeof(val_true));
    uc_mem_write(uc, 0x32209, &val_true, sizeof(val_true));
    

    setup_hooks(uc);

    // Снимаем эталонный снапшот всей секции данных (0x30000 - 0x38000)
    uc_mem_read(uc, DATA_START, data_snapshot, DATA_SIZE);

    // Базовая настройка стека и эталонного контекста CPU
    uc_reg_write(uc, UC_ARM64_REG_SP, &(uint64_t){STACK_TOP});
    uc_context_alloc(uc, &clean_context);
    uc_context_save(uc, clean_context);

    // =================================================================
    // AFL++ PERSISTENT LOOP (БЕЗ FORK)
    // =================================================================
#ifdef __AFL_COMPILER
    // Проверяем, запущены ли мы под управлением afl-fuzz
    int is_fuzzing = (getenv("__AFL_PERSISTENT_LOOP") != NULL) || (getenv("AFL_PERSISTENT") != NULL);

    while (__afl_persistent_loop(is_fuzzing ? 10000 : 1)) {
        coverage_enabled = 1;
#endif

        // 2. Читаем мутированные данные
        ssize_t actual_size = read(STDIN_FILENO, payload, MAX_PAYLOAD_SIZE);
        if (actual_size < 4) {
#ifdef __AFL_COMPILER
            if (!is_fuzzing) break; // Одиночный запуск завершается сразу
            continue;
#else
            return 0;
#endif
        }

        // Восстанавливаем эталонное состояние CPU, кучи и глобальной памяти
        uc_context_restore(uc, clean_context);
        reset_heap(uc);
        reset_prng();
        uc_mem_write(uc, DATA_START, data_snapshot, DATA_SIZE);

        // HARNESS-LEVEL FIXUP: Восстановление Command ID 0x10B
        *(uint32_t *)payload = 0x0000010B; 

        // Загружаем данные
        err = uc_mem_write(uc, REQ_BUFFER, payload, actual_size);
        if (err) {
#ifdef __AFL_COMPILER
            continue;
#else
            return -1;
#endif
        }

        // Настраиваем аргументы и стек
        uc_reg_write(uc, UC_ARM64_REG_SP, &(uint64_t){STACK_TOP});
        uc_reg_write(uc, UC_ARM64_REG_X0, &(uint64_t){REQ_BUFFER});
        uc_reg_write(uc, UC_ARM64_REG_X1, &(uint64_t){actual_size});
        uc_reg_write(uc, UC_ARM64_REG_X2, &(uint64_t){RSP_BUFFER});
        uc_reg_write(uc, UC_ARM64_REG_X3, &(uint64_t){0x1000});
        uc_reg_write(uc, UC_ARM64_REG_LR, &(uint64_t){MAGIC_EXIT});

        // 5. Запуск эмуляции
#ifndef __AFL_COMPILER
    err = uc_emu_start(uc, TARGET_FUNC_ADDR, MAGIC_EXIT, 0, 10000);
#endif

#ifdef __AFL_COMPILER
    err = uc_emu_start(uc, TARGET_FUNC_ADDR, MAGIC_EXIT, 0, 0);
#endif


        // 6. Обработка результатов и логирование
        if (err != UC_ERR_OK) {
            if (err == UC_ERR_READ_UNMAPPED || 
                err == UC_ERR_WRITE_UNMAPPED || 
                err == UC_ERR_FETCH_UNMAPPED ||
                err == UC_ERR_INSN_INVALID) {
                
                printf("\n[!] КРАШ ЭМУЛЯТОРА!\n");
                printf("    Причина: %s\n", uc_strerror(err));
                abort(); 
            } else {
                printf("[-] Ошибка без abort: %s\n", uc_strerror(err));
            }

            uint64_t pc, x0, x1, x2, lr;
            uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
            uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
            uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
            uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

            printf("    Адрес (PC): 0x%lx\n", pc);
            printf("    (X0): 0x%lx\n", x0);
            printf("    (X1): 0x%lx\n", x1);
            printf("    (X2): 0x%lx (в десятичном: %lu)\n", x2, x2);
            printf("    (LR): 0x%lx\n", lr);
        } else {
#ifndef __AFL_COMPILER
    printf("\n[+] Эмуляция завершилась успешно (достигнут MAGIC_EXIT: 0x%lx)\n", (uint64_t)MAGIC_EXIT);
#endif
   }

#ifndef __AFL_COMPILER
    print_pc_history();
#endif

#ifdef __AFL_COMPILER
    // Если это ручной прогон через bash/afl-showmap — выходим после 1 теста
    if (!is_fuzzing) {
        break;
    }
}
#endif

    return 0;
}