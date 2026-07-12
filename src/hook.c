#include <stdint.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include "../include/config.h"

uc_hook hook;

// Куча
static uint64_t current_heap_offset = 0;

// ==========================================
// 1. БОЕВЫЕ ХУКИ (ТОЛЬКО ДЛЯ ФАЗЗЕРА)
// ==========================================
#ifdef __AFL_COMPILER

extern uint8_t *__afl_area_ptr;
extern __thread uint32_t __afl_prev_loc;

// 1. ДОБАВЛЯЕМ ГЛОБАЛЬНЫЙ ФЛАГ ПРЕДОХРАНИТЕЛЯ
int coverage_enabled = 0; 

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    // 2. ЕСЛИ ФАЗЗИНГ ЕЩЕ НЕ НАЧАЛСЯ - НИЧЕГО НЕ ДЕЛАЕМ!
    if (!coverage_enabled || __afl_area_ptr == NULL) return; 
    
    uint32_t cur_loc = (uint32_t)(address & 0xFFFFFFFF);
    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= (65536 - 1);
    
    __afl_area_ptr[cur_loc ^ __afl_prev_loc]++;
    __afl_prev_loc = cur_loc >> 1;
}
#endif


// ==========================================
// 2. ОТЛАДОЧНЫЕ ХУКИ (ТОЛЬКО ДЛЯ РУЧНОГО ЗАПУСКА)
// ==========================================
#ifndef __AFL_COMPILER

#define HISTORY_SIZE 300
uint64_t pc_history[HISTORY_SIZE];
int pc_idx = 0;

static void hook_pc_history(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    pc_history[pc_idx] = address;
    pc_idx = (pc_idx + 1) % HISTORY_SIZE;
}

void print_pc_history() {
    printf("\n[~] Трассировка последних инструкций (PC History):\n");
    for (int i = 0; i < HISTORY_SIZE; i++) {
        int chronological_idx = (pc_idx + i) % HISTORY_SIZE;
        if (pc_history[chronological_idx] != 0) {
            printf("    -> 0x%lx\n", pc_history[chronological_idx]);
        }
    }
}

#endif // Конец блока отладки



static void hook_log_printf(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t lr_val = 0;
    uc_err err;

    err = uc_reg_read(uc, UC_ARM64_REG_LR, &lr_val);
    err = uc_reg_write(uc, UC_ARM64_REG_PC, &lr_val);
    if (err != UC_ERR_OK) {
        printf("[-] Ошибка hook_code: %s\n", uc_strerror(err));
        return;
    }
}

// Callback для невалидного доступа к памяти
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, 
                             uint64_t address, int size, int64_t value, void *user_data) {
    uint64_t lr_val = 0;
    uint64_t pc_val = 0;
    uc_err err;

    // В этой точке можно прочитать регистры (uc_reg_read) и вывести их в консоль,
    // чтобы понять, почему произошел краш.

    // Вызов abort() мгновенно убивает наш C-харнесс с сигналом SIGABRT.
    // Fork-сервер AFL++ перехватывает этот сигнал, понимает, что это Crash,
    // и сохраняет текущий мутированный payload в папку 'crashes'.

    err = uc_reg_read(uc, UC_ARM64_REG_LR, &lr_val);
    if (err != UC_ERR_OK) {
        printf("[-] Ошибка uc_reg_read LR: %s\n", uc_strerror(err));
    }
    else {
        printf("Содержимое LR: %lx\n", lr_val);
    }
    

    err = uc_reg_read(uc, UC_ARM64_REG_PC, &pc_val);
    if (err != UC_ERR_OK) {
        printf("[-] Ошибка uc_reg_read PC: %s\n", uc_strerror(err));
    }
    else {
        printf("Содержимое PC: %lx\n", pc_val);
    }
    

    printf("[-] Ошибка MEM_WRITE_UNMAPPED: %lx\n", address);

    abort(); 
    
    return false; // Возврат false останавливает эмуляцию (до abort код уже не дойдет)
}

static void qsee_svc_handler(uc_engine *uc, uint32_t intno, void *user_data) {
    uint64_t raw_cmd;
    uint64_t ret_val_zero = 0;
    uint64_t ret_val_err = 0xffffffffffffffff; // -1
    
    // Читаем регистр X0
    uc_reg_read(uc, UC_ARM64_REG_X0, &raw_cmd);
    
    // Элегантный перевод в отрицательное число (если старший бит установлен)
    int32_t command_id = (int32_t)(raw_cmd & 0xFFFFFFFF);

    // ==========================================
    // 2. МАРШРУТИЗАЦИЯ
    // ==========================================
    if (command_id == -256) { // qsee_env_init
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val_zero);
    }
    
    else if (command_id == -95) {
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val_zero);
    }
    
    else if (command_id == -244) {
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val_zero);
    }
    
    else {
        // Неизвестная команда
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val_err);
    }
}

static void hook_qsee_malloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t req_size, lr;
    uint64_t ret_val_zero = 0;
    
    // 2. ЧИТАЕМ РАЗМЕР ИЗ X0! (Это стандартная C-функция)
    uc_reg_read(uc, UC_ARM64_REG_X0, &req_size);
    
    // Читаем адрес возврата, чтобы знать, куда выпрыгнуть
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    
    if (req_size == 0) {
        req_size = 4096;
    }
    
    uint64_t aligned_size = (req_size + 4095) & ~4095;
    
    if (current_heap_offset + aligned_size > HEAP_SIZE) {
#ifndef __AFL_COMPILER
        printf("     [!] FATAL: OOM в sys_malloc! (Запрошено: 0x%lx)\n", req_size);
#endif
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val_zero);
    } else {
        uint64_t alloc_addr = HEAP_START + current_heap_offset;
        current_heap_offset += aligned_size;
        
        // Отдаем адрес прошивке
        uc_reg_write(uc, UC_ARM64_REG_X0, &alloc_addr);
    }

    // 3. САМОЕ ГЛАВНОЕ: ПРЫЖОК ОБРАТНО
    // Мы заставляем процессор вернуться туда, откуда вызвали malloc.
    // Оригинальный код по адресу 0x440 никогда не будет выполнен!
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}


void setup_hooks(uc_engine *uc) {

#ifdef __AFL_COMPILER
    uc_hook_add(uc, &hook, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
#endif

#ifndef __AFL_COMPILER
    uc_hook trace_hook;
    uc_hook_add(uc, &trace_hook, UC_HOOK_CODE, hook_pc_history, NULL, 1, 0);
#endif

    uc_hook_add(uc, &hook, UC_HOOK_INTR, qsee_svc_handler, NULL, 1, 0);
    uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_log_printf, NULL, 0x0, 0x0);
    uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_qsee_malloc, NULL, 0x440, 0x440);
    uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

}