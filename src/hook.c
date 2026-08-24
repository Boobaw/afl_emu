#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include "../include/config.h"

// Раздельные дескрипторы хуков
static uc_hook hook_prng_getdata;
static uc_hook hook_time_getutcsec;
static uc_hook hook_blk;
static uc_hook hook_intr;
static uc_hook hook_log;
static uc_hook hook_malloc_h;
static uc_hook hook_mem_inv;
static uc_hook hook_singleton_wrapper;

static uint64_t prng_state = 0x123456789ABCDEF0ULL;

// Куча
uint64_t current_heap_offset = 0;

// ==========================================
// 1. БОЕВЫЕ ХУКИ (ТОЛЬКО ДЛЯ ФАЗЗЕРА)
// ==========================================
#ifdef __AFL_COMPILER

extern uint8_t *__afl_area_ptr;
extern __thread uint32_t __afl_prev_loc;

int coverage_enabled = 0; 

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
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

#define HISTORY_SIZE 10000
uint64_t pc_history[HISTORY_SIZE];
int pc_idx = 0;

static void hook_pc_history(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    pc_history[pc_idx] = address;
    pc_idx = (pc_idx + 1) % HISTORY_SIZE;
}

void print_pc_history(void) {
    printf("\n[~] Трассировка последних инструкций (PC History):\n");
    int first = 1;
    for (int i = 0; i < HISTORY_SIZE; i++) {
        int chronological_idx = (pc_idx + i) % HISTORY_SIZE;
        if (pc_history[chronological_idx] != 0) {
            if (!first) {
                printf(", ");
            }
            printf("0x%lx", pc_history[chronological_idx]);
            first = 0;
        }
    }
    printf("\n");
}
#endif // Конец блока отладки

void reset_heap(uc_engine *uc) {
    current_heap_offset = 0;
}

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
#ifndef __AFL_COMPILER
    uint64_t lr_val = 0;
    uint64_t pc_val = 0;
    
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr_val);
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc_val);

    const char* type_str = "UNKNOWN";
    switch(type) {
        case UC_MEM_READ_UNMAPPED:  type_str = "READ_UNMAPPED"; break;
        case UC_MEM_WRITE_UNMAPPED: type_str = "WRITE_UNMAPPED"; break;
        case UC_MEM_FETCH_UNMAPPED: type_str = "FETCH_UNMAPPED"; break;
        case UC_MEM_READ_PROT:      type_str = "READ_PROT_VIOLATION"; break;
        case UC_MEM_WRITE_PROT:     type_str = "WRITE_PROT_VIOLATION"; break;
        case UC_MEM_FETCH_PROT:     type_str = "FETCH_PROT_VIOLATION"; break;
        default: break;
    }

    printf("[-] CRASH! Type: %s at 0x%lx\n", type_str, address);
    printf("[-] PC: 0x%lx | LR: 0x%lx\n", pc_val, lr_val);
#endif

    return false;
}

static void qsee_svc_handler(uc_engine *uc, uint32_t intno, void *user_data) {
    uint64_t raw_cmd;
    uint64_t ret_val_zero = 0;
    uint64_t ret_val_err = 0xffffffffffffffff; // -1
    
    uc_reg_read(uc, UC_ARM64_REG_X0, &raw_cmd);
    int32_t command_id = (int32_t)(raw_cmd & 0xFFFFFFFF);

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
        uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val_err);
    }
}

void reset_prng(void) {
    prng_state = 0x123456789ABCDEF0ULL;
}

void hook_proxy_prng_getdata(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t buf_addr = 0;
    uint64_t req_len = 0;
    uint64_t lr = 0;

    uc_reg_read(uc, UC_ARM64_REG_X0, &buf_addr);
    uc_reg_read(uc, UC_ARM64_REG_X1, &req_len);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    if (buf_addr != 0 && req_len > 0) {
        uint8_t temp_buf[256];
        uint64_t bytes_to_generate = (req_len > sizeof(temp_buf)) ? sizeof(temp_buf) : req_len;

        // Быстрый детерминированный генератор (LCG)
        for (size_t i = 0; i < bytes_to_generate; i++) {
            prng_state = prng_state * 6364136223846793005ULL + 1ULL;
            temp_buf[i] = (uint8_t)(prng_state >> 32);
        }

        uc_mem_write(uc, buf_addr, temp_buf, bytes_to_generate);
    }

    // Возвращаем запрошенное количество байт
    uc_reg_write(uc, UC_ARM64_REG_X0, &req_len);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_open_singleton_wrapper(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t in_buf = 0, in_len = 0, out_buf = 0, out_len = 0, lr = 0;

    // Читаем аргументы функции:
    // X0 = param_1 (вход)
    // X1 = param_2 (длина входа)
    // X2 = param_3 (выходной буфер KDF)
    // X3 = param_4 (длина выходного ключа)
    uc_reg_read(uc, UC_ARM64_REG_X0, &in_buf);
    uc_reg_read(uc, UC_ARM64_REG_X1, &in_len);
    uc_reg_read(uc, UC_ARM64_REG_X2, &out_buf);
    uc_reg_read(uc, UC_ARM64_REG_X3, &out_len);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    // Заполняем выходной буфер фиксированным ключом KDF (32/64 байта)
    if (out_buf != 0 && out_len > 0) {
        uint8_t fake_kdf_key[64];
        memset(fake_kdf_key, 0x5A, sizeof(fake_kdf_key));
        
        uint64_t write_sz = (out_len > sizeof(fake_kdf_key)) ? sizeof(fake_kdf_key) : out_len;
        uc_mem_write(uc, out_buf, fake_kdf_key, write_sz);
    }

    // Возвращаем 0 (УСПЕХ)
    uint64_t ret_val = 0;
    uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val);

    // Возврат из функции
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void hook_proxy_time_getutcsec(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t time_buf_addr = 0;
    uint64_t lr = 0;

    // 1. Читаем аргумент X0 (указатель на local_30) и адрес возврата LR
    uc_reg_read(uc, UC_ARM64_REG_X0, &time_buf_addr);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);

    if (time_buf_addr != 0) {
        // 2. Записываем 4 байта валидного Unix Timestamp (секунды)
        uint32_t fake_timestamp = 1700000000;
        uc_mem_write(uc, time_buf_addr, &fake_timestamp, sizeof(fake_timestamp));
    }

    // 3. Возвращаем 0 (SUCCESS) в регистр X0
    uint64_t ret_val = 0;
    uc_reg_write(uc, UC_ARM64_REG_X0, &ret_val);

    // 4. Имитируем возврат из функции (RET)
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

static void hook_qsee_malloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t req_size, lr;
    uint64_t ret_val_zero = 0;
    
    uc_reg_read(uc, UC_ARM64_REG_X0, &req_size);
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
        uc_reg_write(uc, UC_ARM64_REG_X0, &alloc_addr);
    }

    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

void setup_hooks(uc_engine *uc) {
#ifdef __AFL_COMPILER
    uc_hook_add(uc, &hook_blk, UC_HOOK_BLOCK, hook_block, NULL, 0x0, 0x2FFFF);
#else
    static uc_hook trace_hook;
    uc_hook_add(uc, &trace_hook, UC_HOOK_CODE, hook_pc_history, NULL, 0x0, 0x2FFFF);
#endif

    uc_hook_add(uc, &hook_prng_getdata, UC_HOOK_CODE, hook_proxy_prng_getdata, NULL, 0x117a4, 0x117a4);
    uc_hook_add(uc, &hook_time_getutcsec, UC_HOOK_CODE, hook_proxy_time_getutcsec, NULL, 0x50, 0x50);
    uc_hook_add(uc, &hook_singleton_wrapper, UC_HOOK_CODE, hook_open_singleton_wrapper, NULL, 0x11854, 0x11854);
    uc_hook_add(uc, &hook_intr, UC_HOOK_INTR, qsee_svc_handler, NULL, 1, 0);
    uc_hook_add(uc, &hook_log, UC_HOOK_CODE, hook_log_printf, NULL, 0x0, 0x0);
    uc_hook_add(uc, &hook_malloc_h, UC_HOOK_CODE, hook_qsee_malloc, NULL, 0x440, 0x440);
    uc_hook_add(uc, &hook_mem_inv, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, 1, 0);
}