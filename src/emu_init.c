#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unicorn/unicorn.h>
#include "../include/config.h"

// Константа размера страницы (4KB)
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(addr) ((addr) & ~(PAGE_SIZE - 1))

// Функция чтения файла (осталась без изменений)
static size_t read_file(const char *filename, uint8_t **buffer) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("[-] Ошибка открытия файла");
        return 0;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buffer = malloc(size);
    size_t read_size = fread(*buffer, 1, size, f);
    fclose(f);
    return read_size;
}

// Конвертация прав ELF (PF_R, PF_W, PF_X) в права Unicorn (UC_PROT_*)
static uint32_t get_uc_prot(uint32_t elf_flags) {
    uint32_t prot = UC_PROT_NONE;
    if (elf_flags & PF_R) prot |= UC_PROT_READ;
    if (elf_flags & PF_W) prot |= UC_PROT_WRITE;
    if (elf_flags & PF_X) prot |= UC_PROT_EXEC;
    return prot;
}

// Функция для вывода реальной карты памяти эмулятора
static void print_memory_map(uc_engine *uc) {
    uc_mem_region *regions;
    uint32_t count;
    uc_err err;

    // Запрашиваем у Unicorn все замапленные регионы
    err = uc_mem_regions(uc, &regions, &count);
    if (err != UC_ERR_OK) {
        printf("[-] Не удалось получить карту памяти: %s\n", uc_strerror(err));
        return;
    }

    printf("\n[=] Текущая карта памяти Unicorn (Memory Map):\n");
    printf("    Начало       Конец        Размер     Права\n");
    printf("    ------------------------------------------\n");
    
    for (uint32_t i = 0; i < count; i++) {
        uint64_t start = regions[i].begin;
        uint64_t end = regions[i].end;
        uint64_t size = end - start + 1;
        uint32_t perms = regions[i].perms;

        // Расшифровываем битовую маску прав доступа
        char r = (perms & UC_PROT_READ) ? 'r' : '-';
        char w = (perms & UC_PROT_WRITE) ? 'w' : '-';
        char x = (perms & UC_PROT_EXEC) ? 'x' : '-';

        printf("    0x%08lX - 0x%08lX (0x%06lX) %c%c%c\n", start, end, size, r, w, x);
    }
    printf("    ------------------------------------------\n\n");

    // Важно: API Unicorn само выделяет память под массив regions,
    // мы обязаны освободить её через uc_free (а не стандартный free).
    uc_free(regions); 
}

// Главная функция инициализации
uc_err init_emu(uc_engine **uc, const char *target_bin) {
    uc_err err;
    uint8_t *bin_buf = NULL;

    printf("[*] Инициализация Unicorn (ARM64)...\n");
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, uc);
    if (err) return err;

    printf("[*] Чтение ELF файла %s...\n", target_bin);
    size_t bin_size = read_file(target_bin, &bin_buf);
    if (bin_size == 0) return UC_ERR_READ_UNMAPPED;

    // 1. Проверяем магическую сигнатуру ELF
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)bin_buf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        printf("[-] Это не валидный ELF файл!\n");
        free(bin_buf);
        return UC_ERR_ARG;
    }

    // 2. Итерируемся по Program Headers
    Elf64_Phdr *phdr = (Elf64_Phdr *)(bin_buf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        // Нас интересуют только загружаемые сегменты (PT_LOAD)
        if (phdr[i].p_type == PT_LOAD) {
            uint64_t vaddr = phdr[i].p_vaddr;
            uint64_t memsz = phdr[i].p_memsz;
            uint64_t filesz = phdr[i].p_filesz;
            uint64_t offset = phdr[i].p_offset;
            uint32_t flags = phdr[i].p_flags;

            // Unicorn требует, чтобы адрес начала маппинга был кратен 4KB.
            // Если секция начинается с 0x100040, мы должны замапить с 0x100000.
            uint64_t map_addr = PAGE_ALIGN(vaddr);
            uint64_t map_offset = vaddr - map_addr;
            
            // Размер тоже должен быть кратен 4KB с учетом смещения
            uint64_t map_size = (memsz + map_offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            
            uint32_t uc_prot = get_uc_prot(flags);

            printf("[+] Маппинг PT_LOAD: addr=0x%lX, size=0x%lX, prot=%u\n", map_addr, map_size, uc_prot);
            
            // Мапим выровненный регион
            err = uc_mem_map(*uc, map_addr, map_size, uc_prot);
            if (err && err != UC_ERR_MAP) { // Игнорируем ошибку, если регион уже частично замаплен
                printf("[-] Ошибка маппинга: %s\n", uc_strerror(err));
                free(bin_buf);
                return err;
            }

            // Пишем данные из файла точно по их виртуальному адресу (vaddr)
            if (filesz > 0) {
                err = uc_mem_write(*uc, vaddr, bin_buf + offset, filesz);
                if (err) {
                    printf("[-] Ошибка записи сегмента: %s\n", uc_strerror(err));
                    free(bin_buf);
                    return err;
                }
            }
        }
    }

    free(bin_buf); // Сырой файл нам больше не нужен

    // 3. Выделяем память под стек и настраиваем регистр SP
    printf("[*] Маппинг стека: 0x%X (Размер: 0x%X)\n", STACK_ADDRESS, STACK_SIZE);
    err = uc_mem_map(*uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    if (err) return err;

    uint64_t sp_val = STACK_ADDRESS + STACK_SIZE;
    err = uc_reg_write(*uc, UC_ARM64_REG_SP, &sp_val);
    if (err) return err;

    // В entry_point лежит оригинальная точка входа из ELF файла
    printf("[+] ELF успешно загружен!");

    print_memory_map(*uc);

    return UC_ERR_OK;
}