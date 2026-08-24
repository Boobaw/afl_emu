#!/usr/bin/env python3
import struct
import subprocess
import os

DEFAULT_INJECT_DIR = os.path.expanduser("~/asn1/inject_seeds")
OUT_FILE = "seed_rsa.bin"

# 1. Генерируем настоящий валидный RSA-2048 ключ в формате PKCS#8 DER
try:
    cmd = ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-outform", "DER"]
    rsa_der_blob = subprocess.check_output(cmd)
except Exception as e:
    print(f"[-] Ошибка генерации ключа через OpenSSL: {e}")
    exit(1)

# 2. Список из 5 обязательных тегов Keymaster (tag_id: uint32, value: uint64)
tags = [
    (0x10000002, 1),      # KM_TAG_ALGORITHM: RSA (1)
    (0x80000003, 2048),   # KM_TAG_KEY_SIZE:  2048 бит
    (0x20000006, 0x0C),   # KM_TAG_PURPOSE:   SIGN (4) | VERIFY (8)
    (0x2000000A, 4),      # KM_TAG_DIGEST:    SHA-256 (4)
    (0x2000000B, 4),      # KM_TAG_PADDING:   RSA_PKCS1_1_5 (4)
]

# Упаковываем теги (каждый тег = 12 байт: 4 байта ID + 8 байт значение)
tag_list_bytes = bytearray()
for tag_id, val in tags:
    tag_list_bytes += struct.pack("<IQ", tag_id, val)

# 3. Вычисляем смещения и размеры
cmd_id = 0x0000010B                            # KM_CMD_IMPORT_KEY
key_format = 1                                 # FORMAT_PKCS8
tag_offset = 24                                # Заголовок занимает ровно 24 байта (0x18)
tag_count = len(tags)                          # 5 тегов
key_offset = tag_offset + len(tag_list_bytes)  # 24 + 60 = 84 байта (0x54)
key_length = len(rsa_der_blob)

# 4. Собираем 24-байтный заголовок (+0x00 .. +0x17)
header = struct.pack(
    "<IIIIII",
    cmd_id,
    key_format,
    tag_offset,
    tag_count,
    key_offset,
    key_length
)

# 5. Склеиваем пакет: Header (24б) + Tags (60б) + Real DER Key
packet = header + bytes(tag_list_bytes) + rsa_der_blob

os.makedirs(DEFAULT_INJECT_DIR, exist_ok=True)
out_path = os.path.join(DEFAULT_INJECT_DIR, OUT_FILE)

with open(out_path, "wb") as f:
    f.write(packet)

print(f"[+] Валидный сид успешно создан: {OUT_FILE}")
print(f"    Полный размер: {len(packet)} байт (DER ключ: {key_length} байт)")