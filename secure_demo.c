#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* FNV-1a 32-bit hash (simples, para integridade demonstrativa) */
uint32_t fnv1a_hash(const uint8_t *data, size_t len) {
    uint32_t hash = 0x811c9dc5; // offset basis
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 0x01000193; // FNV prime
    }
    return hash;
}

/* Criptografia XOR simples com chave repetida (apenas para demo) */
void xor_encrypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= key[i % key_len];
    }
}

/* Gera uma "chave" pseudoaleatória */
void generate_key(uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < key_len; ++i) {
        key[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* Print hex para debug */
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    if (len % 16) printf("\n");
}

int main(void) {
    srand((unsigned)time(NULL));

    const char *original = "Segredo: senha_super_secreta_123!";
    size_t data_len = strlen(original);

    /* Copiando para buffer mutável */
    uint8_t *buffer = malloc(data_len + 1);
    if (!buffer) {
        fprintf(stderr, "Erro ao alocar memória\n");
        return 1;
    }
    memcpy(buffer, original, data_len);
    buffer[data_len] = 0;

    /* 1) calcular hash antes da cifragem (integridade) */
    uint32_t hash_before = fnv1a_hash(buffer, data_len);

    /* 2) gerar chave e cifrar (simulação) */
    size_t key_len = 16;
    uint8_t key[16];
    generate_key(key, key_len);

    printf("Chave gerada (hex):\n");
    print_hex(key, key_len);

    printf("\nDados originais:\n%s\n", original);
    printf("Hash before: 0x%08X\n\n", hash_before);

    xor_encrypt(buffer, data_len, key, key_len); /* cifrar */
    printf("Dados cifrados (hex):\n");
    print_hex(buffer, data_len);

    /* 3) 'armazenar' hash (simulação) e depois verificar */
    uint32_t stored_hash = hash_before; /* em sistema real guardaria separadamente */

    /* --- Simulando recuperação e verificação --- */
    /* Decifrar */
    xor_encrypt(buffer, data_len, key, key_len); /* XOR de novo = original */
    printf("\nDados decifrados:\n%s\n", buffer);

    /* Recalcular hash e comparar */
    uint32_t hash_after = fnv1a_hash(buffer, data_len);
    printf("Hash after:  0x%08X\n", hash_after);
    printf("Hash stored: 0x%08X\n\n", stored_hash);

    if (hash_after == stored_hash) {
        printf("Verificação: OK — integridade confirmada.\n");
    } else {
        printf("Verificação: FALHA — dados alterados!\n");
    }

    free(buffer);
    return 0;
}