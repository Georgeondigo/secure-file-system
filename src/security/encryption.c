#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../../include/security/encryption.h"
#include <openssl/aes.h>


#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 32 // 256 bit
#define AES_IV_SIZE 16 // 128 bit

void derive_key_from_password(const char *password, const unsigned char *salt, unsigned char *key_out, unsigned char *iv_out) {
    unsigned char key[AES_KEY_SIZE + AES_IV_SIZE];

    PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        salt, SALT_LENGTH,
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        sizeof(key),
        key
    );

    memcpy(key_out, key, AES_KEY_SIZE);
    memcpy(iv_out, key + AES_KEY_SIZE, AES_IV_SIZE);
}


int encrypt_file(const char *input_path, const char *output_path, const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");
    if (!in || !out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -2;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int len, out_len;

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, len);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 1;
}

int decrypt_file(const char *input_path, const char *output_path, const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");
    if (!in || !out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -2;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int len, out_len;

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, len);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 1;
}
