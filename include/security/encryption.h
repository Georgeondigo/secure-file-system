#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define SALT_LENGTH 16  // 🔐 128-bit salt
#define PBKDF2_ITERATIONS 100000

int encrypt_file(const char *input_path, const char *output_path, const unsigned char *key, const unsigned char *iv);
int decrypt_file(const char *input_path, const char *output_path, const unsigned char *key, const unsigned char *iv);
void derive_key_from_password(const char *password, const unsigned char *salt, unsigned char *key_out, unsigned char *iv_out);

#endif