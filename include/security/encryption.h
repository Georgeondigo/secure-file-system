#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#define AES_KEY_SIZE 32 // 256 bit
#define AES_IV_SIZE 16 // 128 bit

int encrypt_file(const char *input_path, const char *output_path, const unsigned char *key, const unsigned char *iv  );
int decrypt_file(const char *input_path, const char *output_path, const unsigned char *key, const unsigned char *iv  );

#endif