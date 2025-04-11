#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../../include/file/file_operations.h"
#include "../../include/security/encryption.h"

int upload_file(const char *filepatch, const char *username, const unsigned char *key, const unsigned char *iv){
    char output_path[256];
    sprintf(output_path, "storage/%s_%s.enc", username, filepatch); // Example: storage/ondigo_report.txt.enc

    if(encrypt_file(filepatch, output_path, key, iv) == 1){
        printf( "File '%s' uploaded and encrypted sucessfully.\n", filepatch);
        return 1;
    } else{
        printf(" Failed to upload '%s'.\n", filepatch );
        return 0;
    }
}

int download_file(const char *filename , const char *username, const unsigned char *key, const unsigned char *iv){
    char input_path[256], output_path[256];
    sprintf(input_path, "storage/%s_%s.enc", username, filename);
    sprintf(output_path, "downloads/%s_%s", username, filename); //Example: downloads/ondigo_report.txt

    if(decrypt_file(input_path, output_path, key, iv) == 1){
        printf("File '%s' downloaded and decrypted sucessfully.\n", filename);
        return 1;
    } else {
        printf("Failed to download '%s'.\n", filename);
        return 0;
    }
}
