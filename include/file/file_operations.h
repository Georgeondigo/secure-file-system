#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

int upload_file(const char *filepatch, const char *username, const unsigned char *key, const unsigned char *iv);
int download_file(const char *filepatch, const char *username, const unsigned char *key, const unsigned char *iv);

#endif