#include <stdio.h>
#include <openssl/rand.h>
#include "../include/user/auth.h"
#include "../include/user/session.h"
#include "../include/security/encryption.h"
#include "../include/file/file_operations.h"

int main() {
    char username[50], password[50];
    int choice;

    printf("1. Register\n2. Login\n3. Check Session\n4. Logout\nChoose an option: ");
    scanf("%d", &choice);

    if (choice == 1) {
        printf("Enter Username: ");
        scanf("%s", username);
        printf("Enter Password: ");
        scanf("%s", password);
        register_user(username, password);
    } 
    else if (choice == 2) {
        printf("Enter Username: ");
        scanf("%s", username);
        printf("Enter Password: ");
        scanf("%s", password);

        if (authenticate_user(username, password)) {
            create_session(username);

            // Generate encryption key + IV
            unsigned char key[32], iv[16];
            RAND_bytes(key, sizeof(key));
            RAND_bytes(iv, sizeof(iv));

            int logged_in = 1;
         while(logged_in){
            // File menu
            int file_choice;
            char filepath[100];

            printf("\n-- File Menu --\n");
            printf("\n1. Upload a file\n2. Download a file\n3. Logout\nChoose file option: ");
            scanf("%d", &file_choice);

            if(file_choice == 1){
                printf("Enter filename to upload: ");
                scanf("%s", filepath);
                upload_file(filepath, username, key, iv);
            } else if (file_choice == 2){
                printf("Enter file name to download: ");
                scanf("%s", filepath);
                download_file(filepath, username, key, iv);
            } else if(file_choice == 3){
                destroy_session();
                logged_in = 0;
            } else {
                printf("Invalid file option.\n");
            }
         }}
    } 
    else if (choice == 3) {
        validate_session();
    } 
    else if (choice == 4) {
        destroy_session();
    } 
    else {
        printf("Invalid choice\n");
    }

    return 0;
}
