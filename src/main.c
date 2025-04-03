#include <stdio.h>
#include "../include/user/auth.h"
#include "../include/user/session.h"

int main() {
    char username[50], password[50];
    int choice;

    printf("1. Register \n2. Login\n3. Check Session\n4. Logout\nChoose an option: ");
    scanf("%d", &choice);

    if (choice == 1) {
         printf("Enter Username: ");
         scanf("%s", username);
         printf("Enter Password: ");
         scanf("%s", password);
        register_user(username, password);
    } else if (choice == 2) {
         printf("Enter Username: ");
         scanf("%s", username);
         printf("Enter Password: ");
         scanf("%s", password);
        if(authenticate_user(username, password)){
            create_session(username); // Automatically creates session
        }
    } else if (choice == 3) {
        validate_session(); // automatically checks session
    }else if (choice == 4) {
        destroy_session(); //Logs out and removes session
    }
    else {
        printf("Invalid choice\n");
    }

    return 0;
}
