#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include "../../include/user/session.h"
    
#define MAX_USERNAME_LEN 50
#define SESSION_ID_LENGTH 32 // Length of session ID
#define SESSION_DB "session.db" // File to store active sessions
#define SESSION_FILE "session_token.txt" // Local file for storing session ID


// Function to generate a random  session ID

void generate_session_id(char *session_id) {
    unsigned char raw_bytes[SESSION_ID_LENGTH];  // Temporary buffer for random bytes
    RAND_bytes(raw_bytes, SESSION_ID_LENGTH);   // Generate random bytes

    for (int i = 0; i < SESSION_ID_LENGTH; i++) {
        sprintf(session_id + (i * 2), "%02x", raw_bytes[i]);  // Convert to hex
    }

    session_id[SESSION_ID_LENGTH * 2] = '\0';  // Correctly null terminate
}


// Function to create a session and store it in session_token.txt
int create_session(const char *username){
    FILE *file = fopen(SESSION_DB, "a");
    if (!file){
        printf("error opening session database.\n");
        return -1;
    }

    char session_id[SESSION_ID_LENGTH * 2 +1];
    generate_session_id(session_id);

    fprintf(file, "%s %s\n", username, session_id);
    fclose(file);

    // save session ID locally
    FILE *session_file = fopen(SESSION_FILE, "w");
    if(!session_file){
        printf("error opening session file.\n");
        return -1;
    }
    fprintf(session_file, "%s", session_id);
    fclose(session_file);

    printf("session created for %s.\n", username);
    return 1;
}

// Function to validate the session ( automatically reads from the session_token.txt)
int validate_session() {
    // Open local session file (session_token.txt)
    FILE *session_file = fopen(SESSION_FILE, "r");
    if (!session_file) {
        printf("No active session found.\n");
        return 0;
    }

    // Read session ID from session_token.txt
    char session_id[SESSION_ID_LENGTH * 2 + 1];  // Make sure buffer is large enough
    if (fscanf(session_file, "%64s", session_id) != 1) {  // Ensure one value is read
        fclose(session_file);
        printf("Error reading session ID.\n");
        return 0;
    }
    fclose(session_file);

    // Open the session database (sessions.db) to verify session existence
    FILE *file = fopen(SESSION_DB, "r");
    if (!file) {
        printf("Error opening session database.\n");
        return 0;
    }

    // Read stored username and session from sessions.db
    char stored_username[MAX_USERNAME_LEN];
    char stored_session[SESSION_ID_LENGTH * 2 + 1];  // Ensure correct buffer size

    while (fscanf(file, "%50s %64s", stored_username, stored_session) == 2) {  // Ensure correct data is read
        if (strcmp(session_id, stored_session) == 0) {
            fclose(file);
            printf("Session validated for user: %s\n", stored_username);
            return 1;
        }
    }

    fclose(file);
    printf("Invalid session.\n");
    return 0;
}


// function to destroy the session (logout)
void destroy_session(){
    remove(SESSION_FILE); // Delete local session file
    printf("Session Destroyed. Logged out.\n");
}