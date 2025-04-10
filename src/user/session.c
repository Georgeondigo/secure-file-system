#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include "../../include/user/session.h"
#include "../../include/user/auth.h"

#define MAX_USERNAME_LEN 50
#define SESSION_ID_LENGTH 32
#define SESSION_DB "session.db"
#define SESSION_FILE "session_token.txt"
#define MAX_PASSWORD_LEN 50
#define SESSION_EXPIRATION 60  // 10 minutes

// Generate random session ID (hex)
void generate_session_id(char *session_id) {
    unsigned char raw_bytes[SESSION_ID_LENGTH];
    RAND_bytes(raw_bytes, SESSION_ID_LENGTH);

    for (int i = 0; i < SESSION_ID_LENGTH; i++) {
        sprintf(session_id + (i * 2), "%02x", raw_bytes[i]);
    }

    session_id[SESSION_ID_LENGTH * 2] = '\0';
}

// Create a session (store username, timestamp, session ID)
int create_session(const char *username) {
    FILE *file = fopen(SESSION_DB, "a");
    if (!file) {
        printf("Error opening session database.\n");
        return -1;
    }

    char session_id[SESSION_ID_LENGTH * 2 + 1];
    generate_session_id(session_id);

    // Store: username, timestamp, session ID
    fprintf(file, "%s %ld %s\n", username, time(NULL), session_id);
    fclose(file);

    // Save locally for automatic lookup
    FILE *session_file = fopen(SESSION_FILE, "w");
    if (!session_file) {
        printf("Error opening session file.\n");
        return -1;
    }

    fprintf(session_file, "%s", session_id);
    fclose(session_file);

    printf("Session created for %s.\n", username);
    return 1;
}

// Update timestamp on activity
void update_session_timestamp(const char *username) {
    FILE *file = fopen(SESSION_DB, "r");
    if (!file) return;

    char stored_username[MAX_USERNAME_LEN];
    char stored_session[SESSION_ID_LENGTH * 2 + 1];
    long timestamp;

    char buffer[4096] = {0};

    while (fscanf(file, "%s %ld %s", stored_username, &timestamp, stored_session) == 3) {
        if (strcmp(username, stored_username) == 0) {
            sprintf(buffer + strlen(buffer), "%s %ld %s\n", stored_username, time(NULL), stored_session);
        } else {
            sprintf(buffer + strlen(buffer), "%s %ld %s\n", stored_username, timestamp, stored_session);
        }
    }

    fclose(file);
    file = fopen(SESSION_DB, "w");
    fputs(buffer, file);
    fclose(file);
}

// Validate session with expiration and optional re-login
int validate_session() {
    FILE *session_file = fopen(SESSION_FILE, "r");
    if (!session_file) {
        printf("No active session found.\n");
        return 0;
    }

    char session_id[SESSION_ID_LENGTH * 2 + 1];
    if (fscanf(session_file, "%64s", session_id) != 1) {
        fclose(session_file);
        printf("Error reading session ID.\n");
        return 0;
    }
    fclose(session_file);

    FILE *file = fopen(SESSION_DB, "r");
    if (!file) {
        printf("Error opening session database.\n");
        return 0;
    }

    char stored_username[MAX_USERNAME_LEN];
    char stored_session[SESSION_ID_LENGTH * 2 + 1];
    long timestamp;
    time_t now = time(NULL);
    char valid_sessions[4096] = {0};
    int session_found = 0;

    while (fscanf(file, "%s %ld %s", stored_username, &timestamp, stored_session) == 3) {
        if (now - timestamp <= SESSION_EXPIRATION) {
            // Keep this session in DB
            sprintf(valid_sessions + strlen(valid_sessions), "%s %ld %s\n", stored_username, timestamp, stored_session);
        }

        if (strcmp(session_id, stored_session) == 0) {
            session_found = 1;

            if (now - timestamp > SESSION_EXPIRATION) {
                printf("Session expired. Re-enter your password: ");
                char password[MAX_PASSWORD_LEN];
                scanf("%s", password);

                if (authenticate_user(stored_username, password)) {
                    fclose(file);
                
                    // Remove expired session and recreate a new one
                    FILE *fw = fopen(SESSION_DB, "w");
                    fputs(valid_sessions, fw);
                    fclose(fw);
                
                    // Create a new session for the user
                    create_session(stored_username);
                
                    return 1;
                }else {
                    printf("Wrong password. Logging out.\n");
                    fclose(file);

                    // Save only valid sessions
                    FILE *fw = fopen(SESSION_DB, "w");
                    fputs(valid_sessions, fw);
                    fclose(fw);

                    return 0;
                }
            }

            printf("Session validated for user: %s\n", stored_username);
            update_session_timestamp(stored_username);
        }
    }

    fclose(file);

    // Save only unexpired sessions
    FILE *fw = fopen(SESSION_DB, "w");
    fputs(valid_sessions, fw);
    fclose(fw);

    if (session_found) return 1;

    printf("Invalid session.\n");
    return 0;
}


// Logout
void destroy_session() {
    remove(SESSION_FILE);
    printf("Session destroyed. Logged out.\n");
}
