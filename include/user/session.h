#ifndef SESSION_H
#define SESSION_H

#define SESSION_ID_LENGTH 32 // Length of session ID
#define SESSION_DB "session.db" // File to store active sessions
#define SESSION_FILE "session_token.txt" // Local file for storing session ID

// Fuction to generate a session ID
void generate_session_id(char *session_id);

//Fuction to create a ssesion for a user
int create_session(const char *username);

//Function to  automatically retrieve and validate the session
int validate_session();

// Function to destroy a session (logout)
void destroy_session();


#endif // SESSION_H