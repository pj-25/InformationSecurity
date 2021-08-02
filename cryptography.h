#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#define CHAR_SHIFT_VALUE(c) (c >= 'a') ? 97 : 65;

void transform_text(char* transformed_text, char* text, int key, char (*fptr)(char,int));
char encrypt_char_by_shift(char c, int k);
char decrypt_char_by_shift(char c, int k);

#define TEXT_MAX_LEN 256
void run_cryptography_algo(char* technique_name, void (*encryption_fptr)(char*, char*), void (*decryption_fptr)(char*, char*));


void caeser_cipher_encrypt_text(char* encrypted_text, char* plain_text);
void caeser_cipher_decrypt_text(char* decrypted_text, char* encrypted_text);


extern const char* UPPER_ALPHA_ENCRYPT_MAP;
extern const char* LOWER_ALPHA_ENCRYPT_MAP;
extern char UPPER_ALPHA_DECRYPT_MAP[27], LOWER_ALPHA_DECRYPT_MAP[27]; 

void init_monoalphabetic_cipher();
char monoalphabetic_cipher_encrypt_char(char c, int k);
char monoalphabetic_cipher_decrypt_char(char c, int k);
void monoalphabetic_cipher_encrypt_text(char* encrypted_text, char* plain_text);
void monoalphabetic_cipher_decrypt_text(char* decrypted_text, char* encrypted_text);

#endif
