#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#define CAESER 0
#define MONOALPHABETIC 1
#define POLYALPHABETIC 2
#define PLAYFAIR 3
#define RAIL_FENCE 4    

#define CHAR_SHIFT_VALUE(c) (c >= 'a') ? 97 : 65
#define CHAR_CODE(c) c - (CHAR_SHIFT_VALUE(c))

void transform_text(char* transformed_text, char* text, int key, char (*fptr)(char,int));
char encrypt_char_by_shift(char c, int k);
char decrypt_char_by_shift(char c, int k);

#define TEXT_MAX_LEN 256
void run_cryptographic_algo(char* technique_name, void (*encryption_fptr)(char*, char*), void (*decryption_fptr)(char*, char*));
void run_cryptographic_algo_for(int algo_code);

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

void init_polyalphabetic_cipher(char*);
char polyalphabetic_cipher_encrypt_char(char c, int pos);
char polyalphabetic_cipher_decrypt_char(char c, int pos);
void polyalphabetic_cipher_encrypt_text(char* encrypted_text, char* plain_text);
void polyalphabetic_cipher_decrypt_text(char* decrypted_text, char* encrypted_text);

void init_playfair_cipher(char*);
void generate_playfair_matrix(char *keyword);
void playfair_cipher_encrypt_text(char* encrypted_text, char* plain_text);
void playfair_cipher_decrypt_text(char* decrypted_text, char* encrypted_text);
void clean_playfair_cipher();
int prepare_text(char*, char*);
void print_playfair_matrix();

void init_rail_fence_cipher(int d);
void rail_fence_encrypt_text(char* encrypted_text, char* plain_text);
void rail_fence_decrypt_text(char* decrypted_text, char* encrytped_text);
void clean_rail_fence_cipher();

#endif
