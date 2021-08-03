#include "cryptography.h"

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

void transform_text(char transformed_text[], char text[], int key, char (*transform_char_fptr)(char,int)){
    int text_length = strlen(text);    
    int i=0;
	for(i=0;i<text_length;i++){
		short int char_code = (int)text[i];
		if(char_code >= 65 && (char_code <= 90 || (char_code >= 97 && char_code <= 123))){
        	transformed_text[i] = transform_char_fptr(text[i], key);
		}else{
			transformed_text[i] = text[i];
		}
	}
    transformed_text[i] = '\0';
}

//Runs the cryptographic algorithm by applying given encryption and decryption functions on the input plain text which is scanned from the console
void run_cryptographic_algo(char* technique_name, void (*encryption_fptr)(char*, char*), void (*decryption_fptr)(char*, char*)){
	char plain_text[TEXT_MAX_LEN];
	
	printf("***** %s ******\n", technique_name);
	
    printf("Enter plain text: ");
    scanf("%[^\n]s", plain_text);
    char* encrypted_text = (char*)malloc(sizeof(char)*strlen(plain_text));
    encryption_fptr(encrypted_text, plain_text);
    
    char* decrypted_text = (char*)malloc(sizeof(char)*strlen(plain_text));
    decryption_fptr(decrypted_text, encrypted_text);
    
    printf("Plain Text: %s\nEncrypted Text: %s\nDecrypted Text: %s", plain_text, encrypted_text, decrypted_text);
    
    free(encrypted_text);
    free(decrypted_text);	
}

//Runs cryptographic algorithm for given algo code(defined in header file)
void run_cryptographic_algo_for(int algo_code){
	printf("%d", algo_code);
	switch(algo_code){
		case CAESER:
			run_cryptographic_algo("Caser Cipher", &caeser_cipher_encrypt_text, &caeser_cipher_decrypt_text);
			break;
		case MONOALPHABETIC:
			init_monoalphabetic_cipher();
			run_cryptographic_algo("Monoalphabetic Cipher", &monoalphabetic_cipher_encrypt_text, &monoalphabetic_cipher_decrypt_text);
			break;
	}
}


char encrypt_char_by_shift(char c, int p){
	int shift_value = CHAR_SHIFT_VALUE(c);
	return (char)((((int)c - shift_value + p) % 26) + shift_value);
}

char decrypt_char_by_shift(char c, int p){
    int shift_value = CHAR_SHIFT_VALUE(c);
	int char_code = (int)c - p;
	return (char)( (char_code < shift_value)? 26 + char_code : char_code);
}


void caeser_cipher_encrypt_text(char* encrypted_text, char* plain_text){
    transform_text(encrypted_text, plain_text, 3, &encrypt_char_by_shift);
}

void caeser_cipher_decrypt_text(char* decrypted_text, char* encrypted_text){
    transform_text(decrypted_text, encrypted_text, 3, &decrypt_char_by_shift);
}


const char* UPPER_ALPHA_ENCRYPT_MAP = "LIJYGRDWAQSEFTHUKOPMZNXCBV";
const char* LOWER_ALPHA_ENCRYPT_MAP = "qsefthukolijygrdwpzmxncbva";
char UPPER_ALPHA_DECRYPT_MAP[27], LOWER_ALPHA_DECRYPT_MAP[27]; 

void init_monoalphabetic_cipher(){
	int i;

	for(i=0;i<26;i++){
		UPPER_ALPHA_DECRYPT_MAP[UPPER_ALPHA_ENCRYPT_MAP[i] - 65] = (char) (i + 65);
		LOWER_ALPHA_DECRYPT_MAP[LOWER_ALPHA_ENCRYPT_MAP[i] - 97] = (char) (i + 97); 
	}
	
	UPPER_ALPHA_DECRYPT_MAP[i] = '\0';
	LOWER_ALPHA_DECRYPT_MAP[i] = '\0';
}

char monoalphabetic_cipher_encrypt_char(char c, int k){
	return (c >='a')? LOWER_ALPHA_ENCRYPT_MAP[(int)c - 97] : UPPER_ALPHA_ENCRYPT_MAP[(int)c - 65]; 
}

char monoalphabetic_cipher_decrypt_char(char c, int k){
	return (c >='a')? LOWER_ALPHA_DECRYPT_MAP[(int)c - 97] : UPPER_ALPHA_DECRYPT_MAP[(int)c - 65];
}

void monoalphabetic_cipher_encrypt_text(char* encrypted_text, char* plain_text){
	transform_text(encrypted_text, plain_text, 0, &monoalphabetic_cipher_encrypt_char);
}

void monoalphabetic_cipher_decrypt_text(char* decrytped_text, char* encrypted_text){
	transform_text(decrytped_text, encrypted_text, 0, &monoalphabetic_cipher_decrypt_char);
}
