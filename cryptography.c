#include "cryptography.h"

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#define POS_KEY -1

void transform_text(char transformed_text[], char text[], int key, char (*transform_char_fptr)(char,int)){
    int text_length = strlen(text);    
    int i=0;
	for(i=0;i<text_length;i++){
		short int char_code = (int)text[i];
		if(char_code >= 65 && (char_code <= 90 || (char_code >= 97 && char_code <= 123))){
			int k = key;
			if(key == POS_KEY){
				k = i;
			}
        	transformed_text[i] = transform_char_fptr(text[i], k);
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
    char* encrypted_text = (char*)malloc(sizeof(char)*(strlen(plain_text)+1));
    encryption_fptr(encrypted_text, plain_text);
    
    char* decrypted_text = (char*)malloc(sizeof(char)*(strlen(plain_text)+1));
    decryption_fptr(decrypted_text, encrypted_text);
    printf("Plain Text: %s\nEncrypted Text: %s\n", plain_text, encrypted_text);
    printf("Decrypted Text: %s\n", decrypted_text);
	
    free(encrypted_text);
    free(decrypted_text);	
}

//Runs cryptographic algorithm for given algo code(defined in header file)
void run_cryptographic_algo_for(int algo_code){
	switch(algo_code){
		case CAESER:
			run_cryptographic_algo("Caser Cipher", &caeser_cipher_encrypt_text, &caeser_cipher_decrypt_text);
			break;
		case MONOALPHABETIC:
			init_monoalphabetic_cipher();
			run_cryptographic_algo("Monoalphabetic Cipher", &monoalphabetic_cipher_encrypt_text, &monoalphabetic_cipher_decrypt_text);
			break;
		case POLYALPHABETIC:
			run_cryptographic_algo("Polyalphabetic(Vigenere) Cipher", &polyalphabetic_cipher_encrypt_text, &polyalphabetic_cipher_decrypt_text);
			break;
		case PLAYFAIR:
			run_cryptographic_algo("Playfair Cipher", &playfair_cipher_encrypt_text, &playfair_cipher_decrypt_text);
			break;
		case RAIL_FENCE:
			run_cryptographic_algo("Rail Fence Cipher", &rail_fence_encrypt_text, &rail_fence_decrypt_text);
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


//# Caser Cipher 
void caeser_cipher_encrypt_text(char* encrypted_text, char* plain_text){
    transform_text(encrypted_text, plain_text, 3, &encrypt_char_by_shift);
}

void caeser_cipher_decrypt_text(char* decrypted_text, char* encrypted_text){
    transform_text(decrypted_text, encrypted_text, 3, &decrypt_char_by_shift);
}


//# Monoalphabetic Cipher

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


//# Polyalphabetic(Vigenere) Cipher
char* polyalphabetic_key;
int key_len;

void init_polyalphabetic_cipher(char* key){
	polyalphabetic_key = key;
	key_len = strlen(key);
}

char polyalphabetic_cipher_encrypt_char(char c, int i){
	int svalue = CHAR_SHIFT_VALUE(c);
	return (char)((((int)c - svalue + (int)polyalphabetic_key[i % key_len] - 97) % 26) + svalue);
}

char polyalphabetic_cipher_decrypt_char(char c, int i){
	int svalue = CHAR_SHIFT_VALUE(c);
	return (char)((((int)c - svalue - (int)polyalphabetic_key[i % key_len] + 123) % 26) + svalue);
}

void polyalphabetic_cipher_encrypt_text(char* encrypted_text,char* plain_text){
	transform_text(encrypted_text, plain_text, POS_KEY, &polyalphabetic_cipher_encrypt_char);
}

void polyalphabetic_cipher_decrypt_text(char* decrypted_text, char* encrypted_text){
	transform_text(decrypted_text, encrypted_text, POS_KEY, &polyalphabetic_cipher_decrypt_char);
}


//# Playfair Cipher
int** playfair_pos_map;
int** playfair_matrix;

void init_playfair_cipher(char* keyword){
	generate_playfair_matrix(keyword);
}

void generate_playfair_matrix(char *keyword){

	playfair_pos_map = (int**)malloc(sizeof(int*) * 26);
	playfair_matrix = (int**)malloc(sizeof(int*)*5);
	int i, j;
	for(i=0;i<26;i++){
		playfair_pos_map[i] = (int*)malloc(sizeof(int) * 2);
		playfair_pos_map[i][0] = playfair_pos_map[i][1] = -1;
	}

	int alpha_count = 0, keychar_count = 0;
	int klen = strlen(keyword);

	for(i=0;i<5;i++){
		playfair_matrix[i] = (int*)malloc(sizeof(int)*5);
		for(j=0;j<5;j++){
			int char_index = (keychar_count < klen)? keyword[keychar_count++] - 97 : alpha_count++;
			if( char_index == 9 || playfair_pos_map[char_index][0] != -1){
				j--;
				continue;
			}
			playfair_pos_map[char_index][0] = i;
			playfair_pos_map[char_index][1] = j;
			playfair_matrix[i][j] = char_index;
		}
	}	
	playfair_pos_map[9][0] = playfair_pos_map[8][0];
	playfair_pos_map[9][1] = playfair_pos_map[8][1];
}

void clean_playfair_cipher(){
	int i;
	for(i=0;i<5;i++){
		free(playfair_matrix[i]);
		free(playfair_pos_map[i]);
	}
	for(i=5;i<26;i++){
		free(playfair_pos_map[i]);
	}
	free(playfair_pos_map);
	free(playfair_matrix);
}

void print_playfair_matrix(){
	int i,j;
	for(i=0;i<5;i++){
		for(j=0;j<5;j++){
			printf("%d(%c)\t", playfair_matrix[i][j], playfair_matrix[i][j]+97);
		}
		printf("\n");
	}
	for(i=0;i<26;i++){
		printf("%c:%d(%d, %d)\n", i+97, i, playfair_pos_map[i][0], playfair_pos_map[i][1]);
	}
}

int prepare_text(char* prepared_text, char* text){
	int len = strlen(text);
	int i, plen = 0;
	for(i=0;i<len;i=i+2){
		if(i == len-1 || text[i] == text[i+1]){
			prepared_text[plen++] = text[i];
			prepared_text[plen++] = 'x';
			i--;
		}else{
			prepared_text[plen++] = text[i];
			prepared_text[plen++] = text[i+1];
		}
		//printf("%d(%c, %c)\n", i, prepared_text[plen-2], prepared_text[plen-1]);
	}
	prepared_text[plen] = '\0';
	return plen;
}

void playfair_cipher_encrypt_text(char* encrypted_text, char* plain_text){
	char* prepared_text;
	prepared_text = (char*)malloc(sizeof(char)*(strlen(plain_text)*2+1));
	int plen = prepare_text(prepared_text, plain_text), i;
	printf("Prepared Text = %s\n", prepared_text);
	for(i=0;i < plen - 1;i=i+2){
		int c1 = CHAR_CODE(prepared_text[i]);
		int c2 = CHAR_CODE(prepared_text[i+1]);
		if(playfair_pos_map[c1][0] == playfair_pos_map[c2][0]){
			encrypted_text[i] = (char)(playfair_matrix[playfair_pos_map[c1][0]][(playfair_pos_map[c1][1]+1)%5] + 97);
			encrypted_text[i+1] = (char)(playfair_matrix[playfair_pos_map[c2][0]][(playfair_pos_map[c2][1]+1)%5] + 97);
		}else if(playfair_pos_map[c1][1] == playfair_pos_map[c2][1]){
			encrypted_text[i] = (char)(playfair_matrix[(playfair_pos_map[c1][0]+1)%5][playfair_pos_map[c1][1]] + 97);
			encrypted_text[i+1] = (char)(playfair_matrix[(playfair_pos_map[c2][0]+1)%5][playfair_pos_map[c2][1]] + 97);
		}else{
			encrypted_text[i] = (char)(playfair_matrix[playfair_pos_map[c1][0]][playfair_pos_map[c2][1]] + 97);
			encrypted_text[i+1] = (char)(playfair_matrix[playfair_pos_map[c2][0]][playfair_pos_map[c1][1]] + 97);
		}
	}
	encrypted_text[i] = '\0';
	free(prepared_text);
}

void playfair_cipher_decrypt_text(char* decrypted_text, char* encrypted_text){
	int i, len = strlen(encrypted_text);
	for(i=0; i < len - 1; i=i+2){
		int c1 = CHAR_CODE(encrypted_text[i]);
		int c2 = CHAR_CODE(encrypted_text[i+1]);
		if(playfair_pos_map[c1][0] == playfair_pos_map[c2][0]){
			decrypted_text[i] = (char)(playfair_matrix[playfair_pos_map[c1][0]][(playfair_pos_map[c1][1]+4)%5] + 97);
			decrypted_text[i+1] = (char)(playfair_matrix[playfair_pos_map[c2][0]][(playfair_pos_map[c2][1]+4)%5] + 97);
		}else if(playfair_pos_map[c1][1] == playfair_pos_map[c2][1]){
			decrypted_text[i] = (char)(playfair_matrix[(playfair_pos_map[c1][0]+4)%5][playfair_pos_map[c1][1]] + 97);
			decrypted_text[i+1] = (char)(playfair_matrix[(playfair_pos_map[c2][0]+4)%5][playfair_pos_map[c2][1]] + 97);
		}else{
			decrypted_text[i] = (char)(playfair_matrix[playfair_pos_map[c1][0]][playfair_pos_map[c2][1]] + 97);
			decrypted_text[i+1] = (char)(playfair_matrix[playfair_pos_map[c2][0]][playfair_pos_map[c1][1]] + 97);
		}
	}
	decrypted_text[i] = '\0';
}


//Rail Fence
int** jumpValues;
int depth;

void printJumpValues(){
	int i;
	for(i=0;i<depth;i++){
		printf("%d, %d\n", jumpValues[i][0], jumpValues[i][1]);
	}
}

void init_rail_fence_cipher(int d){
	depth = d;
	jumpValues = (int**)malloc(sizeof(int*)*depth);
	int i;
	for(i=0;i<depth;i++){
		jumpValues[i] = (int*)malloc(sizeof(int)*2);
	}
	for(i=0;i<depth-1;i++){
		jumpValues[i][0] = jumpValues[depth-i-1][1] = 2*(d-1);
		d -= 1;
	}
	jumpValues[depth-1][0] = jumpValues[0][1] = jumpValues[0][0]; 
	//printJumpValues();
}

void rail_fence_encrypt_text(char* encrypted_text, char* plain_text){
	int i,j;
	int len = strlen(plain_text), enclen=0;
	for(i=0; i<depth; i++){
		int choice = 1;
		for(j=i; j < len; j += jumpValues[i][choice]){
			encrypted_text[enclen++] = plain_text[j];
			choice = (choice+1)%2;
		}
	}
	encrypted_text[enclen] = '\0';
}

void rail_fence_decrypt_text(char* decrypted_text, char* encrypted_text){
	int i,j;
	int len = strlen(encrypted_text), enclen=0;
	for(i=0;i<depth;i++){
		int choice = 1;
		for(j=i; j<len; j+=jumpValues[i][choice]){
			decrypted_text[j] = encrypted_text[enclen++];
			choice = (choice+1)%2;
		}
	}
	decrypted_text[len] = '\0';
}

void clean_rail_fence_cipher(){
	int i;
	for(i=0;i<depth;i++){
		free(jumpValues[i]);
	}
	free(jumpValues);
}