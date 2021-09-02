#include"cryptography.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(){
    char msg[TEXT_MAX_LEN];
    printf("Enter your message: ");
    scanf("%s", msg);
    int len =  strlen(msg);
    char* encrypted_msg = (char*)malloc(sizeof(char)*(len+1));
    caeser_cipher_encrypt_text(encrypted_msg, msg);
    break_caeser_cipher(encrypted_msg);
    free(encrypted_msg);
    return 0;
}