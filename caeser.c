#include "cryptography.h"

int main(){
    run_cryptography_algo("Caeser Cipher", &caeser_cipher_encrypt_text, &caeser_cipher_decrypt_text);
    return 1;
}

