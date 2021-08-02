#include "cryptography.h"

int main(){
	init_monoalphabetic_cipher();
	run_cryptography_algo("Monoalphabetic Cipher", &monoalphabetic_cipher_encrypt_text, &monoalphabetic_cipher_decrypt_text);
	return 1;
}
