#include "cryptography.h"

int main(){
    char *key = "cryptography";
    init_polyalphabetic_cipher(key);
    run_cryptographic_algo_for(POLYALPHABETIC);
    return 1;
}