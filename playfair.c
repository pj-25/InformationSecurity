#include "cryptography.h"

int main(){
    init_playfair_cipher("keyword");
    run_cryptographic_algo_for(PLAYFAIR);
    clean_playfair_cipher();
    return 1;
}