#include "cryptography.h"

int main(){
    init_rail_fence_cipher(4);
    run_cryptographic_algo_for(RAIL_FENCE);
    clean_rail_fence_cipher();
    return 0;
}