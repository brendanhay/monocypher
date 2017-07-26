
#include "monocypher.h"

void inline_c_Monocypher_0_af5ae83ac0da53f5107a13445f8b925024bb9487(uint8_t * macPtr_inline_c_0, uint8_t * cipherPtr_inline_c_1, char * key_inline_c_2, char * nonce_inline_c_3, char * plain_inline_c_4, long plain_inline_c_5) {

                crypto_lock( macPtr_inline_c_0
                           , cipherPtr_inline_c_1
                           , key_inline_c_2
                           , nonce_inline_c_3
                           , plain_inline_c_4
                           , plain_inline_c_5
                           );
            
}


int inline_c_Monocypher_1_19a45ee1c458bcdad131b10c6da328f4647f87f1(uint8_t * plainPtr_inline_c_0, char * key_inline_c_1, char * nonce_inline_c_2, char * mac_inline_c_3, char * cipher_inline_c_4, long cipher_inline_c_5) {

                crypto_unlock( plainPtr_inline_c_0
                             , key_inline_c_1
                             , nonce_inline_c_2
                             , mac_inline_c_3
                             , cipher_inline_c_4
                             , cipher_inline_c_5
                             );
            
}

