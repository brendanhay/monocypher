
#include "monocypher.h"

void inline_c_Monocypher_0_ff9009c3f1a672eee5f5f152e2f1e91eca55ec5b(uint8_t * macPtr_inline_c_0, uint8_t * cipherPtr_inline_c_1, char * key_inline_c_2, char * nonce_inline_c_3, char * plain_inline_c_4, long plain_inline_c_5) {

                crypto_lock( macPtr_inline_c_0
                           , cipherPtr_inline_c_1
                           , key_inline_c_2
                           , nonce_inline_c_3
                           , plain_inline_c_4, plain_inline_c_5
                           );
            
}


int inline_c_Monocypher_1_b05d66436ec4db22c8131cdc4bea5bb61ee814ae(uint8_t * plainPtr_inline_c_0, char * key_inline_c_1, char * nonce_inline_c_2, char * mac_inline_c_3, char * cipher_inline_c_4, long cipher_inline_c_5) {

                crypto_unlock( plainPtr_inline_c_0
                             , key_inline_c_1
                             , nonce_inline_c_2
                             , mac_inline_c_3
                             , cipher_inline_c_4, cipher_inline_c_5
                             );
            
}


void inline_c_Monocypher_2_567dad2d56f10672664d6eb42943ec82d52bb83b(uint8_t * macPtr_inline_c_0, uint8_t * cipherPtr_inline_c_1, char * key_inline_c_2, char * nonce_inline_c_3, char * ad_inline_c_4, long ad_inline_c_5, char * plain_inline_c_6, long plain_inline_c_7) {

                crypto_aead_lock( macPtr_inline_c_0
                                , cipherPtr_inline_c_1
                                , key_inline_c_2
                                , nonce_inline_c_3
                                , ad_inline_c_4, ad_inline_c_5
                                , plain_inline_c_6, plain_inline_c_7
                                );
            
}


int inline_c_Monocypher_3_d6fc933044d21e75ee6801b2bd54a9aaf9e05505(uint8_t * plainPtr_inline_c_0, char * key_inline_c_1, char * nonce_inline_c_2, char * mac_inline_c_3, char * ad_inline_c_4, long ad_inline_c_5, char * cipher_inline_c_6, long cipher_inline_c_7) {

                crypto_unlock( plainPtr_inline_c_0
                             , key_inline_c_1
                             , nonce_inline_c_2
                             , mac_inline_c_3
                             , ad_inline_c_4, ad_inline_c_5
                             , cipher_inline_c_6, cipher_inline_c_7
                             );
            
}


int inline_c_Monocypher_4_6f26053580da996483e443d445a9b792a8527aa7(uint8_t * sharedPtr_inline_c_0, char * secret_inline_c_1, char * public_inline_c_2) {

                crypto_key_exchange( sharedPtr_inline_c_0
                                   , secret_inline_c_1
                                   , public_inline_c_2
                                   );
            
}


void inline_c_Monocypher_5_fc86e3476fb70b981858f00e08b9ed20050ea470(uint8_t * publicPtr_inline_c_0, char * secret_inline_c_1) {

                crypto_sign_public_key( publicPtr_inline_c_0
                                      , secret_inline_c_1
                                      );
            
}


void inline_c_Monocypher_6_8f820384fa91108f23a441a42b9a4a77543571ac(uint8_t * sigPtr_inline_c_0, char * secret_inline_c_1, char * publicPtr_inline_c_2, char * message_inline_c_3, long message_inline_c_4) {

                crypto_sign( sigPtr_inline_c_0
                           , secret_inline_c_1
                           , publicPtr_inline_c_2
                           , message_inline_c_3, message_inline_c_4
                           );
            
}


int inline_c_Monocypher_7_b95d990e3215d1b61fd89bd567d65e50a00538dd(char * signature_inline_c_0, char * public_inline_c_1, char * message_inline_c_2, long message_inline_c_3) {

        crypto_check( signature_inline_c_0
                    , public_inline_c_1
                    , message_inline_c_2, message_inline_c_3
                    );
    
}


void inline_c_Monocypher_8_c246fa72fb94c069c9620b53f8cd00bf6c38e04f(uint8_t * digestPtr_inline_c_0, char * input_inline_c_1, long input_inline_c_2) {

                crypto_blake2b( digestPtr_inline_c_0
                              , input_inline_c_1, input_inline_c_2
                              );
            
}


void inline_c_Monocypher_9_35ad6ad8d2e314dc9bdce0e64d0cc4fe5cb6b678(crypto_blake2b_ctx * blake2bPtr_inline_c_0) {

            crypto_blake2b_init(blake2bPtr_inline_c_0);
        
}


void inline_c_Monocypher_10_e1358b30bcade1bbd256c7ed81b901c03b79ed7a(uint8_t * hashPtr_inline_c_0, uint32_t * hashSizePtr_inline_c_1, void * areaPtr_inline_c_2, uint32_t blocks_inline_c_3, uint32_t iterations_inline_c_4, char * password_inline_c_5, long password_inline_c_6, char * salt_inline_c_7, long salt_inline_c_8, uint8_t * keyPtr_inline_c_9, uint32_t keyLen_inline_c_10, uint8_t * adPtr_inline_c_11, uint32_t adLen_inline_c_12) {

                crypto_argon2i( hashPtr_inline_c_0
                              , hashSizePtr_inline_c_1
                              , areaPtr_inline_c_2
                              , blocks_inline_c_3
                              , iterations_inline_c_4
                              , password_inline_c_5,    password_inline_c_6
                              , salt_inline_c_7,        salt_inline_c_8
                              , keyPtr_inline_c_9, keyLen_inline_c_10
                              , adPtr_inline_c_11,  adLen_inline_c_12
                              );
            
}


int inline_c_Monocypher_11_03ef1685db1aea81b65f3e55be59bbcc9a12e738(char * a_inline_c_0, char * b_inline_c_1, long a_inline_c_2) {

        crypto_memcmp(a_inline_c_0, b_inline_c_1, a_inline_c_2);
    
}


int inline_c_Monocypher_12_bc6b4117951593427b110647d34872fce8a3474c(char * a_inline_c_0, long a_inline_c_1) {

        crypto_zerocmp(a_inline_c_0, a_inline_c_1);
    
}

