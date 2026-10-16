#include <openssl/rsa.h>
void demo(void) { RSA_generate_key_ex(NULL, 2048, NULL, NULL); }
