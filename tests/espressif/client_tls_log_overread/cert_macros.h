/* Names from the sample user_settings.h USE_CERT_BUFFERS_2048 block.
 * Defined here so the sample task can be compiled against a normal
 * wolfSSL build. These are the same arrays client-tls.c already includes
 * from wolfssl/certs_test.h. */
#define CTX_CA_CERT          ca_cert_der_2048
#define CTX_CA_CERT_SIZE     sizeof_ca_cert_der_2048
#define CTX_CA_CERT_TYPE     WOLFSSL_FILETYPE_ASN1
#define CTX_CLIENT_CERT      client_cert_der_2048
#define CTX_CLIENT_CERT_SIZE sizeof_client_cert_der_2048
#define CTX_CLIENT_CERT_TYPE WOLFSSL_FILETYPE_ASN1
#define CTX_CLIENT_KEY       client_key_der_2048
#define CTX_CLIENT_KEY_SIZE  sizeof_client_key_der_2048
#define CTX_CLIENT_KEY_TYPE  WOLFSSL_FILETYPE_ASN1
