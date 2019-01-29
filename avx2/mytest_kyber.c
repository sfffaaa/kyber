#include "mypke.h"
#include "poly.h"
#include "randombytes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define NTESTS 10
#define CRYPTO_MSG_LENGTH KYBER_SYMBYTES
#define CRYPTO_CIPHER_MSG_LENGTH KYBER_CIPHERTEXTBYTES

#define TEST_LOOPS NTESTS

#define TEST_JSON_PLAINTEXT "{\n" \
"        body: {\n" \
"                \"from\": \"pub_key_generated_by_library_in_testing_1\",\n" \
"                \"to\": \"pub_key_generated_by_library_in_testing_2\",\n" \
"                \"amount\": 3,1415,\n" \
"                \"itemHash\": \"bdad5ccb7a52387f5693eaef54aeee6de73a6ada7acda6d93a665abbdf954094\"\n" \
"                \"seed\": \"2953135335240383704\"\n" \
"        },\n" \
"        \"fee\": 0,7182,\n" \
"        \"network_id\": 7,\n" \
"        \"protocol_version\": 0,\n" \
"        \"service_id\": 5,\n" \
"}"


int mycryptotest_easy_pke()
{
    unsigned char m[KYBER_SYMBYTES] = {0};
    unsigned char m_[KYBER_SYMBYTES] = {0};
    unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES] = {0};
    unsigned char ct[KYBER_CIPHERTEXTBYTES] = {0};
    unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES] = {0};
    unsigned int i = 0;
    bool status = true;

    printf("\n\nTESTING EASY KYBER PUBLIC KEY ENCRYPTION\n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    snprintf((char*)m, KYBER_SYMBYTES, "123321");
    for (i = 0; i < NTESTS; i++) {
        mypke_keypair(pk, sk);
        mypke_enc(ct, m, pk);
        mypke_dec(m_, ct, sk);

        if (memcmp(m, m_, KYBER_SYMBYTES)) {
            printf("ERROR keys\n");
            status = false;
            break;
        }
    }

    if (status == true) {
        printf("  PKE tests .................................................... PASSED");
    } else {
        printf("  PKE tests ... FAILED");
    }
    printf("\n");

    return status;
}

int mycryptotest_pke()
{
    unsigned int i = 0;
    unsigned char sk[KYBER_INDCPA_SECRETKEYBYTES] = {0};
    unsigned char pk[KYBER_INDCPA_PUBLICKEYBYTES] = {0};
    bool status = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / CRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * CRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * CRYPTO_CIPHER_MSG_LENGTH;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char)))) {
        printf("Cannot get the memory\n");
        return -1;
    }

    printf("\n\nTESTING KYBER PUBLIC KEY ENCRYPTION\n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        memset(myMsg, 0, myMsgLen);
        memset(myMsg_, 0, myMsgLen);
        memset(myCt, 0, myCtLen);

        snprintf((char*)myMsg, myMsgLen, TEST_JSON_PLAINTEXT);

#ifdef JAYPAN_DEBUG
        printf("start test %d\n", i);
#endif
        mypke_keypair(pk, sk);
#ifdef JAYPAN_DEBUG
        printf("start encrypt\n");
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            mypke_enc(myCt + encdecIdx * CRYPTO_CIPHER_MSG_LENGTH, myMsg + encdecIdx * CRYPTO_MSG_LENGTH, pk);
        }
#ifdef JAYPAN_DEBUG
        printf("after encrypt %s\n", (char*)myMsg);
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            mypke_dec(myMsg_ + encdecIdx * CRYPTO_MSG_LENGTH, myCt + encdecIdx * CRYPTO_CIPHER_MSG_LENGTH, sk);
        }
#ifdef JAYPAN_DEBUG
        printf("after decrypt %s\n", (char*)myMsg_);
#endif

        if (memcmp(myMsg, myMsg_, myMsgLen) != 0) {
            status = false;
            break;
        }
    }

    if (myMsg) {
        free(myMsg);
    }
    if (myMsg_) {
        free(myMsg_);
    }
    if (myCt) {
        free(myCt);
    }

    if (status == true) {
        printf("  PKE tests .................................................... PASSED");
    } else {
        printf("  PKE tests ... FAILED");
    }
    printf("\n");

    return status;
}


int main(void)
{
    int status = -1;
    status = mycryptotest_easy_pke();
    if (status != true) {
        printf("\n\n     Error detected: KEM_ERROR_PKE \n\n");
        return -1;
    }

    status = mycryptotest_pke();
    if (status != true) {
        printf("\n\n     Error detected: KEM_ERROR_PKE \n\n");
        return -1;
    }

    return 0;
}
