#include "mypke.h"
#include "poly.h"
#include "randombytes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "mytest/cpucycles.h"
#include "mytest/speed.h"

#define NTESTS 10
#define SCHEME_NAME "kyber1024"

#define MYCRYPTO_SK_LENGTH KYBER_INDCPA_SECRETKEYBYTES
#define MYCRYPTO_PK_LENGTH KYBER_INDCPA_PUBLICKEYBYTES
#define MYCRYPTO_MSG_LENGTH KYBER_SYMBYTES
#define MYCRYPTO_CIPHER_MSG_LENGTH KYBER_CIPHERTEXTBYTES

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

unsigned long long timing_overhead;

int mycryptotest_easy_pke()
{
    unsigned char m[MYCRYPTO_MSG_LENGTH] = {0};
    unsigned char m_[MYCRYPTO_MSG_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    unsigned char ct[MYCRYPTO_CIPHER_MSG_LENGTH] = {0};
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned int i = 0;
    bool status = true;

    printf("\n\nTESTING EASY KYBER PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    snprintf((char*)m, MYCRYPTO_MSG_LENGTH, "123321");
    for (i = 0; i < NTESTS; i++) {
        mypke_keypair(pk, sk);
        mypke_enc(ct, m, pk);
        mypke_dec(m_, ct, sk);

        if (memcmp(m, m_, MYCRYPTO_MSG_LENGTH)) {
            printf("ERROR keys\n");
            status = false;
            break;
        }
    }

    if (status != true) {
        printf("  PKE tests ... FAILED\n");
        return status;
    }

    printf("  PKE tests .................................................... PASSED\n");
    return status;
}

int mycryptotest_pke()
{
    unsigned int i = 0;
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    bool status = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / MYCRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * MYCRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * MYCRYPTO_CIPHER_MSG_LENGTH;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char)))) {
        printf("Cannot get the memory\n");
        return false;
    }

    printf("\n\nTESTING KYBER PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
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
            mypke_enc(myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, myMsg + encdecIdx * MYCRYPTO_MSG_LENGTH, pk);
        }
#ifdef JAYPAN_DEBUG
        printf("after encrypt %s\n", (char*)myMsg);
#endif
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            mypke_dec(myMsg_ + encdecIdx * MYCRYPTO_MSG_LENGTH, myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, sk);
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

    if (status != true) {
        printf("  PKE tests ... FAILED\n");
        return status;
    }

    printf("  PKE tests .................................................... PASSED\n");
    return status;
}

int mycryptorun_pke()
{
    unsigned int i;
    unsigned char sk[MYCRYPTO_SK_LENGTH] = {0};
    unsigned char pk[MYCRYPTO_PK_LENGTH] = {0};
    bool status = true;

    unsigned int encTimes = (strlen(TEST_JSON_PLAINTEXT) + 1) / MYCRYPTO_MSG_LENGTH + 1;
    unsigned int myMsgLen = encTimes * MYCRYPTO_MSG_LENGTH;
    unsigned int myCtLen = encTimes * MYCRYPTO_CIPHER_MSG_LENGTH;
    unsigned int encdecIdx = 0;

    unsigned char* myMsg = NULL;
    unsigned char* myMsg_ = NULL;
    unsigned char* myCt = NULL;

    unsigned long long tkeygen[TEST_LOOPS], tsign[TEST_LOOPS], tverify[TEST_LOOPS];
    timing_overhead = cpucycles_overhead();

    if (NULL == (myMsg = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myMsg_ = (unsigned char*)calloc(myMsgLen, sizeof(unsigned char))) ||
        NULL == (myCt = (unsigned char*)calloc(myCtLen, sizeof(unsigned char)))) {
        printf("Cannot get the memory\n");
        return false;
    }

    printf("\n\nTESTING ISOGENY-BASED PUBLIC KEY ENCRYPTION %s\n", SCHEME_NAME);
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    for (i = 0; i < TEST_LOOPS; i++)
    {
        memset(myMsg, 0, myMsgLen);
        memset(myMsg_, 0, myMsgLen);
        memset(myCt, 0, myCtLen);

        snprintf((char*)myMsg, myMsgLen, TEST_JSON_PLAINTEXT);

        printf("start genkey\n");
        tkeygen[i] = cpucycles_start();
        mypke_keypair(pk, sk);
        tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;

        printf("start encrypt\n");
        tsign[i] = cpucycles_start();
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            mypke_enc(myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, myMsg + encdecIdx * MYCRYPTO_MSG_LENGTH, pk);
        }
        tsign[i] = cpucycles_stop() - tsign[i] - timing_overhead;

        printf("start decrypt\n");
        tverify[i] = cpucycles_start();
        for (encdecIdx = 0; encdecIdx < encTimes; encdecIdx++) {
            mypke_dec(myMsg_ + encdecIdx * MYCRYPTO_MSG_LENGTH, myCt + encdecIdx * MYCRYPTO_CIPHER_MSG_LENGTH, sk);
        }
        tverify[i] = cpucycles_stop() - tverify[i] - timing_overhead;

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

    if (status != true) {
        printf("  PKE tests ... FAILED\n");
        return status;
    }

    printf("  PKE tests .................................................... PASSED\n");

    print_results("keygen:", tkeygen, TEST_LOOPS);
    print_results("sign: ", tsign, TEST_LOOPS);
    print_results("verify: ", tverify, TEST_LOOPS);
    printf("average length: %u\n", myCtLen);

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

    status = mycryptorun_pke();
    if (status != true) {
        printf("\n\n     Error detected: KEM_ERROR_PKE \n\n");
        return -1;
    }

    return 0;
}
