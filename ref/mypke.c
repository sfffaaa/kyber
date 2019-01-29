#include "randombytes.h"
#include "mypke.h"
#include "indcpa.h"
#include "params.h"
#include "fips202.h"

// pk: KYBER_INDCPA_PUBLICKEYBYTES
// sk: KYBER_INDCPA_SECRETKEYBYTES
void mypke_keypair(unsigned char *pk,
                   unsigned char *sk)
{
  indcpa_keypair(pk, sk);
}

// ct: KYBER_CIPHERTEXTBYTES
// m: KYBER_SYMBYTES
// pk: KYBER_INDCPA_SECRETKEYBYTES
void mypke_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk)
{
  unsigned char kr[KYBER_SYMBYTES];
  randombytes(kr, KYBER_SYMBYTES);
  indcpa_enc(c, m, pk, kr);                                 /* coins are in kr+KYBER_SYMBYTES */
}

// m: KYBER_SYMBYTES
// c: KYBER_CIPHERTEXTBYTES
// sk: KYBER_INDCPA_PUBLICKEYBYTES
void mypke_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk)
{
  indcpa_dec(m, c, sk);
}
