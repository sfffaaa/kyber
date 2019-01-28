#include "randombytes.h"
#include "mypke.h"
#include "indcpa.h"
#include "params.h"
#include "fips202.h"

void mypke_keypair(unsigned char *pk,
                   unsigned char *sk)
{
	indcpa_keypair(pk, sk);
}

// m: 2*KYBER_SYMBYTES
void mypke_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk)
{
  unsigned char  kr[2*KYBER_SYMBYTES];                                        /* Will contain key, coins */
  unsigned char buf[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  sha3_256(buf,buf,KYBER_SYMBYTES);                                           /* Don't release system RNG output */

  sha3_256(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);                     /* Multitarget countermeasure for coins + contributory KEM */
  sha3_512(kr, buf, 2*KYBER_SYMBYTES);

  indcpa_enc(c, m, pk, kr+KYBER_SYMBYTES);                                 /* coins are in kr+KYBER_SYMBYTES */
}

void mypke_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk)
{
	indcpa_dec(m, c, sk);
}
