#include "mypke.h"
#include "poly.h"
#include "randombytes.h"
#include <stdio.h>
#include <string.h>

#define NTESTS 10000

int test_pke()
{
  unsigned char m[KYBER_SYMBYTES], m_[KYBER_SYMBYTES];
  unsigned char pk[KYBER_PUBLICKEYBYTES];
  unsigned char ct[KYBER_CIPHERTEXTBYTES];
  unsigned char sk[KYBER_SECRETKEYBYTES];
  int i;

  printf("show my the KYBER_CIPHERTEXTBYTES %d\n", KYBER_CIPHERTEXTBYTES);
  printf("show my the KYBER_SYMBYTES %d\n", KYBER_SYMBYTES);
  printf("show my the KYBER_PUBLICKEYBYTES %d\n", KYBER_PUBLICKEYBYTES);
  printf("show my the KYBER_SECRETKEYBYTES %d\n", KYBER_SECRETKEYBYTES);

  snprintf((char*)m, KYBER_SYMBYTES, "123321");
  for(i=0; i<NTESTS; i++)
  {
  	mypke_keypair(pk, sk);
	mypke_enc(ct, m, pk);
	mypke_dec(m_, ct, sk);

	if(memcmp(m, m_, KYBER_SYMBYTES)) {
	  printf("ERROR keys\n");
	  break;
	}
  }

  return 0;
}


int main(void)
{
  test_pke();

  printf("KYBER_SECRETKEYBYTES:  %d\n",KYBER_SECRETKEYBYTES);
  printf("KYBER_PUBLICKEYBYTES:  %d\n",KYBER_PUBLICKEYBYTES);
  printf("KYBER_CIPHERTEXTBYTES: %d\n",KYBER_CIPHERTEXTBYTES);

  return 0;
}
