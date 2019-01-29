#ifndef MYPKE_H
#define MYPKE_H

void mypke_keypair(unsigned char *pk,
                   unsigned char *sk);

void mypke_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk);

void mypke_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

#endif
