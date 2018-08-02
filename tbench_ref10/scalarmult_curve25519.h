#ifndef scalarmult_curve25519_H
#define scalarmult_curve25519_H
int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p);

int
crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
#endif