#ifndef x25519_ref10_H
#define x25519_ref10_H

#include "ed25519_ref10.h"

static int
crypto_scalarmult_curve25519_ref10(unsigned char *q,
                                   const unsigned char *n,
                                   const unsigned char *p);

static void
edwards_to_montgomery(fe25519 montgomeryX, const fe25519 edwardsY, const fe25519 edwardsZ);

static int
crypto_scalarmult_curve25519_ref10_base(unsigned char *q,
                                        const unsigned char *n);
#endif
