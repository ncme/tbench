
#ifndef scalarmult_ed25519_H
#define scalarmult_ed25519_H

static int
_crypto_scalarmult_ed25519_is_inf(const unsigned char s[32]);

static inline void
_crypto_scalarmult_ed25519_clamp(unsigned char k[32]);

int
crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                          const unsigned char *p);
int
crypto_scalarmult_ed25519_base(unsigned char *q,
                               const unsigned char *n);

size_t
crypto_scalarmult_ed25519_bytes(void);

size_t
crypto_scalarmult_ed25519_scalarbytes(void);
#endif