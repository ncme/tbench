#ifndef crypto_scalarmult_nistp256_H
#define crypto_scalarmult_nistp256_H

#define crypto_scalarmult_nistp256_mj32_BYTES 64
#define crypto_scalarmult_nistp256_mj32_SCALARBYTES 32
extern int crypto_scalarmult_nistp256_mj32(unsigned char *,const unsigned char *,const unsigned char *);
extern int crypto_scalarmult_nistp256_mj32_base(unsigned char *,const unsigned char *);

#define crypto_scalarmult_nistp256 crypto_scalarmult_nistp256_mj32
#define crypto_scalarmult_nistp256_base crypto_scalarmult_nistp256_mj32_base
#define crypto_scalarmult_nistp256_BYTES crypto_scalarmult_nistp256_mj32_BYTES
#define crypto_scalarmult_nistp256_SCALARBYTES crypto_scalarmult_nistp256_mj32_SCALARBYTES
#define crypto_scalarmult_nistp256_IMPLEMENTATION "mj32"
#define crypto_scalarmult_nistp256_VERSION "-"

#endif