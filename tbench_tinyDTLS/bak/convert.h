#include <inttypes.h>

void twisted_edwards_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);
void short_weierstrass_to_twisted_edwards(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);
void short_weierstrass_to_montgomery(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);
void montgomery_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry);