#define TBENCH_CONV_W2M tbench_morph25519_w2m
#define TBENCH_CONV_W2E tbench_morph25519_w2e
#define TBENCH_CONV_M2W tbench_morph25519_m2w
#define TBENCH_CONV_M2E tbench_morph25519_m2e
#define TBENCH_CONV_E2W tbench_morph25519_e2w
#define TBENCH_CONV_E2M tbench_morph25519_e2m

#define TBENCH_CONV_WX2MX tbench_morph25519_wx2mx
#define TBENCH_CONV_MX2WX tbench_morph25519_mx2wx
#define TBENCH_CONV_MX2EY tbench_morph25519_mx2ey
#define TBENCH_CONV_EY2MX tbench_morph25519_ey2mx

#define TBENCH_RECOVER_EX tbench_morph25519_ey2ex
#define TBENCH_RECOVER_MY tbench_morph25519_recover_mt
#define TBENCH_RECOVER_WY tbench_morph25519_wx2wy

int tbench_morph25519_w2m(TBENCH_ARGS);
int tbench_morph25519_w2e(TBENCH_ARGS);
int tbench_morph25519_m2e(TBENCH_ARGS);
int tbench_morph25519_m2w(TBENCH_ARGS);
int tbench_morph25519_e2w(TBENCH_ARGS);
int tbench_morph25519_e2m(TBENCH_ARGS);

int tbench_morph25519_wx2mx(TBENCH_ARGS);
int tbench_morph25519_mx2wx(TBENCH_ARGS);
int tbench_morph25519_mx2ey(TBENCH_ARGS);
int tbench_morph25519_ey2mx(TBENCH_ARGS);

int tbench_morph25519_ey2ex(TBENCH_ARGS);
int tbench_morph25519_recover_mt(TBENCH_ARGS);
int tbench_morph25519_wx2wy(TBENCH_ARGS);
