#define TBENCH_DH_X25519 tbench_dh_mt
#define TBENCH_DH_CURVE25519 tbench_dh_mt_xy
#define TBENCH_DH_ED25519 tbench_dh_ed
#define TBENCH_DH_ED25519_TO_X25519 tbench_dh_ed_to_mt
#define TBENCH_DH_ED25519_TO_CURVE25519 tbench_dh_ed_to_mt_xy
#define TBENCH_DH_X25519_TO_ED25519 tbench_dh_mt_to_ed
#define TBENCH_DH_WEI25519_1_TO_ED25519 tbench_dh_wei_to_ed
#define TBENCH_DH_WEI25519_1_TO_X25519 tbench_dh_wei_to_mt
#define TBENCH_DH_WEI25519_1_TO_CURVE25519 tbench_dh_wei_to_mt_xy
#define TBENCH_EDDSA_ED25519_SIGN tbench_eddsa_sign
#define TBENCH_EDDSA_ED25519_VERIFY tbench_eddsa_verify
#define TBENCH_ECDSA_ED25519_SIGN tbench_ecdsa_sign
#define TBENCH_ECDSA_ED25519_VERIFY tbench_ecdsa_verify


int tbench_dh_mt(TBENCH_ARGS);
int tbench_dh_mt_xy(TBENCH_ARGS);
int tbench_dh_mt_to_ed(TBENCH_ARGS);

int tbench_dh_ed(TBENCH_ARGS);
int tbench_dh_ed_to_mt(TBENCH_ARGS);
int tbench_dh_ed_to_mt_xy(TBENCH_ARGS);

int tbench_dh_wei_to_mt(TBENCH_ARGS);
int tbench_dh_wei_to_mt_xy(TBENCH_ARGS);
int tbench_dh_wei_to_ed(TBENCH_ARGS);

int tbench_eddsa_sign(TBENCH_ARGS);
int tbench_eddsa_verify(TBENCH_ARGS);
int tbench_ecdsa_sign(TBENCH_ARGS);
int tbench_ecdsa_verify(TBENCH_ARGS);