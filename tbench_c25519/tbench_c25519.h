
#define TBENCH_DH_X25519 tbench_dh_mt
#define TBENCH_DH_ED25519 tbench_dh_ed
#define TBENCH_DH_ED25519_TO_X25519 tbench_dh_ed_to_mt
#define TBENCH_DH_X25519_TO_ED25519 tbench_dh_mt_to_ed
#define TBENCH_DH_WEI25519_1_TO_ED25519 tbench_dh_wei_to_ed
#define TBENCH_DH_WEI25519_1_TO_X25519 tbench_dh_wei_to_mt
#define TBENCH_EDDSA_ED25519_SIGN tbench_eddsa_sign
#define TBENCH_EDDSA_ED25519_VERIFY tbench_eddsa_verify


int tbench_dh_mt(long* acycles, int i);
int tbench_dh_ed(long* acycles, int i);
int tbench_dh_ed_to_mt(long* acycles, int i);
int tbench_dh_mt_to_ed(long* acycles, int i);
int tbench_dh_wei_to_mt(long* acycles, int i);
int tbench_dh_wei_to_ed(long* acycles, int i);
int tbench_eddsa_sign(long* acycles, int i);
int tbench_eddsa_verify(long* acycles, int i);