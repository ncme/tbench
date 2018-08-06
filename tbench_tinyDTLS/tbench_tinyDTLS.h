#define TBENCH_DH_P256 tbench_dh_P256
#define TBENCH_DH_WEI25519 tbench_dh_Wei
#define TBENCH_DH_ED25519_TO_WEI25519 tbench_dh_Ed

int tbench_dh_P256(long acycles[], int i);
int tbench_dh_Wei(long acycles[], int i);
int tbench_dh_Ed(long acycles[], int i);
