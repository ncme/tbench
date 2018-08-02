#define TBENCH_P256 tbench_dh_P256
#define TBENCH_WEI25519 tbench_dh_Wei
#define TBENCH_ED25519_TO_WEI25519 tbench_dh_Ed

int tbench_dh_P256(long acycles[], int i);
int tbench_dh_Wei(long acycles[], int i);
int tbench_dh_Ed(long acycles[], int i);
