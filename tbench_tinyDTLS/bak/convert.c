#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "ecc.h"
#include "fprime.h"
#include "f25519.h"

static const uint32_t A[8] = {0x00076d06, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
static const uint32_t A_3[8] = {0x000279ac, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
static const uint32_t delta[8] = {0xaaad2451, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0x2aaaaaaa};
static const uint32_t c[8] = {0x00ba81e7, 0x3391fb55, 0xb482e57d, 0x3a5e2c2e, 0xfc03b081, 0x2d84f723, 0x9f5ff944, 0x70d9120b};
//static const uint32_t cinv[8] = {0xdb4268e9, 0x40b404af, 0xf243d5a1, 0x283138f9, 0x67051701, 0xf861819b, 0x6a3e5ba9, 0x244b6720};
static const uint32_t minus_one[8] = {0xffffffec, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff};
/*
int call_and_verify(char* callString) {
	if(system(callString)) exit(1);
	free(callString);
	return 0;
}

void strcat_array(char* callString, const uint32_t *p, int numberLength){ //here the values are turned to MSB!
	int n;
	strcat(callString, " 0x");
	char number[64];
	for(n = numberLength - 1; n >= 0; n--){
		sprintf(number, "%08x", p[n]);
		strcat(callString, number);
	}
}

int verify_e2w(uint32_t *x, uint32_t *y, uint32_t *rx, uint32_t *ry) {
	char* callString = malloc(1023 * sizeof(char));

	strcat(callString, "/home/ncme/uni/ma/proto/verify_e2w.py");
	strcat_array(callString, x, arrayLength);
	strcat_array(callString, y, arrayLength);
	strcat_array(callString, rx, arrayLength);
	strcat_array(callString, ry, arrayLength);
	//printf("%s\n", callString);
	return call_and_verify(callString);
}

int verify_w2e(uint32_t *x, uint32_t *y, uint32_t *rx, uint32_t *ry) {
	char* callString = malloc(1023 * sizeof(char));

	strcat(callString, "/home/ncme/uni/ma/proto/verify_w2e.py");
	strcat_array(callString, x, arrayLength);
	strcat_array(callString, y, arrayLength);
	strcat_array(callString, rx, arrayLength);
	strcat_array(callString, ry, arrayLength);
	//printf("%s\n", callString);
	return call_and_verify(callString);
}

static void print_array(const uint32_t *A, uint8_t length) {
	int i;
	for (i = length-1; i >= 0; --i)
	{
		printf("%08x ", A[i]);
	}
	//printf("\n");
}
*/
void twisted_edwards_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    if(isZero(px))  {
        if(isZero(py)) {
            printf("ED->WEI: Special Case: 0");
            setZero(rx, arrayLength);
            setZero(ry, arrayLength);
            return;
        }
        if(isSame(py, minus_one, arrayLength)) {
            printf("ED->WEI: Special Case: (0,-1)");
            copy(A_3, rx, arrayLength);
            setZero(ry, arrayLength);
            return;
        }
    }

    /*
        The following code calculates:
        rx = (1 + py) / ((1 - py) + delta)   (mod p)
        ry = (c * (1 + py)) / (1 - py) * px  (mod p)
    */

    uint32_t nom[8]; // nominator
    uint32_t den[8]; // denominator
    uint32_t tmp[8]; // temporary
    uint32_t tmp2[8];
    uint32_t mul[16];// multiplication result

/*
    static const uint32_t px2[8] = {0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760, 0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3};
    static const uint32_t py2[8] = {0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666};
    //assert(isSameDebug(px, px2, arrayLength));
    //assert(isSameDebug(py, py2, arrayLength));

    static const uint32_t lxpy[8] = {0x66666659, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666};
    static const uint32_t l_py[8] = {0x99999996, 0x99999999, 0x99999999, 0x99999999, 0x99999999, 0x99999999, 0x99999999, 0x19999999};
    static const uint32_t colxpy[8] = {0x9ae95054, 0x5cd39132, 0x11b869e1, 0x9c431c54, 0xf8d370e8, 0x51ef5673, 0x52132714, 0x17ed207b};
    static const uint32_t l_pyopx[8] = {0xe96df764, 0x5b77a2ac, 0x1dd454bd, 0x483c27e0, 0x992af8df, 0x59ba93a3, 0xf5e2dd99, 0x39e1d7c3};
    static const uint32_t l_py_inv[8] = {0x00000005, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
    static const uint32_t l_pyopx_inv[8] = {0x679e6794, 0x03f60932, 0x3e95a286, 0xe52ccfdf, 0xdefe19f1, 0x2603714e, 0xa0142031, 0x1c3ee720};

    static const uint32_t Gx[8] = {0xaaad245a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0x2aaaaaaa};
    static const uint32_t Gy[8] = {0x7eced3d9, 0x29e9c5a2, 0x6d7c61b2, 0x923d4d7e, 0x7748d14c, 0xe01edd2c, 0xb8a086b4, 0x20ae19a1};
*/
    setZero(tmp, arrayLength);
    tmp[0] = 0x00000001;                        // tmp = 1

    fieldAdd(tmp, py, ecc_prime_r, nom);        // nom = 1 + py
    //assert(isSameDebug(nom, lxpy, arrayLength));
    fieldSub(tmp, py, ecc_prime_m, tmp2);        // tmp2 = 1 - py
    //assert(isSameDebug(tmp2, l_py, arrayLength));
    fieldInv(tmp2, ecc_prime_m, ecc_prime_r, den);//den = (1 - py)^-1
    //assert(isSameDebug(tmp2, l_py, arrayLength));
    //assert(isSameDebug(den, l_py_inv, arrayLength));
    fieldMult(nom, den, mul, arrayLength);      // mul = (1 + py) * (1 - py)^-1
    fieldModP(tmp, mul);                         // tmp  = (1 + py) * (1 - py)^-1  (mod p)
    //assert(isSameDebug(tmp2, l_py, arrayLength));
    //print_array(tmp, arrayLength);
    setZero(mul, 16);
    fieldAdd(tmp, delta, ecc_prime_r, mul);     // rx = ((1 + py) * (1 - py)^-1) + delta
    if(isGreater(mul, ecc_prime_m, arrayLength) >= 0) {
        fieldModP(rx,mul);
    } else {
        copy(mul, rx, arrayLength);
    }

    //assert(isSameDebug(rx, Gx, arrayLength));

    fieldMult(tmp2, px, mul, arrayLength);       // mul = (1 - py) * px
    fieldModP(tmp, mul);                         // tmp = (1 - py) * px (mod p)
    //assert(isSameDebug(tmp, l_pyopx, arrayLength));
    fieldMult(c, nom, mul, arrayLength);       //   mul = c * (1 + py)
    fieldModP(nom, mul);                        // nom = (c * (1 + py)) (mod p)
    //assert(isSameDebug(nom, colxpy, arrayLength));
    fieldInv(tmp, ecc_prime_m, ecc_prime_r, den);//den = ((1 - py) * px)^-1 (mod p)
    //assert(isSameDebug(den, l_pyopx_inv, arrayLength));
    fieldMult(nom, den, mul, arrayLength);      // mul = (c * (1 + py)) * ((1 - py) * px)^-1
    fieldModP(ry, mul);                         // ry  = (c * (1 + py)) * ((1 - py) * px)^-1  (mod p)
    //isSameDebug(ry, Gy, arrayLength);
    //verify_e2w(px, py, rx, ry);
}

void short_weierstrass_to_twisted_edwards(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    if(isZero(py))  {
        if(isZero(px)) {
            printf("WEI->ED: Special Case: 0");
            setZero(rx, arrayLength);
            setZero(ry, arrayLength);
            return;
        }
        if(isSame(px, A_3, arrayLength)) {
            printf("WEI->ED: Special Case: (0,delta)");
            setZero(rx, arrayLength);
            copy(minus_one, ry, arrayLength);
            return;
        }
    }

    /*
        The following code calculates:
        pa = 3 * p.x - A
        rx = (c * pa) / (3 * py)
        ry = (pa - 3) / (pa + 3)
    */

   static const uint32_t three[8] = {0x00000003, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};

    uint32_t pa[8];  // intermediate result
    uint32_t nom[8]; // nominator
    uint32_t den[8]; // denominator
    uint32_t tmp[8]; // temporary
    uint32_t mul[16];// multiplication result

    //setZero(tmp, arrayLength);
    //tmp[0] = 0x00000003;                        // tmp = 3

    fieldMult(three, py, mul, arrayLength);       // mul = 3 * py
    fieldModP(tmp, mul);                        // tmp = 3 * py (mod p)
    fieldInv(tmp, ecc_prime_m, ecc_prime_r, den);//den = (3 * py)^-1

    fieldMult(three, px, mul, arrayLength);       // mul = 3 * p.x
    fieldModP(tmp, mul);                        // tmp = 3 * px (mod p)
    fieldSub(tmp, A, ecc_prime_m, pa);          // pa  = 3 * px - A

    fieldMult(c, pa, mul, arrayLength);         // mul = c * pa
    fieldModP(nom, mul);                        // nom = c * pa (mod p)

    fieldMult(nom, den, mul, arrayLength);       // mul = (c * pa) * (3 * py)^-1
    fieldModP(rx, mul);                          // rx  = (c * pa) * (3 * py)^-1 (mod p)

    fieldSub(pa, three, ecc_prime_m, nom);        // nom = pa - 3
    fieldAdd(pa, three, ecc_prime_r, den);        // den = pa + 3
    fieldInv(den, ecc_prime_m, ecc_prime_r, tmp);//tmp = (pa + 3)^-1
    fieldMult(nom, tmp, mul, arrayLength);      // mul = (pa - 3) * (pa + 3)^-1
    fieldModP(ry, mul);                         // ry  = (pa - 3) * (pa + 3)^-1 (mod p)
    //verify_w2e(px, py, rx, ry);
}

/*
The inverse mapping maps the point (x,y) on Wei25519 to (u,v):=(x - A/3,y) on Curve25519,
*/
void short_weierstrass_to_montgomery(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    ecc_copy(py, ry, arrayLength);
    if(isZero(px) && isZero(py)) {
        copy(px, rx, arrayLength);
        return;
    }

    /*
        The following code calculates:
        (px,py) == ((px - A/3),py)
    */
    uint32_t tmp[arrayLength];
    fieldSub(px, delta, ecc_prime_m, rx);
    //fieldModP(rx, tmp);
    return;
}

/*
Each point (u,v) of Curve25519 corresponds to the point (x,y):=(u + A/3,y) of Wei25519, while the point at infinity of Curve25519
corresponds to the point at infinity of Wei25519.
*/
void montgomery_to_short_weierstrass(const uint32_t* px, const uint32_t* py, uint32_t* rx, uint32_t* ry) {
    ecc_copy(py, ry, arrayLength);
    if(isZero(px) && isZero(py)) {
        copy(px, rx, arrayLength);
        return;
    }

    /*
        The following code calculates:
        (px,py) == ((px + A/3),py)
    */
    uint32_t tmp[arrayLength];
    fieldAdd(px, delta, ecc_prime_r, rx);
    //fieldModP(rx, tmp);
    return;
}

const uint8_t fprime_three[FPRIME_SIZE] = {};
const uint8_t fprime_minus_one[FPRIME_SIZE] = {};
const uint8_t fprime_A_3[FPRIME_SIZE] = {};
const uint8_t fprime_delta[FPRIME_SIZE] = {};
const uint8_t fprime_c[FPRIME_SIZE] = {};
const uint8_t fprime_A[FPRIME_SIZE] = {};

void c25519_ed_to_wei(const uint8_t* px, const uint8_t* py, uint8_t* rx, uint8_t* ry, uint8_t* mod) {
    if(fprime_eq(px, fprime_zero))  {
        if(fprime_eq(py, fprime_zero)) {
            printf("ED->WEI: Special Case: 0");
            fprime_copy(rx, fprime_zero);
            fprime_copy(ry, fprime_zero);
            return;
        }
        if(fprime_eq(py, fprime_minus_one)) {
            printf("ED->WEI: Special Case: (0,-1)");
            fprime_copy(rx, fprime_A_3);
            fprime_copy(ry, fprime_zero);
            return;
        }
    }

    /*
        The following code calculates:
        rx = ((1 + py) / (1 - py)) + delta   (mod p)
        ry = (c * (1 + py)) / (1 - py) * px  (mod p)
    */

    uint8_t nom[FPRIME_SIZE];   // nominator
    uint8_t den[FPRIME_SIZE];   // denominator
    uint8_t inv[FPRIME_SIZE];   // inversion result
    uint8_t tmp[FPRIME_SIZE];   // temporary
    uint8_t mul[FPRIME_SIZE];   // multiplication result

    fprime_copy(nom, fprime_one);       // nom =   1
    fprime_copy(den, fprime_one);       // den =              1
    fprime_add(nom, py, mod);           // nom =   1 + py
    fprime_sub(den, py, mod);           // den =              1 - py
    fprime_inv(tmp, den, mod);          // inv =             (1 - py)^-1
    fprime_mul(rx, nom, tmp, mod);      //  rx =  (1 + py) * (1 - py)^-1
    fprime_add(rx, fprime_delta, mod);  //  rx = ((1 + py) * (1 - py)^-1) + delta
    //fprime_normalize(rx, mod);        //  rx = ((1 + py) * (1 - py)^-1) + delta  (mod p)

    fprime_mul(mul, fprime_c, nom, mod);// mul =  c * (1 + py)
    fprime_mul(tmp, den, px, mod);      // tmp =                   (1 - py) * px
    fprime_inv(den, tmp, mod);          // den =                  ((1 - py) * px)^-1
    fprime_mul(ry, mul, den, mod);      //  ry = (c * (1 + py)) * ((1 - py) * px)^-1
    //fprime_normalize(ry, mod);        //  ry = (c * (1 + py)) * ((1 - py) * px)^-1  (mod p)
}

void c25519_wei_to_ed(const uint8_t* px, const uint8_t* py, uint8_t* rx, uint8_t* ry, uint8_t* mod) {
    if(fprime_eq(py, fprime_zero))  {
        if(fprime_eq(px, fprime_zero)) {
            printf("WEI->ED: Special Case: 0");
            fprime_copy(rx, fprime_zero);
            fprime_copy(ry, fprime_zero);
            return;
        }
        if(fprime_eq(px, fprime_A_3)) {
            printf("WEI->ED: Special Case: (0,delta)");
            fprime_copy(rx, fprime_zero);
            fprime_copy(ry, fprime_minus_one);
            return;
        }
    }

    /*
        The following code calculates:
        pa = 3 * p.x - A
        rx = (c * pa) / (3 * py)
        ry = (pa - 3) / (pa + 3)
    */
    uint8_t pa[FPRIME_SIZE]; // intermediate result
    fprime_mul(pa, fprime_three, px, mod);      // pa  = 3 * px
    fprime_sub(pa, fprime_A, mod);              // pa  = 3 * px - A

    uint8_t nom[FPRIME_SIZE]; // nominator
    uint8_t den[FPRIME_SIZE]; // denominator
    uint8_t inv[FPRIME_SIZE]; // inverted denominator

    fprime_mul(den, fprime_three, py, mod);     // den =             3 * py
    fprime_inv(inv, den, mod);                  // inv =            (3 * py)^-1
    fprime_mul(nom, fprime_c, pa, mod);         // nom =  c * pa
    fprime_mul(rx, nom, inv, mod);              // rx  = (c * pa) * (3 * py)^-1
    //fprime_normalize(rx, mod);                // rx  = (c * pa) * (3 * py)^-1 (mod p)

    fprime_copy(nom, pa);                       // nom =  pa
    fprime_sub(nom, fprime_three, mod);         // nom =  pa - 3
    fprime_add(pa, fprime_three, mod);          //  pa =             pa + 3
    fprime_inv(inv, pa, mod);                   // inv =            (pa + 3)^-1
    fprime_mul(ry, nom, inv, mod);              //  ry = (pa - 3) * (pa + 3)^-1
    //fprime_normalize(ry, mod);                //  ry = (pa - 3) * (pa + 3)^-1 (mod p)
}

/*
The inverse mapping maps the point (x,y) on Wei25519 to (u,v):=(x - A/3,y) on Curve25519,
*/
void c25519_wei_to_mt(const uint8_t* px, const uint8_t* py, uint8_t* rx, uint8_t* ry, uint8_t* mod) {
    fprime_copy(rx, px);
    fprime_copy(ry, py);

    /*
        The following code calculates:
        (px,py) == (0,0) ? (0,0) : ((px - A/3),py)
    */
    fprime_sub(rx, fprime_A_3, mod);
    fprime_normalize(rx, mod);
    fprime_select(rx, rx, fprime_zero, fprime_eq(px, fprime_zero));
}

/*
Each point (u,v) of Curve25519 corresponds to the point (x,y):=(u + A/3,y) of Wei25519, while the point at infinity of Curve25519
corresponds to the point at infinity of Wei25519.
*/
void c25519_mt_to_wei(const uint8_t* px, const uint8_t* py, uint8_t* rx, uint8_t* ry, uint8_t* mod) {
    fprime_copy(rx, px);
    fprime_copy(ry, py);

    /*
        The following code calculates:
        (px,py) == (0,0) ? (0,0) : ((px + A/3),py)
    */
    fprime_add(rx, fprime_A_3, mod);
    fprime_normalize(rx, mod);
    fprime_select(rx, rx, fprime_zero, fprime_eq(px, fprime_zero));
}

