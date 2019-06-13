#ifndef OBLIVIOUSTRANSFER
#define OBLIVIOUSTRANSFER
#include "gmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//Maximum bit length of the scheme
int maxBitLength;
int securityParam;

//Global state of random generator
gmp_randstate_t state;
unsigned long int seed;

typedef struct publicParams_t{
    mpz_t p,g0,g1,g2;
}publicParams_t;

typedef mpz_t secretKey_t;
typedef mpz_t blindedsecretKey_t;
typedef mpz_t sharedKey_t;
typedef int nonDisclosedData_t;

typedef struct sharedTuple_t{
    mpz_t G,Q;
}sharedTuple_t;

typedef struct secretTuple_t{
    mpz_t a,e;
}secretTuple_t;

void initObliviousTransfer();

void PublicParamsGenerator(publicParams_t*);

void ComputeSecretKey(secretKey_t,publicParams_t);

void ComputeBlindSecretKey(blindedsecretKey_t,secretKey_t,publicParams_t);

void ComputeDHSharedKey(sharedKey_t,blindedsecretKey_t,secretKey_t,publicParams_t);

void ComputeSharedTuple(sharedTuple_t*,secretTuple_t*, sharedKey_t, publicParams_t, nonDisclosedData_t);

void ComputeBlindR(blindedsecretKey_t,sharedTuple_t,sharedTuple_t,secretKey_t,publicParams_t);

void ComputeDHSharedR(sharedKey_t,blindedsecretKey_t,secretKey_t,publicParams_t);

int CompareNonDisclosedData(sharedTuple_t,sharedTuple_t,secretKey_t,secretKey_t,sharedKey_t,publicParams_t);



#endif