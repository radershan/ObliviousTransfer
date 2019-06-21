/*
This protocol is implementetd according to "A Fair and Efficient Solution to the Socialist
Millionaires’ Problem" by Fabrice Boudot (https://www.win.tue.nl/~berry/papers/dam.pdf)
*/
#ifndef OBLIVIOUSTRANSFER
#define OBLIVIOUSTRANSFER
#include "gmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


#define securityParam   5
//Maximum bit length of the scheme
#define maxBitLength    8



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
    mpz_t B[securityParam];
}sharedTuple_t;

typedef struct secretTuple_t{
    mpz_t a,e;
    mpz_t aArray[securityParam];
    mpz_t eArray[securityParam];
}secretTuple_t;

/**
 * @brief Initialize the protocol
 * 
 */
void initObliviousTransfer();

/**
 * @brief Generates public parameters that required for protocol
 * 
 */
void PublicParamsGenerator(publicParams_t*);

/**
 * @brief Computes a secret key for Diffe-Helman shared key generation
 * 
 */
void ComputeSecretKey(secretKey_t,publicParams_t);

/**
 * @brief Blinds the secretkey for  Diffe-Helman shared key generation
 * 
 */
void ComputeBlindSecretKey(blindedsecretKey_t,secretKey_t,publicParams_t);

/**
 * @brief Computes the Diffe-Helman shared key
 * 
 */
void ComputeDHSharedKey(sharedKey_t,blindedsecretKey_t,secretKey_t,publicParams_t);

/**
 * @brief Computes secret tuple a,e according to the protocol 
 * 
 */
void ComputeSecretTuple(secretTuple_t*,publicParams_t);

/**
 * @brief Computes the a, e from a[0]...a[k-1], e[0]...e[k-1]
 * 
 */

void ComputeSecret(secretTuple_t*,publicParams_t);

/**
 * @brief Validates a {a[i],e[i]} tuple with respective B[i]
 * 
 */
 
int  ValidatePartofSecret(mpz_t,mpz_t,mpz_t,int,sharedKey_t,publicParams_t);

/**
 * @brief Computes P,Q according to protocol
 * 
 */

void ComputeSharedTuple(sharedTuple_t*,secretTuple_t, sharedKey_t, publicParams_t, nonDisclosedData_t);

/**
 * @brief Validates the {B[0]...B[k-1]} with P
 * 
 */

int ValidateKnowledgeOfSecret(sharedTuple_t,publicParams_t);

/**
 * @brief Computes the blinded R value
 * 
 */
void ComputeBlindR(blindedsecretKey_t,sharedTuple_t,sharedTuple_t,secretKey_t,publicParams_t);

/**
 * @brief Computes the Shared R value according to Diffe-Helman Shared key generation
 * 
 */
 
void ComputeDHSharedR(sharedKey_t,blindedsecretKey_t,secretKey_t,publicParams_t);

/**
 * @brief Computes the redsults that both parties values are equal or not 
 * 
 */
int CompareNonDisclosedData(sharedTuple_t,sharedTuple_t,secretKey_t,secretKey_t,sharedKey_t,publicParams_t);



#endif