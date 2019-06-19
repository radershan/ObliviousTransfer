#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"
#include "ObliviousTransfer.h"


#define DEBUG           0

publicParams_t publicParam;

//Alice
secretKey_t secretKeyA;
blindedsecretKey_t blindedSecretKeyA;
blindedsecretKey_t blindedSecretKeyB;
sharedKey_t sharedKey;

sharedTuple_t sharedTupleA;
sharedTuple_t sharedTupleB;
secretTuple_t secretTupleA;
secretTuple_t secretTupleB;

blindedsecretKey_t blindedRA;
blindedsecretKey_t blindedRB;
sharedKey_t sharedR;   
int compareValueA;
int member;

void InitOT(int m){
    member = m;
    initObliviousTransfer();
    PublicParamsGenerator(&publicParam);
}

void SetPublicParams(char* strP, char* strG0, char* strG1, char* strG2){
    mpz_set_str(publicParam.p,strP,10);
    mpz_set_str(publicParam.g0,strG0,10);
    mpz_set_str(publicParam.g1,strG1,10);
    mpz_set_str(publicParam.g2,strG2,10);
}

char* GetPublicParams(int index){
    if(index ==0){
        return mpz_get_str(NULL,10,publicParam.p);
    }
    else if(index ==1){
        return mpz_get_str(NULL,10,publicParam.g0);
    }
    else if(index ==2){
        return mpz_get_str(NULL,10,publicParam.g1);
    }
    else if(index ==3){
        return mpz_get_str(NULL,10,publicParam.g2);
    }
}

char* GetBlinedKey(){
    ComputeSecretKey(secretKeyA,publicParam);
    ComputeBlindSecretKey(blindedSecretKeyA,secretKeyA,publicParam);
    return mpz_get_str(NULL,10,blindedSecretKeyA);
}

void SetSharedKey(char* strBKey){
    mpz_init2(blindedSecretKeyB,maxBitLength);
    mpz_set_str(blindedSecretKeyB,strBKey,10);
    ComputeDHSharedKey(sharedKey,blindedSecretKeyB,secretKeyA,publicParam);
    
#if DEBUG
    printf("Shared Key :");
    mpz_out_str(stdout,10,sharedKey);
    printf("\r\n");
#endif
}

void SetCompareValue(int c){
    compareValueA = c;
    ComputeSecretTuple(&secretTupleA,publicParam);
    ComputeSharedTuple(&sharedTupleA,secretTupleA,sharedKey,publicParam,compareValueA);
}

char* GetSharedTuple(int index){
    if(index ==0){
        return mpz_get_str(NULL,10,sharedTupleA.G);
    }
    else if(index ==1){
        return mpz_get_str(NULL,10,sharedTupleA.Q);
    }
}

void SetSharedTuple(char* strP, char* strQ){
    mpz_init2(sharedTupleB.G,maxBitLength);
    mpz_init2(sharedTupleB.Q,maxBitLength);
    mpz_set_str(sharedTupleB.G,strP,10);
    mpz_set_str(sharedTupleB.Q,strQ,10);

#if DEBUG
    printf("P :");
    mpz_out_str(stdout,10,sharedTupleB.G);
    printf(" Q :");
    mpz_out_str(stdout,10,sharedTupleB.Q);
    printf("\r\n");
#endif
}

char* GetBValue(int index){
    return mpz_get_str(NULL,10,sharedTupleA.B[index]);
}

char* GetAValue(int index){
    return mpz_get_str(NULL,10,secretTupleA.aArray[index]);
}

char* GetEValue(int index){
    return mpz_get_str(NULL,10,secretTupleA.eArray[index]);
}

void SetAEValue(char* strA, char* strE, int index){
    mpz_init2(secretTupleB.aArray[index],maxBitLength);
    mpz_init2(secretTupleB.eArray[index],maxBitLength);
    mpz_set_str(secretTupleB.aArray[index],strA,10);
    mpz_set_str(secretTupleB.eArray[index],strE,10);     
}

int ValidateKnowledge(char* strB, char* stra, char* stre){
    mpz_t B,a,e;
    mpz_init2(B,maxBitLength);
    mpz_init2(a,maxBitLength);
    mpz_init2(e,maxBitLength);

    mpz_set_str(B,strB,10);
    mpz_set_str(a,stra,10);
    mpz_set_str(e,stre,10);
    int result;
    result = ValidatePartofSecret(a,e,B,sharedKey,publicParam);
    return !result;
}

char* GetBlinedR(){
    if(member==0){
    ComputeBlindR(blindedRA,sharedTupleA,sharedTupleB,secretKeyA,publicParam);
    return mpz_get_str(NULL,10,blindedRA);
    }
    else if(member==1){
    ComputeBlindR(blindedRA,sharedTupleB,sharedTupleA,secretKeyA,publicParam);
    return mpz_get_str(NULL,10,blindedRA);
    }
}

void SetSharedR(char* strBRKey){
    mpz_init2(blindedRB,maxBitLength);
    mpz_set_str(blindedRB,strBRKey,10);
    ComputeDHSharedR(sharedR,blindedRB,secretKeyA,publicParam);
    
#if DEBUG
    printf("Shared Key :");
    mpz_out_str(stdout,10,sharedR);
    printf("\r\n");
#endif
}

int GetResult(){
    ComputeSecret(&secretTupleB,publicParam);
    int result;
    if(member==0){
        result = CompareNonDisclosedData(sharedTupleA,sharedTupleB,secretTupleA.e,secretTupleB.e,sharedR,publicParam);
        return !result;
    }
    else if(member==1){
        result = CompareNonDisclosedData(sharedTupleB,sharedTupleA,secretTupleB.e,secretTupleA.e,sharedR,publicParam);
        return !result;
    }
}

int GetSecurityParam(){
    return securityParam;
}