#include <stdio.h>
#include <stdlib.h>
#include "gmp.h"
#include "ObliviousTransfer.h"

int main(){
    publicParams_t publicParam;

    //Alice
    secretKey_t secretKeyA;
    blindedsecretKey_t blindedSecretKeyA;
    sharedKey_t sharedKeyA;
    sharedTuple_t sharedTupleA;
    secretTuple_t secretTupleA;
    blindedsecretKey_t blindedRA;
    sharedKey_t sharedRA;   

    //Bob
    secretKey_t secretKeyB;
    blindedsecretKey_t blindedSecretKeyB;
    sharedKey_t sharedKeyB;
    sharedTuple_t sharedTupleB;
    secretTuple_t secretTupleB;
    blindedsecretKey_t blindedRB;
    sharedKey_t sharedRB;  

    initObliviousTransfer();

    PublicParamsGenerator(&publicParam);

    printf("Public Parameters\r\nprime :");
    mpz_out_str(stdout,10,publicParam.p);
    printf("\r\ng0 :");
    mpz_out_str(stdout,10,publicParam.g0);
    printf("\r\ng1 :");
    mpz_out_str(stdout,10,publicParam.g1);
    printf("\r\ng2 :");
    mpz_out_str(stdout,10,publicParam.g2);
    printf("\r\n");

    ComputeSecretKey(secretKeyA,publicParam);
    printf("Alice Secret Key: ");
    mpz_out_str(stdout,10,secretKeyA);
    printf("\r\n");

    ComputeBlindSecretKey(blindedSecretKeyA,secretKeyA,publicParam);
    printf("Alice Blined Secret Key: ");
    mpz_out_str(stdout,10,blindedSecretKeyA);
    printf("\r\n");

    ComputeSecretKey(secretKeyB,publicParam);
    printf("Bob Secret Key: ");
    mpz_out_str(stdout,10,secretKeyB);
    printf("\r\n");

    ComputeBlindSecretKey(blindedSecretKeyB,secretKeyB,publicParam);
    printf("Bob Blined Secret Key: ");
    mpz_out_str(stdout,10,blindedSecretKeyB);
    printf("\r\n");

    ComputeDHSharedKey(sharedKeyA,blindedSecretKeyB,secretKeyA,publicParam);
    printf("Alice Shared Key: ");
    mpz_out_str(stdout,10,sharedKeyA);
    printf("\r\n");

    ComputeDHSharedKey(sharedKeyB,blindedSecretKeyA,secretKeyB,publicParam);
    printf("Bob Shared Key: ");
    mpz_out_str(stdout,10,sharedKeyB);
    printf("\r\n");


    ComputeSecretTuple(&secretTupleA,publicParam);
    printf("Alice Secret Tuple a: ");
    mpz_out_str(stdout,10,secretTupleA.a);
    printf("\t e:");
    mpz_out_str(stdout,10,secretTupleA.e);
    printf("\r\n");
    ComputeSecret(&secretTupleA,publicParam);
    ComputeSharedTuple(&sharedTupleA,secretTupleA,sharedKeyA,publicParam,50);
    printf("Alice Shared Tuple G: ");
    mpz_out_str(stdout,10,sharedTupleA.G);
    printf("\t Q:");
    mpz_out_str(stdout,10,sharedTupleA.Q);
    printf("\r\n");
    int i;
    printf("B :");
    for(i=0;i<securityParam;i++){
        mpz_out_str(stdout,10,sharedTupleA.B[i]);
        printf("  ");
    }
    printf("\r\n");

    ComputeSecretTuple(&secretTupleB,publicParam);
    printf("Bob Secret Tuple a: ");
    mpz_out_str(stdout,10,secretTupleB.a);
    printf("\t e:");
    mpz_out_str(stdout,10,secretTupleB.e);
    printf("\r\n");
    ComputeSecret(&secretTupleB,publicParam);
    ComputeSharedTuple(&sharedTupleB,secretTupleB,sharedKeyB,publicParam,50);
    printf("Bob Shared Tuple G: ");
    mpz_out_str(stdout,10,sharedTupleB.G);
    printf("\t Q:");
    mpz_out_str(stdout,10,sharedTupleB.Q);
    printf("\r\n");
        printf("B :");
    for(i=0;i<securityParam;i++){
        mpz_out_str(stdout,10,sharedTupleB.B[i]);
        printf("  ");
    }
    printf("\r\n");

    int k;
    for(k=0;k<securityParam;k++){
        if(ValidatePartofSecret(secretTupleA.aArray[k],secretTupleA.eArray[k],sharedTupleA.B[k],k,sharedKeyA,publicParam)){
            printf("Alice %d failed\r\n",k);
        }
        else{
            printf("Alice %d passed\r\n",k);
        }
    }

    for(k=0;k<securityParam;k++){
        if(ValidatePartofSecret(secretTupleB.aArray[k],secretTupleB.eArray[k],sharedTupleB.B[k],k,sharedKeyB,publicParam)){
            printf("Bob %d failed\r\n",k);
        }
        else{
            printf("Bob %d passed\r\n",k);
        }
    }

    int validate;
    validate = ValidateKnowledgeOfSecret(sharedTupleA,publicParam);
    if(validate){
        printf("Alice's Knowledge of a,e not validated\r\n ");
    }
    else{
          printf("Alice's Knowledge of a,e validated\r\n ");
    }

    validate = ValidateKnowledgeOfSecret(sharedTupleB,publicParam);
    if(validate){
        printf("Bob's Knowledge of e,f not validated\r\n ");
    }
    else{
          printf("Bob's Knowledge of e,f validated\r\n ");
    }

    ComputeBlindR(blindedRA,sharedTupleA,sharedTupleB,secretKeyA,publicParam);
    printf("Alice Blined R: ");
    mpz_out_str(stdout,10,blindedRA);
    printf("\r\n");

    ComputeBlindR(blindedRB,sharedTupleA,sharedTupleB,secretKeyB,publicParam);
    printf("Bob Blined R: ");
    mpz_out_str(stdout,10,blindedRB);
    printf("\r\n");

    ComputeDHSharedR(sharedRA,blindedRB,secretKeyA,publicParam);
    printf("Alice Shared R: ");
    mpz_out_str(stdout,10,sharedRA);
    printf("\r\n");

    ComputeDHSharedR(sharedRB,blindedRA,secretKeyB,publicParam);
    printf("Bob Shared R: ");
    mpz_out_str(stdout,10,sharedRB);
    printf("\r\n");

    int result;
    result = CompareNonDisclosedData(sharedTupleA,sharedTupleB,secretTupleA.e,secretTupleB.e,sharedRA,publicParam);
    if(result){
        printf("Alice : Values not Equal\r\n");
    }
    else{
        printf("Alice : Values are Equal\r\n");
    }

    result = CompareNonDisclosedData(sharedTupleA,sharedTupleB,secretTupleA.e,secretTupleB.e,sharedRB,publicParam);
    if(result){
        printf("Bob : Values not Equal\r\n");
    }
    else{
        printf("Bob : Values are Equal\r\n");
    }
    return 0;
}