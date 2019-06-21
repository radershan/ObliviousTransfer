#include "ObliviousTransfer.h"


/*Parameter Generation*/
/*
1. Find large prime q
2. Find g0,g1,g2 generator of q
3. security parameter k, k<|q|
4. x,y element of q
*/

/*
Step 1
ga =g1^xa modq
g3 =g1^(xa*xb) modq

step 2
1. random a = sum(ai*2^i modq)
2. random e = sum(ei*2^i) (0<= e <= 2^k)
3. Pa = g3^a * g0^e
4. Qa = g1^a * g2^x
*/
void initObliviousTransfer(){
  // maxBitLength = 128;
  // securityParam = 60;
  //Initializing random generator with current time as seed
  seed = (unsigned long int)time(NULL);
  seed += rand();
  gmp_randinit_mt(state);
  gmp_randseed_ui(state,seed);
}

static void GetGeneratorOfSafePrime(mpz_t g, mpz_t prime){
    mpz_t temp,n;
    mpz_init2(temp,maxBitLength);
    mpz_init2(n,maxBitLength);
    mpz_sub_ui(n,prime,1);

    while(1){
      mpz_urandomm(g ,state, n);
      mpz_div_ui(temp,n,2);
      mpz_powm(temp,g,temp,prime);
      if(mpz_get_ui(temp)==1 || mpz_get_ui(g)==0){
        continue;
      }
      mpz_set_ui(temp,2);
      mpz_powm(temp,g,temp,prime);
      if(mpz_get_ui(temp)==1 || mpz_get_ui(g)==0){
        continue;
      }
      else{
        break;
      }
   }
   mpz_clear(temp);
   mpz_clear(n);
}

void PublicParamsGenerator(publicParams_t* publicParams){
    mpz_init2(publicParams->p,maxBitLength);
    mpz_init2(publicParams->g0,maxBitLength);
    mpz_init2(publicParams->g1,maxBitLength);
    mpz_init2(publicParams->g2,maxBitLength);

    //Finding a safe prime
    while(!(mpz_probab_prime_p(publicParams->p,50))){
      //Find a very large random no
      mpz_rrandomb(publicParams->p ,state, maxBitLength-2);

      //Find a very large prime no p by using a large random no 
      mpz_nextprime (publicParams->p,publicParams->p);

      //2p
      mpz_mul_ui(publicParams->p,publicParams->p,2);

      //2p+1
      mpz_add_ui(publicParams->p,publicParams->p,1);
    }

    GetGeneratorOfSafePrime(publicParams->g0,publicParams->p);
    GetGeneratorOfSafePrime(publicParams->g1,publicParams->p);
    GetGeneratorOfSafePrime(publicParams->g2,publicParams->p);
}


void ComputeSecretKey(secretKey_t secretKey, publicParams_t publicParams){
    mpz_init2(secretKey,maxBitLength);
    mpz_urandomm(secretKey,state, publicParams.p);
    while(mpz_get_ui(secretKey)==0){
        mpz_urandomm(secretKey,state, publicParams.p);
    }
}

void ComputeBlindSecretKey(blindedsecretKey_t blindedsecretKey,secretKey_t secretKey,publicParams_t publicParams){
    mpz_init2(blindedsecretKey,maxBitLength);
    mpz_powm(blindedsecretKey,publicParams.g1,secretKey,publicParams.p);
}

void ComputeDHSharedKey(sharedKey_t sharedKey,blindedsecretKey_t blindedsecretKey,secretKey_t secretKey,publicParams_t publicParams){
    mpz_init2(sharedKey,maxBitLength);
    mpz_powm(sharedKey,blindedsecretKey,secretKey,publicParams.p);
}

void ComputeSecretTuple(secretTuple_t* secretTuple,publicParams_t publicParams){
    mpz_init2(secretTuple->a,maxBitLength);
    mpz_init2(secretTuple->e,maxBitLength);
    
    mpz_t temp;
    mpz_init2(temp,maxBitLength*2);

    mpz_set_ui(secretTuple->a,0);
    mpz_set_ui(secretTuple->e,0);
    unsigned long int i;

    for(i=0;i<securityParam;i++){
      mpz_init2(secretTuple->aArray[i],maxBitLength);
      mpz_urandomm(secretTuple->aArray[i],state, publicParams.p);
      while(mpz_get_ui(secretTuple->aArray[i])==0){
        mpz_urandomm(secretTuple->aArray[i],state, publicParams.p);
      }
      
      mpz_ui_pow_ui(temp,2,i);
      mpz_mul(temp,secretTuple->aArray[i],temp);
      mpz_mod(temp,temp,publicParams.p);
      mpz_add(secretTuple->a,secretTuple->a,temp);

      mpz_init2(secretTuple->eArray[i],1);
      mpz_urandomb(secretTuple->eArray[i],state, 1);

      mpz_ui_pow_ui(temp,2,i);
      mpz_mul(temp,secretTuple->eArray[i],temp);
      mpz_add(secretTuple->e,secretTuple->e,temp);

    }

}

void ComputeSecret(secretTuple_t*secretTuple,publicParams_t publicParams){
    mpz_t temp;
    mpz_init2(temp,maxBitLength*2);
    mpz_init2(secretTuple->a,maxBitLength*2);
    mpz_init2(secretTuple->e,maxBitLength*2);

    mpz_set_ui(secretTuple->a,0);
    mpz_set_ui(secretTuple->e,0);
    unsigned long int i;

    for(i=0;i<securityParam;i++){         
      mpz_ui_pow_ui(temp,2,i);
      mpz_mul(temp,secretTuple->aArray[i],temp);
      mpz_mod(temp,temp,publicParams.p);
      mpz_add(secretTuple->a,secretTuple->a,temp);

      mpz_ui_pow_ui(temp,2,i);
      mpz_mul(temp,secretTuple->eArray[i],temp);
      mpz_add(secretTuple->e,secretTuple->e,temp);
    }
   
}

void ComputeSharedTuple(sharedTuple_t* sharedTuple, secretTuple_t secretTuple, sharedKey_t sharedKey, publicParams_t publicParams, nonDisclosedData_t nonDisclosedData){
    mpz_init2(sharedTuple->G,maxBitLength);
    mpz_init2(sharedTuple->Q,maxBitLength);

    mpz_t temp;
    mpz_init2(temp,maxBitLength*2);

    int i;
    for(i=0;i<securityParam;i++){
      mpz_init2(sharedTuple->B[i],maxBitLength);
      mpz_ui_pow_ui(temp,2,i);
      mpz_mul(temp,secretTuple.aArray[i],temp);
      mpz_mod(temp,temp,publicParams.p);
      mpz_powm(sharedTuple->B[i],sharedKey,temp, publicParams.p);

      mpz_ui_pow_ui(temp,2,i);
      mpz_mul(temp,secretTuple.eArray[i],temp);
      mpz_powm(temp,publicParams.g0,temp, publicParams.p);
      mpz_mul(temp,temp,sharedTuple->B[i]);
      mpz_mod(sharedTuple->B[i],temp,publicParams.p);
          
    }
    
    mpz_powm(sharedTuple->G,sharedKey,secretTuple.a, publicParams.p);
    mpz_powm(temp,publicParams.g0,secretTuple.e, publicParams.p);
    mpz_mul(temp,temp,sharedTuple->G);
    mpz_mod(sharedTuple->G,temp,publicParams.p);
    
    
    mpz_powm(sharedTuple->Q,publicParams.g1,secretTuple.a, publicParams.p);
    mpz_set_ui(temp,nonDisclosedData);
    mpz_powm(temp,publicParams.g2,temp, publicParams.p);
    mpz_mul(temp,temp,sharedTuple->Q);
    mpz_mod(sharedTuple->Q,temp,publicParams.p);
}

int ValidatePartofSecret(mpz_t a,mpz_t e,mpz_t B,int index,sharedKey_t sharedKey,publicParams_t publicParams){
    mpz_t tempB,temp;
    mpz_init2(tempB,maxBitLength*2);
    mpz_init2(temp,maxBitLength*2);

    mpz_ui_pow_ui(temp,2,index);
    mpz_mul(temp,a,temp);
    mpz_mod(temp,temp,publicParams.p);
    mpz_powm(tempB,sharedKey,temp, publicParams.p);

    mpz_ui_pow_ui(temp,2,index);
    mpz_mul(temp,e,temp);
    mpz_powm(temp,publicParams.g0,temp, publicParams.p);
    mpz_mul(temp,temp,tempB);
    mpz_mod(tempB,temp,publicParams.p);
  
  return mpz_cmp(B,tempB);
  
}

int ValidateKnowledgeOfSecret(sharedTuple_t sharedTuple,publicParams_t publicParams){
    mpz_t temp,temp1,tempB;
    mpz_init2(temp,maxBitLength*2);
    mpz_init2(temp1,maxBitLength);
    mpz_init2(tempB,maxBitLength*3);

    mpz_set_ui(tempB,1);
    int i;
    for(i=0;i<securityParam;i++){        
        mpz_mul(tempB,sharedTuple.B[i],tempB);  
    }
    mpz_mod(tempB,tempB,publicParams.p);

    int result;

    result = mpz_cmp(tempB,sharedTuple.G);
    return result;
}

int ValidateStreamValue(sharedTuple_t sharedTuple){
  
}

void ComputeBlindR(blindedsecretKey_t blindedR,sharedTuple_t sharedTuple1,sharedTuple_t sharedTuple2 ,secretKey_t secretKey,publicParams_t publicParams){
    mpz_init2(blindedR,maxBitLength);

    mpz_t temp;
    mpz_init2(temp,maxBitLength*2);

    mpz_invert(temp,sharedTuple2.Q,publicParams.p);
    mpz_mul(temp,sharedTuple1.Q,temp);
    mpz_powm(blindedR,temp,secretKey,publicParams.p);
}

void ComputeDHSharedR(sharedKey_t sharedR,blindedsecretKey_t blindedR,secretKey_t secretKey,publicParams_t publicParams){
    mpz_init2(sharedR,maxBitLength);
    mpz_powm(sharedR,blindedR,secretKey,publicParams.p);
}

int CompareNonDisclosedData(sharedTuple_t sharedTuple1,sharedTuple_t sharedTuple2,secretKey_t e1,secretKey_t e2,sharedKey_t sharedR,publicParams_t publicParams){
    mpz_t v1,v2;
    mpz_init2(v1,maxBitLength*2);
    mpz_init2(v2,maxBitLength*2);

    mpz_invert(v1,sharedTuple2.G,publicParams.p);
    mpz_mul(v1,sharedTuple1.G,v1);
    mpz_mod(v1,v1,publicParams.p);

    mpz_sub(v2,e1,e2);
    mpz_powm(v2,publicParams.g0,v2,publicParams.p);
    mpz_mul(v2,v2,sharedR);
    mpz_mod(v2,v2,publicParams.p);

    int result;
    result = mpz_cmp(v1,v2);
    return result;
}

