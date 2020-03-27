/*
 * pp.h
 *
 *  Created on: 2018骞?3鏈?14鏃?
 *      Author: root
 */

#include "Node.h"
#include "clt13.h"
#include "gmp.h"
using namespace std;

class publicKey {
public:
	int top_level;
	int attrNumber;
	clt_pp_t * pp;
	clt_state_t *sk;
	mpz_t *attribute;//存h1 到hn,是属性需要的东西
	clt_elem_t *encodingOfa;//gk的阿发
	publicKey() {
	}
	publicKey(int attrNumber) {
		this->attrNumber = attrNumber;
		attribute = (mpz_t*) malloc(sizeof(mpz_t) * attrNumber);
		encodingOfa = clt_elem_new();

		printf("publicKey init****************************************\n");
	}

	~publicKey() {
		if (pp != NULL) {
			clt_pp_free(pp);
		}
		if (sk != NULL) {
			clt_state_free(sk);
		}
		if (encodingOfa != NULL) {
			clt_elem_free(encodingOfa);
		}
		if (attribute != NULL) {
			free(attribute);
		}
	}

};
class CT {
public:
	mpz_t CM;
	mpz_t gs;
	mpz_t* ci;
	int attrNumber;
	CT(int attrNumber) {
		this->attrNumber = attrNumber;
		ci = (mpz_t*) malloc(sizeof(mpz_t) * attrNumber);
	}

	~CT() {

		if (CM != NULL) {
			mpz_clears(CM, NULL);
		}
		if (gs != NULL) {
			mpz_clears(gs, NULL);
		}
		if(ci!=NULL){
			free(ci);
		}

	}

};
class ssk {
public:
	int nodeNumber;
	mpz_t kh;
	mpz_t *skUnion;//放每个输入，节点的kw
	int * skStartIndex;
	ssk(){}
	ssk(int nodeNumber){
		this->nodeNumber= nodeNumber;
		skUnion=(mpz_t*) malloc(sizeof(mpz_t) * nodeNumber*4);
		skStartIndex = (int *)malloc(sizeof(int)*nodeNumber);
	}
	~ssk(){
		if(kh!=NULL){
			mpz_clears(kh,NULL);
		}
		if(skUnion!=NULL){
			free(skUnion);
		}
		if(skStartIndex!=NULL){
			free(skStartIndex);

		}


	}

};

