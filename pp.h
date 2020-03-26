/*
 * pp.h
 *
 *  Created on: 2018å¹´3æœˆ14æ—¥
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
	clt_pp * pp;
	clt_state *sk;
	mpz_t *attribute;//´æh1 µ½hn,ÊÇÊôÐÔÐèÒªµÄ¶«Î÷
	mpz_t encodingOfa;//gkµÄ°¢·¢
	publicKey() {
	}
	publicKey(int attrNumber) {
		this->attrNumber = attrNumber;
		attribute = (mpz_t*) malloc(sizeof(mpz_t) * attrNumber);

		printf("publicKey init****************************************\n");
	}

	~publicKey() {
		if (pp != NULL) {
			clt_pp_delete(pp);
		}
		if (sk != NULL) {
			clt_state_delete(sk);
		}
		if (encodingOfa != NULL) {
			mpz_clears(encodingOfa, NULL);
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
	mpz_t *skUnion;//·ÅÃ¿¸öÊäÈë£¬½ÚµãµÄkw
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

