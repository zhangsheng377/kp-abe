//============================================================================
// Name        : Encryption.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "Tree.h"
#include "Node.h"
#include "gmp.h"
#include <aesrand.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include "clt13.h" //调用pbc库
#include "pp.h"
//#include<process.h>  
#include <time.h>

#define LIBSO_FILE ("libclt13.so")//linux加载库的
mpz_t z; //Master Key
int debugrnqs;
int debugr1;
int debugr2;
int debugaw;
int debugbw;

static void setUp(publicKey *pk, int serParam, int attrNumberz, int denth) {
	//Group //denth:群组的个数.数的层数加一 initalize serparam：安全参数:人，初始化/库需要的东西,attrNumberz:系统属性个数.denth:电路最大深度
	ulong default_flags = CLT_FLAG_NONE | CLT_FLAG_VERBOSE;
	int begin, end;//定义开始和结束标志位 
	begin=clock();//开始计时
	int kappa = denth;
	int lambda = 10;
	int pows[kappa], top_level[kappa];       //use for Mulitilinear Map
	clt_state_t *sk;  							//Mulitilinear Map sercert key
	clt_pp_t *pp;                                //Mulitilinear Map Public key
	aes_randstate_t rng;
	aes_randinit(rng);
	for (int k = 0; k < kappa; k++) {
		top_level[k] = kappa;
	}
	
	clt_params_t params = {
        .lambda = lambda,
        .kappa = kappa,
        .nzs = kappa,
        .pows = top_level,
    };
    sk = clt_state_new(&params, NULL, 0, default_flags, rng);
	pp = clt_pp_new(sk);

	srand((unsigned) time(NULL));

	//initalie element  即 初始化gk阿发（pk->encodingOfa） 初始化h1到hn（pk->attribute[i]）
	for (int i = 0; i < attrNumberz; i++) {
		mpz_init(pk->attribute[i]);
	}
	//random master key a; //随机生成阿发，主密钥是阿发/gk-1阿发方，这里是阿发
	mpz_init_set_ui(z, (rand()%100) + 1);
	clt_encode(pk->encodingOfa, sk, 1, &z, top_level);//生成gk的啊法方
	gmp_printf("The public gk^a=");       //输出一：gk^a
	clt_elem_print(pk->encodingOfa);
	gmp_printf("\n");

	for (int k = 0; k < kappa; k++) {
		pows[k] = 1;
	}
	mpz_t temp;
	mpz_init(temp);
	for (int i = 0; i < attrNumberz; i++) {
		mpz_set_ui(temp, (rand()%100)+1);
		clt_encode((clt_elem_t*)pk->attribute[i], sk, 1, &temp, pows);
		gmp_printf("The public h%d=%Zd\n", i, pk->attribute[i]);// 输出二：随机产生h1......hn
	}
	aes_randclear(rng);
	mpz_clear(temp);

	pk->attrNumber = attrNumberz;
	pk->pp = pp;
	pk->sk = sk;
	pk->top_level = kappa;
	end=clock();//结束计时 
	printf("setup time is %d\n", end-begin);//差为时间，单位毫秒  
	printf("*********setUp() Complete!!!***************************************************\n");
	 
}

static void encrypt(CT* ct, publicKey * pk, int * att, int M) {
	//initalize elements
	for (int k = 0; k < pk->attrNumber; k++) {
		mpz_inits(ct->ci[k], NULL);
	}
	int pows_one[pk->top_level];
	for (int i = 0; i < pk->top_level; i++) {
		pows_one[i] = 1;
	}

	mpz_t result, temp1;
	mpz_inits(result, temp1, ct->gs, ct->CM, NULL);
	int s = (rand()%100)+1;                          //产生随机数s 属于Zp
	mpz_set_ui(temp1, s);
	clt_encode((clt_elem_t*)ct->gs, pk->sk, 1, &temp1, pows_one);  //g^s
	clt_elem_mul_ui((clt_elem_t*)result, pk->pp, pk->encodingOfa, s);//(gk阿发)s次方
	mpz_t codeM, mmm;
	mpz_inits(codeM, NULL);
	mpz_init_set_ui(mmm, M);
	int top_level[pk->top_level];
	for (int i = 0; i < pk->top_level; i++) {
		top_level[i] = pk->top_level;
	}
	clt_encode((clt_elem_t*)codeM, pk->sk, 1, &mmm, top_level);//输入的明文M
	clt_elem_add((clt_elem_t*)ct->CM, pk->pp, (clt_elem_t*)result, (clt_elem_t*)codeM);//M*(gk阿发)s次方
     //这两个循环就是得到V i属于s，Ci=hi的s方
	for (int i = 0; i < pk->attrNumber; i++) {
		if (att[i] == 1) {
			clt_elem_mul_ui((clt_elem_t*)ct->ci[i], pk->pp, (clt_elem_t*)pk->attribute[i], s);  //h1到hn的s方，放到ci[]里面
		}
	}
	//下面三个输出就是加密的密文全部内容，cm密文，g的s方，以及c[i]=hi的s方
	gmp_printf("Cm=%Zd\n", ct->CM);
	gmp_printf("gs=%Zd\n", ct->gs);
	for (int i = 0; i < pk->attrNumber; i++) {
		gmp_printf("c[%d]=%Zd\n", i, ct->ci[i]);
	}

	ct->attrNumber = pk->attrNumber;

	printf("*********Encrypt() Complete********************************************\n");

}
static int depth(Node * curr) {
	int dep = 1;
	while (curr->leftsons != NULL) {
		dep++;
		curr = curr->leftsons;
	}
	return dep;
}

static void keyGen(ssk* gssk, Tree * tree, publicKey *pk) {
	int nodenumber = tree->nodeNumb;
	for (int i = 0; i < gssk->nodeNumber * 4; i++) {
		mpz_init(gssk->skUnion[i]);   //初始化存储输出节点，与门，或门的 关键组件kw的数组
	}
	long rs[nodenumber];
	for (int i = 0; i < nodenumber; i++) {
		long s = (rand()%10)+1;
		rs[i] = s;  //random value of every node 随机产生r1....rn+q
	}
	//输出随机产生的r1....rn+q
	/*for (int i = 0; i <nodenumber; i++) {   
		gmp_printf("rs[%d]=%Zd\n", i, rs[i]);
	}*/
	debugrnqs=rs[0]; //This is debug code
	int pows[pk->top_level];
	for (int k = 0; k < pk->top_level; k++) {
		pows[k] = pk->top_level - 1;
	}
	mpz_t rnq, temp1, temp2;
	mpz_inits(rnq, gssk->kh, temp1, temp2, NULL);
	mpz_set_ui(rnq, rs[0]);
	clt_encode((clt_elem_t*)temp1, pk->sk, 1, &rnq, pows); //temp1=gk-1^rnq
	clt_encode((clt_elem_t*)temp2, pk->sk, 1, &z, pows); //temp2=gk-1^a
	clt_elem_sub((clt_elem_t*)gssk->kh, pk->pp, (clt_elem_t*)temp2, (clt_elem_t*)temp1);//Kh=temp1/temp2    得到头部密钥Kh
	mpz_clears(rnq, temp1, temp2, NULL);

	Node* quence[nodenumber];  //The container visit the tree
	quence[0] = tree->root;
	int index = 0; // the index of the visited node
	int had = 1;
	Node* pz = NULL;
	int powsOne[pk->top_level];
	int powsdepth[pk->top_level];
	for (int i = 0; i < pk->top_level; i++) {
		powsOne[i] = 1;
	}
	mpz_t aw;
	mpz_init(aw);
	mpz_t bw;
	mpz_init(bw);
	int storeplace = 0;
	do {
		pz = quence[index++];
		
		int awint=(rand()%1000)+1;
		int bwint =(rand()%1000)+1;			

		mpz_set_ui(aw, awint);
		mpz_set_ui(bw, bwint);
		int dep = depth(pz);
		for (int i = 0; i < pk->top_level; i++) {
			powsdepth[i] = dep;
		}
		int place = pz->index - 1;   //root->index=1;
		long kaz = rs[place];
		mpz_t rw;
		mpz_init_set_ui(rw, kaz);
		if (pz->Nodetype == 1) {   //and 与门三个关键组件
			gssk->skStartIndex[place] = storeplace; //describe the sercert key element start place  存当前节点位置，每存一个关键组件到skUnition,storeplace++
			clt_encode((clt_elem_t*)gssk->skUnion[storeplace++], pk->sk, 1, &aw, powsOne); //g^aw  组件一
			clt_encode((clt_elem_t*)gssk->skUnion[storeplace++], pk->sk, 1, &bw, powsOne); //g^bw  组件二

			mpz_t codeaw, codebw, coderw;
			mpz_inits(codeaw, codebw, coderw, NULL);
			clt_encode((clt_elem_t*)codeaw, pk->sk, 1, &aw, powsdepth); //gj^aw
			clt_encode((clt_elem_t*)codebw, pk->sk, 1, &bw, powsdepth); //gj^bw
			clt_encode((clt_elem_t*)coderw, pk->sk, 1, &rw, powsdepth); //gj^rw
			clt_elem_mul_ui((clt_elem_t*)codeaw, pk->pp, (clt_elem_t*)codeaw,
					rs[pz->leftsons->index - 1]); //gj^(aw*r1) 
			clt_elem_mul_ui((clt_elem_t*)codebw, pk->pp, (clt_elem_t*)codebw,
					rs[pz->rightson->index - 1]);
			clt_elem_sub((clt_elem_t*)coderw, pk->pp, (clt_elem_t*)coderw, (clt_elem_t*)codeaw);//gj^(bw*r2)
			clt_elem_sub((clt_elem_t*)gssk->skUnion[storeplace++], pk->pp, (clt_elem_t*)coderw, (clt_elem_t*)codebw); //gj^(rw-aw*r1-bw*r2) 组件三
			mpz_clears(codeaw, codebw, coderw, NULL);
		}
		if (pz->Nodetype == 2) {	//or  或门四个关键组件
			gssk->skStartIndex[place] = storeplace;
			clt_encode((clt_elem_t*)gssk->skUnion[storeplace++], pk->sk, 1, &aw, powsOne);//g^aw  组件一
			clt_encode((clt_elem_t*)gssk->skUnion[storeplace++], pk->sk, 1, &bw, powsOne);//g^bw  组件二
			mpz_t codeaw, codebw, coderw;
			mpz_inits(codeaw, codebw, coderw, NULL);
			clt_encode((clt_elem_t*)codeaw, pk->sk, 1, &aw, powsdepth); //gj^aw
			clt_encode((clt_elem_t*)codebw, pk->sk, 1, &bw, powsdepth); //gj^bw
			clt_encode((clt_elem_t*)coderw, pk->sk, 1, &rw, powsdepth); //gj^rw
			clt_elem_mul_ui((clt_elem_t*)codeaw, pk->pp, (clt_elem_t*)codeaw,
					rs[pz->leftsons->index - 1]);//gj^(aw*r1)
			clt_elem_mul_ui((clt_elem_t*)codebw, pk->pp, (clt_elem_t*)codebw,
					rs[pz->rightson->index - 1]);//gj^(bw*r2)
			clt_elem_sub((clt_elem_t*)gssk->skUnion[storeplace++], pk->pp, (clt_elem_t*)coderw, (clt_elem_t*)codeaw);//gj^(rw-aw*r1) 组件三
			clt_elem_sub((clt_elem_t*)gssk->skUnion[storeplace++], pk->pp, (clt_elem_t*)coderw, (clt_elem_t*)codebw);//gj^(rw-bw*r2) 组件四
			mpz_clears(codeaw, codebw, coderw, NULL);
		}
		if (pz->Nodetype >= 3) {	//attr  输入导线2个关键组件
			gssk->skStartIndex[place] = storeplace;
			int attributeindex = pz->Nodetype - 3;
			int randzw = (rand()%100)+1;
			mpz_t  temp, temp2, temp3;
			mpz_inits(temp, temp2, NULL);
			mpz_init_set_ui(temp3, randzw);

			clt_elem_mul_ui((clt_elem_t*)temp, pk->pp, (clt_elem_t*)pk->attribute[attributeindex],randzw); //temp=hw^zw
			clt_encode((clt_elem_t*)temp2, pk->sk, 1, &rw, powsOne); //temp2=g^rw
			clt_elem_add((clt_elem_t*)gssk->skUnion[storeplace++], pk->pp, (clt_elem_t*)temp2, (clt_elem_t*)temp);  //g^(rw)*hw^zw  组件一
			clt_encode((clt_elem_t*)gssk->skUnion[storeplace++], pk->sk, 1, &temp3, powsOne);//g^(-zw)    组件二

		}
		if (pz->leftsons != NULL) {
			quence[had++] = pz->leftsons;
		}
		if (pz->rightson != NULL) {
			quence[had++] = pz->rightson;
		}
	} while (index != had);
	//输出每个节点存储的关键密钥
	for (int i = 0; i < storeplace; i++) {
		gmp_printf("skUnion[%d]=%Zd\n", i, gssk->skUnion[i]);
	}
	printf("*********KeyGen() Complete********************************************\n");


}

static int evaluate(mpz_t ele, Node * p, ssk* ssk, CT*ct, publicKey* pk) {

	if (p->Nodetype >= 3) {//输入导线
		int attrIndex = p->Nodetype - 3;
		int isZero = mpz_cmp_d(ct->ci[attrIndex],0);   //？？？？？？
		if(isZero != 0){
			int index = p->index - 1;
			int skStartIndex = ssk->skStartIndex[index];
			mpz_t kw1, kw2;
			mpz_inits(kw1, kw2, NULL);
			clt_elem_mul((clt_elem_t*)kw1, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex++], (clt_elem_t*)ct->gs);//e(k(w,1),g^s)
			clt_elem_mul((clt_elem_t*)kw2, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex], (clt_elem_t*)ct->ci[attrIndex]);//e(k(w,2),hw^s)
			clt_elem_sub((clt_elem_t*)ele, pk->pp, (clt_elem_t*)kw1, (clt_elem_t*)kw2); //ele=e(k(w,1),g^s)*e(k(w,2),hw^s) 
			return 1;
		}else{
			return 0;
		}
	}
	if (p->Nodetype == 1) { //and
		 
		int index = p->index - 1;
		int skStartIndex = ssk->skStartIndex[index];
		mpz_t kw1, kw2, kw3, aw, bw,temp;
		mpz_inits(kw1, kw2, kw3, aw, bw,temp, NULL);
		int validleft = evaluate(aw, p->leftsons, ssk, ct, pk);
		int validright = evaluate(bw, p->rightson, ssk, ct, pk);

		if(validleft==1&&validright==1){
			clt_elem_mul((clt_elem_t*)kw1, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex++], (clt_elem_t*)aw);//e(k(w,1),Eaw)
			clt_elem_mul((clt_elem_t*)kw2, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex++], (clt_elem_t*)bw);//e(k(w,2),Ebw)
			clt_elem_mul((clt_elem_t*)kw3, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex], (clt_elem_t*)ct->gs);//e(k(w,3),g^s)
			clt_elem_add((clt_elem_t*)temp, pk->pp, (clt_elem_t*)kw1, (clt_elem_t*)kw2);
			clt_elem_add((clt_elem_t*)ele, pk->pp, (clt_elem_t*)temp, (clt_elem_t*)kw3);//ele=e(k(w,1),Eaw)*e(k(w,2),Ebw)*e(k(w,3),g^s)  即得到Ew
			return 1;
		}else{
			return 0;
		}
	}
	if (p->Nodetype == 2) {//or
		int index = p->index - 1;
		int skStartIndex = ssk->skStartIndex[index];
		mpz_t kw1, kw2,aw,bw;
		mpz_inits(kw1, kw2, aw, bw,NULL);
		int validleft = evaluate(aw, p->leftsons, ssk, ct, pk);
		if(validleft==1){
			clt_elem_mul((clt_elem_t*)kw1, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex], (clt_elem_t*)aw);//e(k(w,1),Eaw)
			clt_elem_mul((clt_elem_t*)kw2, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex+2], (clt_elem_t*)ct->gs);//e(k(w,3),g^s)
			clt_elem_add((clt_elem_t*)ele, pk->pp, (clt_elem_t*)kw1, (clt_elem_t*)kw2);                        //e(k(w,1),Eaw)*e(k(w,3),g^s)
			return 1;
		}
		int validright = evaluate(bw, p->rightson, ssk, ct, pk);
		if(validright==1){
			clt_elem_mul((clt_elem_t*)kw1, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex+1], (clt_elem_t*)bw);//e(k(w,2),Ebw)
			clt_elem_mul((clt_elem_t*)kw2, pk->pp, (clt_elem_t*)ssk->skUnion[skStartIndex+3], (clt_elem_t*)ct->gs);//e(k(w,4),g^s)
			clt_elem_add((clt_elem_t*)ele, pk->pp, (clt_elem_t*)kw1, (clt_elem_t*)kw2);                       //e(k(w,2),Ebw)*e(k(w,4),g^s)
			return 1;
		}
		return 0;
	}

}

static int decrypt(mpz_t result, ssk* ssk, CT*ct, int * attribute, Tree * tree,
		publicKey* pk) {
	mpz_t E, rnqs;
	mpz_inits(E, rnqs, NULL);

	int aa = evaluate(rnqs, tree->root, ssk, ct, pk);// rnqs=gk^rnqs
	if(aa==1){
		clt_elem_mul((clt_elem_t*)E, pk->pp, (clt_elem_t*)ssk->kh, (clt_elem_t*)ct->gs);//e'=e(KH,g^s)
		clt_elem_add((clt_elem_t*)E, pk->pp, (clt_elem_t*)E, (clt_elem_t*)rnqs);        //E=e(KH,g^s)*(gk^rnqs)=gk^(as-rnqs)*gk^rnqs=gk^as
		clt_elem_sub((clt_elem_t*)result, pk->pp, (clt_elem_t*)ct->CM, (clt_elem_t*)E); //result=CM/E=CM/gk^as     result就是解密出来的东西
		return 1;
	}
	return 0;

}

int main() {

	Node* a0 = new Node();
	Node* a1 = new Node();
	Node* root = new Node();
	a0->setType(3);//attribute
	a0->index = 2;
	a1->setType(4);//attribute
	a1->index = 3;
	root->setType(1);//and

//	root->setType(2);//or

	root->index = 1;
	root->setleftsons(a0);
	root->setrightson(a1);
	a0->setParent(root);
	a1->setParent(root);

	publicKey* pk = new publicKey(5);
	setUp(pk, 10, 5, 3);


// new !!!
	int encattr[5] = { 1, 1, 0, 0, 0}; //can decrypt   系统属性个数==用户的属性个数
//	int encattr[5] = { 1, 0, 0, 0, 0};	//can not decrypt

	CT * ct = new CT(5);

    	int M;
	printf("please input M:");
	scanf("%d",&M);
	encrypt(ct, pk, encattr, M);


	Tree *tree = new Tree();
	tree->root = root;
	tree->nodeNumb = 3;
	ssk * sk = new ssk(tree->nodeNumb);//真正的私钥
	keyGen(sk, tree, pk);

	clt_elem_t *result = clt_elem_new();
	
	//new !!! remove the encattr1
	int isresultValid = decrypt((MP_INT*)result, sk, ct, encattr, tree, pk);

	if(isresultValid==1){
		clt_elem_print(result);

		int top_level[pk->top_level];  //top_level=3
		for (int i = 0; i < pk->top_level; i++) {
			top_level[i] = pk->top_level;
		}
		mpz_t ten, codeTen; mpz_inits(codeTen,ten,NULL);
		int pazz=0; int message=0;
		do{
			
			mpz_set_ui(ten, pazz);
			clt_encode((clt_elem_t*)codeTen, pk->sk, 1, &ten, top_level);  //g^0
			clt_elem_sub((clt_elem_t*)codeTen, pk->pp, (clt_elem_t*)codeTen, result);    //g^0/result
			if(clt_is_zero((clt_elem_t*)codeTen, pk->pp)==1){
				message=pazz;break;
			}else{
			pazz++;
			}
		}while(true);
		printf("\nThe Message is %d\n",message);

	}else{
		printf("\nCan not decrypt the message!!\n");
	}
	


}

