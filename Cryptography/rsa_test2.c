/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a) {
	/* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main () {
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *o = BN_new();
	BIGNUM *p1 = BN_new();
	BIGNUM *q1 = BN_new();
	BIGNUM *one_val = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *c = BN_new();
	
	//BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	//BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "010001");
	BN_dec2bn(&one_val, "1");
	BN_hex2bn(&m, "4120746f702073656372657421"); //hex for message "A top secret!"
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	
	//BN_sub(p1, p, one_val);
	//BN_sub(q1, q, one_val);
	
	//BN_mul(n, p, q, ctx);
	//BN_mul(o, p1, q1, ctx);
	//BN_mod_inverse(d, e, o, ctx);
	BN_mod_exp(c, m, e, n, ctx);
	
	printBN("c = ", c);
	
	BN_mod_exp(m, c, d, n, ctx);
	
	printBN("m = ", m);
	
	return 0;
}
