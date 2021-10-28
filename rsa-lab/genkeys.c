#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}


int main(int argc, char** argv) 
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM * p = BN_new();
	BIGNUM * q = BN_new();
	BIGNUM * e = BN_new();
	BIGNUM * d = BN_new();
	BIGNUM * N = BN_new();

	BIGNUM * res1 = BN_new();
	BIGNUM * res2 = BN_new();
	BIGNUM * res3 = BN_new();

	BIGNUM * one = BN_new();
        if (argc != 4) {
                fprintf(stderr, "invalid number of parameters.\n");
                return 1;
        }
	BN_hex2bn(&p, argv[1]);
	BN_hex2bn(&q, argv[2]);
	BN_hex2bn(&e, argv[3]);
	BN_dec2bn(&one, "1");

	BN_sub(res1, p, one);
	BN_sub(res2, q, one);

	BN_mul(res3, res1, res2, ctx);

	BN_mod_inverse(d, e, res3, ctx);
	//printBN("d = ", d);

	BN_mul(N, p, q, ctx);


	printBN("N = ", N);
	printBN("e = ", e);
	printBN("d = ", d);

	return 0;
}
