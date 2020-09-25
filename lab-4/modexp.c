#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main(int argc, char ** argv)
{
	BN_CTX * ctx = BN_CTX_new();
	BIGNUM * M = BN_new();
	BIGNUM * e = BN_new();
	BIGNUM * N = BN_new();
	BIGNUM * d = BN_new();
	BIGNUM * enc = BN_new();
	BIGNUM * dec = BN_new();

	BN_hex2bn(&M, argv[1]);
	BN_hex2bn(&N, argv[2]);
	BN_hex2bn(&e, argv[3]);
	//BN_hex2bn(&d, argv[4]);

	BN_mod_exp(enc, M, e, N, ctx);
	//printBN("Encrypted Message = ", enc);

	char * number_str = BN_bn2hex(enc);
	printf("%s\n", number_str);
	OPENSSL_free(number_str);
	//BN_mod_exp(dec, enc, d, N, ctx);
	//printBN("Decrypted Message = ", dec);

	return 0;

}