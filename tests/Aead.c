#include <stdio.h>
#include <stdlib.h>

#include "Aead.h"

int main(int argc, char *argv[])
{
	unsigned char buf[100] = "", buf_out[100];
	int res = EXIT_FAILURE, ret;
	size_t i, size, size_out;
	struct Aead *alice, *bob;
	unsigned char alice_iv[4] = {0x1, 0x2, 0x3, 0x4}, alice_key[16] = {0x11, 0x22, 0x33, 0x44};
	unsigned char bob_iv[4] = {0x6, 0x7, 0x8, 0x9}, bob_key[16] = {0x66, 0x77, 0x88, 0x99};

	/* Create */
	alice = Aead(bob_key, sizeof bob_key,
		     alice_key, sizeof alice_key,
		     bob_iv, sizeof bob_iv,
		     alice_iv, sizeof alice_iv);
	if (alice == NULL) {
		perror("Aead (alice)");
		goto out;
	}

	bob = Aead(alice_key, sizeof alice_key,
		   bob_key, sizeof bob_key,
		   alice_iv, sizeof alice_iv,
		   bob_iv, sizeof bob_iv);
	if (bob == NULL) {
		perror("Aead (bob)");
		goto out_free_aead_alice;
	}

	/* Forward */
	size = sizeof buf;
	ret = Aead_Seal(alice, (unsigned char *) "foobar", 6, 42,
			(unsigned char *) "aad", 3,
			buf, &size);
	if (ret < 0) {
		perror("Aead_Seal (alice)");
		goto out_free_aead_bob;
	}

	printf("Encrypted (alice):\n");
	for (i = 0; i < size; i++)
		printf("%02hhx ", buf[i]);
	putchar('\n');

	size_out = sizeof buf_out;
	ret = Aead_Open(bob, buf, size, 42,
			(unsigned char *) "aad", 3,
			buf_out, &size_out);
	if (ret < 0) {
		perror("Aead_Open (bob)");
		goto out_free_aead_bob;
	}

	printf("Decrypted (bob):\n");
	for (i = 0; i < size_out; i++)
		printf("%02hhx ", buf_out[i]);
	putchar('\n');

	putchar('\n');

	/* Reverse */
	size = sizeof buf;
	ret = Aead_Seal(bob, (unsigned char *) "foobar", 6, 42,
			(unsigned char *) "aad", 3,
			buf, &size);
	if (ret < 0) {
		perror("Aead_Seal (bob)");
		goto out_free_aead_bob;
	}

	printf("Encrypted (bob):\n");
	for (i = 0; i < size; i++)
		printf("%02hhx ", buf[i]);
	putchar('\n');

	size_out = sizeof buf_out;
	ret = Aead_Open(alice, buf, size, 42,
			(unsigned char *) "aad", 3,
			buf_out, &size_out);
	if (ret < 0) {
		perror("Aead_Open (alice)");
		goto out_free_aead_bob;
	}

	printf("Decrypted (alice):\n");
	for (i = 0; i < size_out; i++)
		printf("%02hhx ", buf_out[i]);
	putchar('\n');

	res = EXIT_SUCCESS;

out_free_aead_bob:
	Aead_Free(bob);
out_free_aead_alice:
	Aead_Free(alice);
out:
	return res;
}
