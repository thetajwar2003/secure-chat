#include "util.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

// Provide equivalent macros if needed
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)

#else
// Assume a POSIX-compliant system (Linux, etc.)
#include <endian.h>
#endif

/* when reading long integers, never read more than this many bytes: */
#define MPZ_MAX_LEN 1024

/* Like read(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xread(int fd, void *buf, size_t nBytes)
{
	do
	{
		ssize_t n = read(fd, buf, nBytes);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno == EWOULDBLOCK)
			continue;
		if (n < 0)
			perror("read"), abort();
		buf = (char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

/* Like write(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xwrite(int fd, const void *buf, size_t nBytes)
{
	do
	{
		ssize_t n = write(fd, buf, nBytes);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno == EWOULDBLOCK)
			continue;
		if (n < 0)
			perror("write"), abort();
		buf = (const char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

size_t serialize_mpz(int fd, mpz_t x)
{
	/* format:
	 * +--------------------------------------------+---------------------------+
	 * | nB := numBytes(x) (little endian, 4 bytes) | bytes(x) (l.e., nB bytes) |
	 * +--------------------------------------------+---------------------------+
	 * */
	/* NOTE: for compatibility across different systems, we always write integers
	 * little endian byte order when serializing.  Note also that mpz_sizeinbase
	 * will return 1 if x is 0, so nB should always be the correct byte count. */
	size_t nB;
	unsigned char *buf = Z2BYTES(NULL, &nB, x);
	/* above has allocated memory for us, and stored the size in nB.  HOWEVER,
	 * if x was 0, then no allocation would be done, and buf will be NULL: */
	if (!buf)
	{
		nB = 1;
		buf = malloc(1);
		*buf = 0;
	}
	assert(nB < 1LU << 32); /* make sure it fits in 4 bytes */
	LE(nB);
	xwrite(fd, &nB_le, 4);
	xwrite(fd, buf, nB);
	free(buf);
	return nB + 4; /* total number of bytes written to fd */
}

int deserialize_mpz(mpz_t x, int fd)
{
	/* we assume buffer is formatted as above */
	uint32_t nB_le;
	xread(fd, &nB_le, 4);
	size_t nB = le32toh(nB_le);
	if (nB > MPZ_MAX_LEN)
		return -1;
	unsigned char *buf = malloc(nB);
	xread(fd, buf, nB);
	BYTES2Z(x, buf, nB);
	return 0;
}

void generate_rsa_keys(const char *private_filename, const char *public_filename)
{
	RSA *rsa = NULL;
	BIGNUM *bignum = BN_new();
	BN_set_word(bignum, RSA_F4);
	rsa = RSA_new();
	RSA_generate_key_ex(rsa, 4096, bignum, NULL);

	// Writing the private key
	FILE *fp = fopen(private_filename, "wb");
	if (!fp)
	{
		perror("Unable to open file for writing private key");
		RSA_free(rsa);
		BN_free(bignum);
		return;
	}
	PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
	fclose(fp);

	// Writing the public key
	fp = fopen(public_filename, "wb");
	if (!fp)
	{
		perror("Unable to open file for writing public key");
		RSA_free(rsa);
		BN_free(bignum);
		return;
	}
	PEM_write_RSA_PUBKEY(fp, rsa);
	fclose(fp);

	RSA_free(rsa);
	BN_free(bignum);
}