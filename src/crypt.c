/* crypt -	`mbedtls enc` / `mbedtls dec` : symmetric authenticated file
 *				encryption for mbedtls-clu. DRAFT for the Gargoyle
 *				encrypted-backup feature (RFC #117).
 *
 *				AES-256-GCM (authenticated) with a PBKDF2-HMAC-SHA256-derived
 *				key. Wrong passphrase or tampered file fails on the GCM tag
 *				rather than producing silent garbage. Whole-input buffering so
 *				decryption NEVER writes unverified plaintext: the tag is
 *				checked before a single output byte is emitted (avoids the
 *				release-of-unverified-plaintext problem when the output is
 *				piped straight into `tar x`). A backup tarball is config-sized
 *				(well under router RAM); a future streaming/temp-file variant
 *				could lift the in-memory size ceiling if ever needed.
 *
 *			Intended for lantis1008/mbedtls-clu.
 *
 * Copyright © 2026, distributed under the GNU GPL v2 or later (matching the
 * rest of mbedtls-clu). No warranty; see the project LICENSE.
 *
 * On-disk format (little in it is secret; the whole header is authenticated
 * as GCM additional data so its fields cannot be tampered with):
 *
 *   off  size  field
 *   0    8     magic            "GARGENC1"
 *   8    1     version          0x01
 *   9    1     kdf id           0x01 = PBKDF2-HMAC-SHA256
 *   10   1     cipher id        0x01 = AES-256-GCM
 *   11   1     reserved         0x00
 *   12   4     kdf iterations   uint32 big-endian
 *   16   16    kdf salt         random per encryption
 *   32   12    gcm nonce/iv     random per encryption
 *   ---- 44-byte header (all of the above is the GCM AAD) ----
 *   44   L     ciphertext       same length L as the plaintext
 *   44+L 16    gcm auth tag
 */

#include "crypt.h"
#include <fcntl.h>
#include <unistd.h>
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"   /* mbedtls_platform_zeroize */

#define CRYPT_MAGIC       "GARGENC1"
#define CRYPT_MAGIC_LEN   8
#define CRYPT_VERSION     0x01
#define CRYPT_KDF_PBKDF2  0x01
#define CRYPT_CIPHER_GCM  0x01
#define CRYPT_HDR_LEN     44
#define CRYPT_SALT_LEN    16
#define CRYPT_IV_LEN      12
#define CRYPT_TAG_LEN     16
#define CRYPT_KEY_BITS    256
#define CRYPT_KEY_LEN     32
#define CRYPT_DFL_ITER    200000     /* one-off op; ~1-2s on a weak router CPU */
#define CRYPT_MAX_PASS    1024
#define CRYPT_READ_CHUNK  65536

#define ENC_USAGE \
	"\n usage: enc [options]\n"                                                              \
	"\n\n Options:\n"                                                                        \
	"    -help                    Display this summary\n"                                    \
	"    -pass <source>           Passphrase source: env:VAR | file:PATH | fd:N | stdin\n"   \
	"    -iter <n>                PBKDF2 iterations (default 200000)\n"                       \
	"    -in <path>               Input plaintext (default: stdin)\n"                        \
	"    -out <path>              Output ciphertext (default: stdout)\n"

#define DEC_USAGE \
	"\n usage: dec [options]\n"                                                              \
	"\n\n Options:\n"                                                                        \
	"    -help                    Display this summary\n"                                    \
	"    -pass <source>           Passphrase source: env:VAR | file:PATH | fd:N | stdin\n"   \
	"    -in <path>               Input ciphertext (default: stdin)\n"                       \
	"    -out <path>              Output plaintext (default: stdout)\n"

#if !defined(MBEDTLS_GCM_C) || !defined(MBEDTLS_PKCS5_C) || \
	!defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_ENTROPY_C) || \
	!defined(MBEDTLS_MD_C)
int enc_main(int argc, char** argv, int argi)
{
	(void) argc; (void) argv; (void) argi;
	mbedtls_printf("MBEDTLS_GCM_C / PKCS5_C / CTR_DRBG_C / ENTROPY_C / MD_C not defined.\n");
	return MBEDTLS_EXIT_FAILURE;
}
int dec_main(int argc, char** argv, int argi) { return enc_main(argc, argv, argi); }
#else

/* ---- small helpers ---------------------------------------------------- */

static void put_be32(unsigned char* p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)(v);
}
static uint32_t get_be32(const unsigned char* p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

/* Read a passphrase from -pass <source>. Never taken from argv directly (it
 * would be visible in ps). Trailing newline is stripped. Returns length, or
 * -1 on error. out must be CRYPT_MAX_PASS+1 bytes. */
static int read_passphrase(const char* source, char* out)
{
	int fd = -1, opened = 0, n, total = 0;
	const char* v;

	if (source == NULL) { return -1; }

	if (strncmp(source, "env:", 4) == 0) {
		v = getenv(source + 4);
		if (v == NULL) { return -1; }
		total = (int) strlen(v);
		if (total > CRYPT_MAX_PASS) { return -1; }
		memcpy(out, v, total);
	} else {
		if (strncmp(source, "file:", 5) == 0) {
			fd = open(source + 5, O_RDONLY);
			opened = 1;
		} else if (strncmp(source, "fd:", 3) == 0) {
			fd = atoi(source + 3);
		} else if (strcmp(source, "stdin") == 0) {
			fd = 0;
		} else {
			return -1;
		}
		if (fd < 0) { return -1; }
		while (total < CRYPT_MAX_PASS &&
		       (n = (int) read(fd, out + total, CRYPT_MAX_PASS - total)) > 0) {
			total += n;
		}
		if (opened) { close(fd); }
		if (n < 0) { return -1; }
	}
	/* strip a single trailing \n and/or \r */
	while (total > 0 && (out[total - 1] == '\n' || out[total - 1] == '\r')) { total--; }
	out[total] = '\0';
	if (total == 0) { return -1; }
	return total;
}

/* Slurp an fd fully into a malloc'd buffer. Returns length, buf via *out. */
static long slurp_fd(int fd, unsigned char** out)
{
	unsigned char* buf = NULL;
	long cap = 0, len = 0;
	int n;
	for (;;) {
		if (len + CRYPT_READ_CHUNK > cap) {
			unsigned char* nb;
			cap = (cap == 0) ? CRYPT_READ_CHUNK : cap * 2;
			nb = realloc(buf, cap);
			if (nb == NULL) { free(buf); return -1; }
			buf = nb;
		}
		n = (int) read(fd, buf + len, CRYPT_READ_CHUNK);
		if (n < 0) { free(buf); return -1; }
		if (n == 0) { break; }
		len += n;
	}
	*out = buf;
	return len;
}

static int write_all(int fd, const unsigned char* p, long len)
{
	long off = 0; int n;
	while (off < len) {
		n = (int) write(fd, p + off, len - off);
		if (n <= 0) { return -1; }
		off += n;
	}
	return 0;
}

/* seed a CTR_DRBG for salt/nonce generation */
static int seed_rng(mbedtls_ctr_drbg_context* ctr, mbedtls_entropy_context* ent)
{
	const char* pers = "mbedtls-clu-enc";
	mbedtls_ctr_drbg_init(ctr);
	mbedtls_entropy_init(ent);
	return mbedtls_ctr_drbg_seed(ctr, mbedtls_entropy_func, ent,
	                             (const unsigned char*) pers, strlen(pers));
}

/* ---- enc -------------------------------------------------------------- */

int enc_main(int argc, char** argv, int argi)
{
	int i, ret, exit_code = MBEDTLS_EXIT_FAILURE;
	char* pass_src = NULL;
	unsigned int iter = CRYPT_DFL_ITER;
	int in_fd = 0, out_fd = 1, in_opened = 0, out_opened = 0;
	char pass[CRYPT_MAX_PASS + 1];
	int pass_len = 0;
	unsigned char key[CRYPT_KEY_LEN];
	unsigned char hdr[CRYPT_HDR_LEN];
	unsigned char tag[CRYPT_TAG_LEN];
	unsigned char* plain = NULL;
	unsigned char* cipher = NULL;
	long plen = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_gcm_context gcm;

	mbedtls_gcm_init(&gcm);

	for (i = argi; i < argc; i++) {
		char* p = argv[i];
		if (strcmp(p, "-help") == 0) { mbedtls_printf(ENC_USAGE); goto exit; }
		else if (strcmp(p, "-pass") == 0 && i + 1 < argc) { pass_src = argv[++i]; }
		else if (strcmp(p, "-iter") == 0 && i + 1 < argc) { iter = (unsigned int) strtoul(argv[++i], NULL, 10); }
		else if (strcmp(p, "-in")  == 0 && i + 1 < argc) { in_fd = open(argv[++i], O_RDONLY); in_opened = 1; }
		else if (strcmp(p, "-out") == 0 && i + 1 < argc) { out_fd = open(argv[++i], O_WRONLY | O_CREAT | O_TRUNC, 0600); out_opened = 1; }
		else { mbedtls_printf(ENC_USAGE); goto exit; }
	}
	if (in_fd < 0 || out_fd < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: cannot open in/out file\n"); goto exit; }
	if (iter < 1000) { iter = 1000; }   /* floor: never accept a trivially weak KDF */

	pass_len = read_passphrase(pass_src, pass);
	if (pass_len < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: could not read passphrase (-pass env:VAR|file:PATH|fd:N|stdin)\n"); goto exit; }

	if ((ret = seed_rng(&ctr_drbg, &entropy)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: RNG seed failed: -0x%04x\n", (unsigned int) -ret);
		goto exit_rng;
	}

	/* build header: magic, version, ids, iter, then random salt + nonce */
	memcpy(hdr, CRYPT_MAGIC, CRYPT_MAGIC_LEN);
	hdr[8]  = CRYPT_VERSION;
	hdr[9]  = CRYPT_KDF_PBKDF2;
	hdr[10] = CRYPT_CIPHER_GCM;
	hdr[11] = 0x00;
	put_be32(hdr + 12, (uint32_t) iter);
	if ((ret = mbedtls_ctr_drbg_random(&ctr_drbg, hdr + 16, CRYPT_SALT_LEN)) != 0 ||
	    (ret = mbedtls_ctr_drbg_random(&ctr_drbg, hdr + 32, CRYPT_IV_LEN)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: RNG draw failed\n");
		goto exit_rng;
	}

	/* derive key = PBKDF2-HMAC-SHA256(pass, salt, iter) */
	if ((ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
	           (const unsigned char*) pass, (size_t) pass_len,
	           hdr + 16, CRYPT_SALT_LEN, iter, CRYPT_KEY_LEN, key)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: PBKDF2 failed: -0x%04x\n", (unsigned int) -ret);
		goto exit_rng;
	}

	plen = slurp_fd(in_fd, &plain);
	if (plen < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: read failed\n"); goto exit_rng; }
	cipher = malloc(plen > 0 ? plen : 1);
	if (cipher == NULL) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: out of memory\n"); goto exit_rng; }

	if ((ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, CRYPT_KEY_BITS)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: gcm_setkey failed: -0x%04x\n", (unsigned int) -ret);
		goto exit_rng;
	}
	/* whole header is the additional authenticated data (binds params) */
	if ((ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, (size_t) plen,
	           hdr + 32, CRYPT_IV_LEN, hdr, CRYPT_HDR_LEN,
	           plain, cipher, CRYPT_TAG_LEN, tag)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: encryption failed: -0x%04x\n", (unsigned int) -ret);
		goto exit_rng;
	}

	if (write_all(out_fd, hdr, CRYPT_HDR_LEN) != 0 ||
	    write_all(out_fd, cipher, plen) != 0 ||
	    write_all(out_fd, tag, CRYPT_TAG_LEN) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: write failed\n");
		goto exit_rng;
	}
	exit_code = MBEDTLS_EXIT_SUCCESS;

exit_rng:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
exit:
	mbedtls_platform_zeroize(key, sizeof(key));
	mbedtls_platform_zeroize(pass, sizeof(pass));
	if (plain)  { mbedtls_platform_zeroize(plain, (size_t) plen); free(plain); }
	if (cipher) { free(cipher); }
	mbedtls_gcm_free(&gcm);
	if (in_opened && in_fd >= 0) { close(in_fd); }
	if (out_opened && out_fd >= 0) { close(out_fd); }
	return exit_code;
}

/* ---- dec -------------------------------------------------------------- */

int dec_main(int argc, char** argv, int argi)
{
	int i, ret, exit_code = MBEDTLS_EXIT_FAILURE;
	char* pass_src = NULL;
	int in_fd = 0, out_fd = 1, in_opened = 0, out_opened = 0;
	char pass[CRYPT_MAX_PASS + 1];
	int pass_len = 0;
	unsigned char key[CRYPT_KEY_LEN];
	unsigned char* blob = NULL;
	unsigned char* plain = NULL;
	long blen = 0, clen = 0;
	unsigned int iter;
	const unsigned char* hdr;
	const unsigned char* cipher;
	const unsigned char* tag;
	mbedtls_gcm_context gcm;

	mbedtls_gcm_init(&gcm);

	for (i = argi; i < argc; i++) {
		char* p = argv[i];
		if (strcmp(p, "-help") == 0) { mbedtls_printf(DEC_USAGE); goto exit; }
		else if (strcmp(p, "-pass") == 0 && i + 1 < argc) { pass_src = argv[++i]; }
		else if (strcmp(p, "-in")  == 0 && i + 1 < argc) { in_fd = open(argv[++i], O_RDONLY); in_opened = 1; }
		else if (strcmp(p, "-out") == 0 && i + 1 < argc) { out_fd = open(argv[++i], O_WRONLY | O_CREAT | O_TRUNC, 0600); out_opened = 1; }
		else { mbedtls_printf(DEC_USAGE); goto exit; }
	}
	if (in_fd < 0 || out_fd < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: cannot open in/out file\n"); goto exit; }

	pass_len = read_passphrase(pass_src, pass);
	if (pass_len < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: could not read passphrase\n"); goto exit; }

	blen = slurp_fd(in_fd, &blob);
	if (blen < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: read failed\n"); goto exit; }
	if (blen < CRYPT_HDR_LEN + CRYPT_TAG_LEN ||
	    memcmp(blob, CRYPT_MAGIC, CRYPT_MAGIC_LEN) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: not a GARGENC1 file (bad magic or too short)\n");
		goto exit;
	}
	hdr = blob;
	if (hdr[8] != CRYPT_VERSION || hdr[9] != CRYPT_KDF_PBKDF2 || hdr[10] != CRYPT_CIPHER_GCM) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: unsupported version/kdf/cipher\n");
		goto exit;
	}
	iter   = get_be32(hdr + 12);
	clen   = blen - CRYPT_HDR_LEN - CRYPT_TAG_LEN;
	cipher = blob + CRYPT_HDR_LEN;
	tag    = blob + CRYPT_HDR_LEN + clen;

	if ((ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
	           (const unsigned char*) pass, (size_t) pass_len,
	           hdr + 16, CRYPT_SALT_LEN, iter, CRYPT_KEY_LEN, key)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: PBKDF2 failed\n");
		goto exit;
	}

	plain = malloc(clen > 0 ? clen : 1);
	if (plain == NULL) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: out of memory\n"); goto exit; }

	if ((ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, CRYPT_KEY_BITS)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: gcm_setkey failed\n");
		goto exit;
	}
	/* auth_decrypt verifies the tag over ciphertext + AAD(header); a wrong
	 * passphrase or any tampering returns MBEDTLS_ERR_GCM_AUTH_FAILED and we
	 * emit NOTHING -- no unverified plaintext ever reaches the output. */
	ret = mbedtls_gcm_auth_decrypt(&gcm, (size_t) clen,
	          hdr + 32, CRYPT_IV_LEN, hdr, CRYPT_HDR_LEN,
	          tag, CRYPT_TAG_LEN, cipher, plain);
	if (ret != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: authentication failed -- wrong passphrase or corrupted/tampered file\n");
		goto exit;
	}

	if (write_all(out_fd, plain, clen) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "dec: write failed\n");
		goto exit;
	}
	exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
	mbedtls_platform_zeroize(key, sizeof(key));
	mbedtls_platform_zeroize(pass, sizeof(pass));
	if (plain) { mbedtls_platform_zeroize(plain, (size_t) clen); free(plain); }
	if (blob)  { free(blob); }
	mbedtls_gcm_free(&gcm);
	if (in_opened && in_fd >= 0) { close(in_fd); }
	if (out_opened && out_fd >= 0) { close(out_fd); }
	return exit_code;
}

#endif
