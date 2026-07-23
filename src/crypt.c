/* crypt -	`mbedtls enc` : symmetric file encryption for mbedtls-clu, made
 *				CLI- and format-compatible with `openssl enc` (per the rest of
 *				mbedtls-clu, which mirrors the openssl utilities). For the
 *				Gargoyle encrypted-backup feature (RFC #117).
 *
 *				AES-256-CBC (PKCS#7 padding) with a PBKDF2-HMAC-derived key,
 *				written in openssl's own `Salted__` container so a file made
 *				here decrypts with stock `openssl enc -d -aes-256-cbc -pbkdf2`
 *				on a PC, and vice-versa.
 *
 *				`openssl enc` deliberately does NOT support authenticated
 *				(AEAD) modes such as GCM/CCM -- its man page says so and says
 *				it never will -- so an openssl-compatible `enc` is CBC, not
 *				GCM. CBC is unauthenticated: a wrong passphrase yields garbage
 *				rather than a clean failure, exactly as `openssl enc` behaves.
 *				(Gargoyle's backup path makes that safe in practice: the
 *				payload is a gzip'd tar, so a wrong key dies loudly at
 *				gunzip/tar, and the backup manifest is kept in the clear
 *				outside the envelope.)
 *
 *			Intended for lantis1008/mbedtls-clu.
 *
 * Copyright © 2026, distributed under the GNU GPL v2 or later (matching the
 * rest of mbedtls-clu). No warranty; see the project LICENSE.
 *
 * On-disk format = openssl's `enc` format:
 *
 *   off  size  field
 *   0    8     magic     "Salted__"            (omitted entirely with -nosalt)
 *   8    8     salt      random per encryption (omitted with -nosalt)
 *   16   L     ciphertext  AES-256-CBC, PKCS#7-padded (L = plaintext rounded
 *                          up to the next 16-byte block)
 *
 * Key derivation (with -pbkdf2, the only KDF this implements):
 *   keyiv = PBKDF2-HMAC(<md>, pass, salt, iter, 48 bytes)
 *   key   = keyiv[0..31]   (AES-256)
 *   iv    = keyiv[32..47]  (CBC IV)
 * matching openssl's `enc -pbkdf2` (default md sha256, default iter 10000,
 * neither stored in the file -- decryption must use the same flags).
 */

#include "crypt.h"
#include <fcntl.h>
#include <unistd.h>
#include "mbedtls/cipher.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"   /* mbedtls_platform_zeroize */

#define OSSL_MAGIC        "Salted__"
#define OSSL_MAGIC_LEN    8
#define CRYPT_SALT_LEN    8          /* openssl uses an 8-byte salt */
#define CRYPT_KEY_LEN     32         /* AES-256 */
#define CRYPT_IV_LEN      16         /* CBC block */
#define CRYPT_KEYIV_LEN   (CRYPT_KEY_LEN + CRYPT_IV_LEN)
#define CRYPT_DFL_ITER    10000      /* openssl's -pbkdf2 default */
#define CRYPT_MAX_PASS    1024
#define CRYPT_READ_CHUNK  65536

#define ENC_USAGE \
	"\n usage: enc [options]\n"                                                                  \
	"\n openssl-enc-compatible AES-256-CBC file encryption (PBKDF2).\n\n Options:\n"             \
	"    -help                Display this summary\n"                                            \
	"    -e                   Encrypt (default)\n"                                               \
	"    -d                   Decrypt\n"                                                         \
	"    -aes-256-cbc         Cipher (the only cipher supported; may be omitted)\n"              \
	"    -pbkdf2              Use PBKDF2 for key derivation (required; the only KDF)\n"          \
	"    -iter <n>            PBKDF2 iterations (default 10000, matching openssl)\n"             \
	"    -md <digest>         PBKDF2 digest: sha256 (default), sha512, sha1\n"                   \
	"    -salt                Use a salt (default)\n"                                            \
	"    -nosalt              Do not use a salt (openssl-compatible, not recommended)\n"         \
	"    -a, -base64          Base64-encode on encrypt / decode on decrypt\n"                    \
	"    -pass <source>       pass:VALUE | env:VAR | file:PATH | fd:N | stdin\n"                 \
	"    -in <path>           Input (default: stdin)\n"                                          \
	"    -out <path>          Output (default: stdout)\n"

#if !defined(MBEDTLS_CIPHER_C) || !defined(MBEDTLS_AES_C) || \
	!defined(MBEDTLS_CIPHER_MODE_CBC) || !defined(MBEDTLS_PKCS5_C) || \
	!defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_ENTROPY_C) || \
	!defined(MBEDTLS_MD_C) || !defined(MBEDTLS_BASE64_C)
int enc_main(int argc, char** argv, int argi)
{
	(void) argc; (void) argv; (void) argi;
	mbedtls_printf("CIPHER_C / AES_C / CIPHER_MODE_CBC / PKCS5_C / CTR_DRBG_C / ENTROPY_C / MD_C / BASE64_C not all defined.\n");
	return MBEDTLS_EXIT_FAILURE;
}
int dec_main(int argc, char** argv, int argi) { return enc_main(argc, argv, argi); }
#else

/* ---- small helpers ---------------------------------------------------- */

/* Read a passphrase from an openssl-style -pass source. `pass:` is taken
 * verbatim (openssl allows it, though it is visible in ps); the others read
 * from the environment / a file / an fd / stdin. Trailing CR/LF is stripped.
 * Returns length, or -1 on error. out must be CRYPT_MAX_PASS+1 bytes. */
static int read_passphrase(const char* source, char* out)
{
	int fd = -1, opened = 0, n = 0, total = 0;
	const char* v;

	if (source == NULL) { return -1; }

	if (strncmp(source, "pass:", 5) == 0) {
		total = (int) strlen(source + 5);
		if (total > CRYPT_MAX_PASS) { return -1; }
		memcpy(out, source + 5, total);
		out[total] = '\0';
		return total;          /* used verbatim, no newline stripping */
	} else if (strncmp(source, "env:", 4) == 0) {
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
	/* strip a single trailing \n and/or \r (file:/fd:/stdin/env: forms) */
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

static mbedtls_md_type_t md_from_name(const char* name)
{
	if (name == NULL || strcmp(name, "sha256") == 0) { return MBEDTLS_MD_SHA256; }
	if (strcmp(name, "sha512") == 0) { return MBEDTLS_MD_SHA512; }
	if (strcmp(name, "sha1")   == 0) { return MBEDTLS_MD_SHA1;   }
	return MBEDTLS_MD_NONE;
}

/* ---- shared enc/dec --------------------------------------------------- */

static int crypt_run(int argc, char** argv, int argi, int decrypt)
{
	int i, ret, exit_code = MBEDTLS_EXIT_FAILURE;
	char* pass_src = NULL;
	const char* md_name = NULL;
	unsigned int iter = CRYPT_DFL_ITER;
	int in_fd = 0, out_fd = 1, in_opened = 0, out_opened = 0;
	int use_salt = 1, use_b64 = 0, pbkdf2 = 0;
	char pass[CRYPT_MAX_PASS + 1];
	int pass_len = 0;
	unsigned char keyiv[CRYPT_KEYIV_LEN];
	unsigned char salt[CRYPT_SALT_LEN];
	unsigned char* in_buf = NULL;    /* raw bytes read from -in */
	unsigned char* work = NULL;      /* payload after optional base64 step */
	unsigned char* out_buf = NULL;   /* cipher/plain output */
	long in_len = 0, work_len = 0;
	size_t out_len = 0, fin_len = 0;
	const unsigned char* ct;         /* ciphertext start (after any header) */
	long ct_len = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_cipher_context_t cipher;
	const mbedtls_cipher_info_t* info;
	mbedtls_md_type_t mdt;
	int rng_ready = 0;

	mbedtls_cipher_init(&cipher);

	for (i = argi; i < argc; i++) {
		char* p = argv[i];
		if      (strcmp(p, "-help") == 0)   { mbedtls_printf(ENC_USAGE); goto exit; }
		else if (strcmp(p, "-e") == 0)      { decrypt = 0; }
		else if (strcmp(p, "-d") == 0)      { decrypt = 1; }
		else if (strcmp(p, "-aes-256-cbc") == 0) { /* the only cipher; accept it */ }
		else if (strcmp(p, "-pbkdf2") == 0) { pbkdf2 = 1; }
		else if (strcmp(p, "-salt") == 0)   { use_salt = 1; }
		else if (strcmp(p, "-nosalt") == 0) { use_salt = 0; }
		else if (strcmp(p, "-a") == 0 || strcmp(p, "-base64") == 0) { use_b64 = 1; }
		else if (strcmp(p, "-iter") == 0 && i + 1 < argc) { iter = (unsigned int) strtoul(argv[++i], NULL, 10); pbkdf2 = 1; }
		else if (strcmp(p, "-md")   == 0 && i + 1 < argc) { md_name = argv[++i]; }
		else if (strcmp(p, "-pass") == 0 && i + 1 < argc) { pass_src = argv[++i]; }
		else if (strcmp(p, "-in")   == 0 && i + 1 < argc) { in_fd = open(argv[++i], O_RDONLY); in_opened = 1; }
		else if (strcmp(p, "-out")  == 0 && i + 1 < argc) { out_fd = open(argv[++i], O_WRONLY | O_CREAT | O_TRUNC, 0600); out_opened = 1; }
		else { mbedtls_printf(ENC_USAGE); goto exit; }
	}

	if (in_fd < 0 || out_fd < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: cannot open in/out file\n"); goto exit; }
	if (!pbkdf2) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: only PBKDF2 is supported -- pass -pbkdf2\n"); goto exit; }
	if (iter < 1) { iter = CRYPT_DFL_ITER; }
	mdt = md_from_name(md_name);
	if (mdt == MBEDTLS_MD_NONE) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: unsupported -md (use sha256|sha512|sha1)\n"); goto exit; }

	pass_len = read_passphrase(pass_src, pass);
	if (pass_len < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: could not read passphrase (-pass pass:V|env:VAR|file:PATH|fd:N|stdin)\n"); goto exit; }

	in_len = slurp_fd(in_fd, &in_buf);
	if (in_len < 0) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: read failed\n"); goto exit; }

	/* On decrypt with -a, base64-decode the input first. On encrypt with -a
	 * we base64-encode the finished ciphertext at the end. */
	if (decrypt && use_b64) {
		size_t dlen = 0;
		work = malloc(in_len > 0 ? in_len : 1);
		if (work == NULL) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: out of memory\n"); goto exit; }
		if (mbedtls_base64_decode(work, in_len, &dlen, in_buf, in_len) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: base64 decode failed\n"); goto exit;
		}
		work_len = (long) dlen;
	} else {
		work = in_buf; in_buf = NULL; work_len = in_len;
	}

	info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
	if (info == NULL || (ret = mbedtls_cipher_setup(&cipher, info)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: cipher setup failed\n"); goto exit;
	}
	if ((ret = mbedtls_cipher_set_padding_mode(&cipher, MBEDTLS_PADDING_PKCS7)) != 0) {
		mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: set padding failed\n"); goto exit;
	}

	if (!decrypt) {
		/* ---- encrypt ---- */
		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_entropy_init(&entropy);
		rng_ready = 1;
		if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		                                 (const unsigned char*) "mbedtls-clu-enc", 15)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: RNG seed failed\n"); goto exit;
		}
		if (use_salt && (ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, CRYPT_SALT_LEN)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: RNG draw failed\n"); goto exit;
		}
		if (!use_salt) { memset(salt, 0, CRYPT_SALT_LEN); }

		/* -nosalt => openssl feeds PBKDF2 a ZERO-LENGTH salt (not 8 zero
		 * bytes), so match that or the derived key won't interoperate. */
		if ((ret = mbedtls_pkcs5_pbkdf2_hmac_ext(mdt, (const unsigned char*) pass, (size_t) pass_len,
		           salt, (size_t)(use_salt ? CRYPT_SALT_LEN : 0), iter, CRYPT_KEYIV_LEN, keyiv)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: PBKDF2 failed\n"); goto exit;
		}

		/* output buffer: input rounded up one block for PKCS#7 padding */
		out_buf = malloc((size_t) work_len + CRYPT_IV_LEN);
		if (out_buf == NULL) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: out of memory\n"); goto exit; }

		if ((ret = mbedtls_cipher_setkey(&cipher, keyiv, CRYPT_KEY_LEN * 8, MBEDTLS_ENCRYPT)) != 0 ||
		    (ret = mbedtls_cipher_set_iv(&cipher, keyiv + CRYPT_KEY_LEN, CRYPT_IV_LEN)) != 0 ||
		    (ret = mbedtls_cipher_reset(&cipher)) != 0 ||
		    (ret = mbedtls_cipher_update(&cipher, work, (size_t) work_len, out_buf, &out_len)) != 0 ||
		    (ret = mbedtls_cipher_finish(&cipher, out_buf + out_len, &fin_len)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: encryption failed: -0x%04x\n", (unsigned int) -ret); goto exit;
		}
		out_len += fin_len;

		if (use_b64) {
			/* header (if any) then base64 of the ciphertext, matching
			 * `openssl enc -a`: the Salted__ header is NOT base64-wrapped by
			 * openssl -- with -a openssl base64s the whole output INCLUDING
			 * the header. So encode header||ciphertext together. */
			size_t raw_len = (use_salt ? OSSL_MAGIC_LEN + CRYPT_SALT_LEN : 0) + out_len;
			unsigned char* raw = malloc(raw_len);
			unsigned char* b64;
			size_t b64_cap, b64_len = 0;
			if (raw == NULL) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: oom\n"); goto exit; }
			if (use_salt) { memcpy(raw, OSSL_MAGIC, OSSL_MAGIC_LEN); memcpy(raw + OSSL_MAGIC_LEN, salt, CRYPT_SALT_LEN); }
			memcpy(raw + (use_salt ? OSSL_MAGIC_LEN + CRYPT_SALT_LEN : 0), out_buf, out_len);
			b64_cap = ((raw_len + 2) / 3) * 4 + 2;
			b64 = malloc(b64_cap);
			if (b64 == NULL) { free(raw); mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: oom\n"); goto exit; }
			ret = mbedtls_base64_encode(b64, b64_cap, &b64_len, raw, raw_len);
			free(raw);
			if (ret != 0) { free(b64); mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: base64 encode failed\n"); goto exit; }
			if (write_all(out_fd, b64, (long) b64_len) != 0 || write_all(out_fd, (const unsigned char*) "\n", 1) != 0) {
				free(b64); mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: write failed\n"); goto exit;
			}
			free(b64);
		} else {
			if ((use_salt && (write_all(out_fd, (const unsigned char*) OSSL_MAGIC, OSSL_MAGIC_LEN) != 0 ||
			                  write_all(out_fd, salt, CRYPT_SALT_LEN) != 0)) ||
			    write_all(out_fd, out_buf, (long) out_len) != 0) {
				mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: write failed\n"); goto exit;
			}
		}
		exit_code = MBEDTLS_EXIT_SUCCESS;
	} else {
		/* ---- decrypt ---- */
		/* recover salt: present iff the stream starts with "Salted__" */
		if (use_salt && work_len >= OSSL_MAGIC_LEN + CRYPT_SALT_LEN &&
		    memcmp(work, OSSL_MAGIC, OSSL_MAGIC_LEN) == 0) {
			memcpy(salt, work + OSSL_MAGIC_LEN, CRYPT_SALT_LEN);
			ct = work + OSSL_MAGIC_LEN + CRYPT_SALT_LEN;
			ct_len = work_len - OSSL_MAGIC_LEN - CRYPT_SALT_LEN;
		} else {
			/* -nosalt, or a headerless stream: zero salt, whole input is ct */
			memset(salt, 0, CRYPT_SALT_LEN);
			ct = work;
			ct_len = work_len;
		}
		if (ct_len <= 0 || (ct_len % CRYPT_IV_LEN) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: ciphertext length invalid (not a whole number of blocks)\n"); goto exit;
		}

		/* -nosalt => openssl feeds PBKDF2 a ZERO-LENGTH salt (not 8 zero
		 * bytes), so match that or the derived key won't interoperate. */
		if ((ret = mbedtls_pkcs5_pbkdf2_hmac_ext(mdt, (const unsigned char*) pass, (size_t) pass_len,
		           salt, (size_t)(use_salt ? CRYPT_SALT_LEN : 0), iter, CRYPT_KEYIV_LEN, keyiv)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: PBKDF2 failed\n"); goto exit;
		}

		out_buf = malloc((size_t) ct_len);
		if (out_buf == NULL) { mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: out of memory\n"); goto exit; }

		if ((ret = mbedtls_cipher_setkey(&cipher, keyiv, CRYPT_KEY_LEN * 8, MBEDTLS_DECRYPT)) != 0 ||
		    (ret = mbedtls_cipher_set_iv(&cipher, keyiv + CRYPT_KEY_LEN, CRYPT_IV_LEN)) != 0 ||
		    (ret = mbedtls_cipher_reset(&cipher)) != 0 ||
		    (ret = mbedtls_cipher_update(&cipher, ct, (size_t) ct_len, out_buf, &out_len)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: decryption failed\n"); goto exit;
		}
		/* finish validates + strips PKCS#7 padding; a wrong passphrase almost
		 * always fails here (bad pad), which is CBC's only integrity signal.
		 * It is NOT authentication -- see the file header comment. */
		if ((ret = mbedtls_cipher_finish(&cipher, out_buf + out_len, &fin_len)) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: bad decrypt -- wrong passphrase or corrupted file\n"); goto exit;
		}
		out_len += fin_len;

		if (write_all(out_fd, out_buf, (long) out_len) != 0) {
			mbedtlsclu_prio_printf(MBEDTLSCLU_ERR, "enc: write failed\n"); goto exit;
		}
		exit_code = MBEDTLS_EXIT_SUCCESS;
	}

exit:
	mbedtls_platform_zeroize(keyiv, sizeof(keyiv));
	mbedtls_platform_zeroize(pass, sizeof(pass));
	if (rng_ready) { mbedtls_ctr_drbg_free(&ctr_drbg); mbedtls_entropy_free(&entropy); }
	mbedtls_cipher_free(&cipher);
	if (in_buf)  { free(in_buf); }
	if (work)    { mbedtls_platform_zeroize(work, (size_t) work_len); free(work); }
	if (out_buf) { mbedtls_platform_zeroize(out_buf, (size_t)(out_len ? out_len : 1)); free(out_buf); }
	if (in_opened && in_fd >= 0)   { close(in_fd); }
	if (out_opened && out_fd >= 0) { close(out_fd); }
	return exit_code;
}

int enc_main(int argc, char** argv, int argi) { return crypt_run(argc, argv, argi, 0); }
int dec_main(int argc, char** argv, int argi) { return crypt_run(argc, argv, argi, 1); }

#endif
