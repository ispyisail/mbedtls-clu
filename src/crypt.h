/* crypt -	openssl-`enc`-compatible symmetric file encryption for
 *				mbedtls-clu (Gargoyle encrypted-backup feature, RFC #117).
 *				Provides `mbedtls enc` (with `-d` to decrypt, mirroring
 *				`openssl enc`): AES-256-CBC + PBKDF2 in openssl's `Salted__`
 *				format, so files interoperate with stock `openssl enc`.
 *				`dec` is kept as a convenience alias for `enc -d`.
 *
 *			Intended for lantis1008/mbedtls-clu. Header style matches the
 *			existing utilities in that repo.
 *
 * This file is free software: you may copy, redistribute and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 2 of the License, or (at your
 * option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include "mbedtlsclu_common.h"

int enc_main(int argc, char** argv, int argi);
int dec_main(int argc, char** argv, int argi);
