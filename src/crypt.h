/* crypt -	Symmetric authenticated file encryption for mbedtls-clu
 *				DRAFT proposed addition for the Gargoyle encrypted-backup
 *				feature (RFC #117). Provides `mbedtls enc` / `mbedtls dec`:
 *				AES-256-GCM with a PBKDF2-HMAC-SHA256-derived key.
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
