/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#include <janet.h>
#include <ffi.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "botan_errors.h"
#include "botan_view_functions.h"

#include "botan_versioning.h"
#include "botan_utility.h"
#include "botan_rng.h"
#include "botan_block_cipher.h"
#include "botan_hash.h"
#include "botan_mac.h"
#include "botan_cipher.h"
#include "botan_bcrypt.h"
#include "botan_pbkdf.h"
#include "botan_scrypt.h"
#include "botan_kdf.h"
#include "botan_mpi.h"
#include "botan_oid.h"
#include "botan_ec_group.h"
#include "botan_public_key.h"
#include "botan_private_key.h"
#include "botan_pk_encrypt.h"
#include "botan_pk_decrypt.h"
#include "botan_pk_sign.h"
#include "botan_pk_verify.h"
#include "botan_pk_key_agreement.h"
#include "botan_pk_kem_encrypt.h"
#include "botan_pk_kem_decrypt.h"
#include "botan_fpe.h"
#include "botan_hotp.h"
#include "botan_totp.h"
#include "botan_nist_key_wrap.h"
#include "botan_x509_cert.h"
#include "botan_srp6_server_session.h"
#include "botan_zfec.h"

JANET_MODULE_ENTRY(JanetTable *env) {
    submod_versioning(env);
    submod_utility(env);
    submod_rng(env);
    submod_block_cipher(env);
    submod_hash(env);
    submod_mac(env);
    submod_cipher(env);
    submod_bcrypt(env);
    submod_pbkdf(env);
    submod_scrypt(env);
    submod_kdf(env);
    submod_mpi(env);
    submod_oid(env);
    submod_ec_group(env);
    submod_public_key(env);
    submod_private_key(env);
    submod_pk_encrypt(env);
    submod_pk_decrypt(env);
    submod_pk_sign(env);
    submod_pk_verify(env);
    submod_pk_key_agreement(env);
    submod_pk_kem_encrypt(env);
    submod_pk_kem_decrypt(env);
    submod_fpe(env);
    submod_hotp(env);
    submod_totp(env);
    submod_nist_key_wrap(env);
    submod_x509_cert(env);
    submod_x509_crl(env);
    submod_srp6_server_session(env);
    submod_zfec(env);
}
