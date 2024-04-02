/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_SCRYPT_H
#define BOTAN_SCRYPT_H

static Janet scrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 6);
    size_t out_len = janet_getsize(argv, 0);
    JanetByteView pass = janet_getbytes(argv, 1);
    JanetByteView salt = janet_getbytes(argv, 2);
    JanetBuffer *out = janet_buffer(out_len);

    size_t N = janet_optsize(argv, argc, 3, 1024);
    size_t r = janet_optsize(argv, argc, 4, 8);
    size_t p = janet_optsize(argv, argc, 5, 8);
    int ret;

    ret = botan_pwdhash("Scrypt", N, r, p,
                        out->data, out_len,
                        (const char *)pass.bytes, pass.len,
                        salt.bytes, salt.len);
    JANET_BOTAN_ASSERT(ret);

    out->count = out_len;
    return janet_wrap_string(janet_string(out->data, out->count));
}

static JanetReg scrypt_cfuns[] = {
    {"scrypt", scrypt,
     "(scrypt out-len password salt &opt N r p)\n\n"
     "Runs Scrypt key derivation function over the specified password and "
     "salt using Scrypt parameters N, r, p. If omitted, the default values "
     "of N=1024, r=8, p=8 are used."
    },
    {NULL, NULL, NULL}
};

static void submod_scrypt(JanetTable *env) {
    janet_cfuns(env, "botan", scrypt_cfuns);
}

#endif /* BOTAN_SCRYPT_H */
