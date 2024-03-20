/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_BCRYPT_H
#define BOTAN_BCRYPT_H

static Janet bcrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView pass = janet_getbytes(argv, 0);
    botan_rng_obj_t *rng_obj = janet_getabstract(argv, 1, get_rng_obj_type());
    botan_rng_t rng = rng_obj->rng;
    size_t work_factor = 10;
    size_t out_len = 64;
    JanetBuffer *out = janet_buffer(out_len);
    int ret;

    if (argc == 3) {
        work_factor = janet_getsize(argv, 2);
    }

    ret = botan_bcrypt_generate(out->data, &out_len, pass.bytes,
                                rng, work_factor, 0);
    JANET_BOTAN_ASSERT(ret);

    out->count = out_len;
    return janet_wrap_string(janet_string(out->data, out->count));
}

static Janet bcrypt_is_valid(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    JanetByteView pass = janet_getbytes(argv, 0);
    JanetByteView hashed = janet_getbytes(argv, 1);
    int ret;

    ret = botan_bcrypt_is_valid(pass.bytes, hashed.bytes);
    if (ret != 0 && ret != 1) {
        janet_panic(getBotanError(ret));
    }

    return janet_wrap_boolean(ret == 0);
}

static JanetReg bcrypt_cfuns[] = {
    {"bcrypt", bcrypt,
     "(bcrypt password rng &opt work_factor)\n\n"
     "Provided the password and an RNG object, returns a bcrypt string."
    },
    {"bcrypt-is-valid", bcrypt_is_valid,
     "(bcrypt-is-valid password bcrypt)\n\n"
     "Check a bcrypt hash against the provided password, returning true if "
     "the password matches."
    },
    {NULL, NULL, NULL}
};

static void submod_bcrypt(JanetTable *env) {
    janet_cfuns(env, "botan", bcrypt_cfuns);
}

#endif /* BOTAN_BCRYPT_H */
