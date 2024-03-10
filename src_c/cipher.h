/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#ifndef CIPHER_H
#define CIPHER_H

static Janet cfun_cipher_init(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    uint32_t flag = (argc == 0) ? 0 : 1;
    const char *name = janet_getcstring(argv, 0);
    botan_cipher_t cipher;
    int ret = botan_cipher_init(&cipher, name, flag);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_pointer(cipher);
}

static Janet cfun_cipher_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    int ret = botan_cipher_destroy(cipher);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_nil();
}

static Janet cfun_cipher_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    int ret = botan_cipher_clear(cipher);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_nil();
}

static Janet cfun_cipher_get_min_keylen(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    size_t spec;
    int ret = botan_cipher_get_keyspec(cipher, &spec, NULL, NULL);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_number((double)spec);
}

static Janet cfun_cipher_get_max_keylen(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    size_t spec;
    int ret = botan_cipher_get_keyspec(cipher, NULL, &spec, NULL);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_number((double)spec);
}

static Janet cfun_cipher_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    JanetByteView key = janet_getbytes(argv, 1);
    int ret = botan_cipher_set_key(cipher, key.bytes, key.len);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_nil();
}

static JanetReg cipher_cfuns[] = {
    {"cipher/init", cfun_cipher_init, "(cipher/init name &opt decrypt)\n\n"
     "Creates an cipher object of the given name, e.g., \"AES-256/GCM\"."
     "Create an encryption cipher, or a decryption cipher if `decrypt` is supplied."
    },
    {"cipher/destroy", cfun_cipher_destroy, "(cipher/destroy cipher)\n\n"
     "Destroy the `cipher` object created by `cipher/init`."
    },
    {"cipher/clear", cfun_cipher_clear, "(cipher/clear cipher)\n\n"
     "Reset the state of `cipher` back to clean, "
     "as if no key and input has been supplied."
    },
    {"cipher/get-min-keylen", cfun_cipher_get_min_keylen,
     "(cipher/get-min-keylen cipher)\n\n"
     "Return the smallest key length that is acceptable for the algorithm."
    },
    {"cipher/get-max-keylen", cfun_cipher_get_max_keylen,
     "(cipher/get-max-keylen cipher)\n\n"
     "Return the largest key length that is acceptable for the algorithm."
    },
    {"cipher/set-key", cfun_cipher_set_key, "(cipher/set-key cipher key)\n\n"
     "Set the symmetric key to be used."
    },
    {NULL, NULL, NULL}
};

#endif /* CIPHER_H */
