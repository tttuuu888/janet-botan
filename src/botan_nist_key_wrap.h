/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_NIST_KEY_WRAP_H
#define BOTAN_NIST_KEY_WRAP_H

static Janet nist_key_wrap(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView kek = janet_getbytes(argv, 0);
    JanetByteView key = janet_getbytes(argv, 1);
    const char *cipher;
    if (argc == 3) {
        cipher = janet_getcstring(argv, 2);
    } else {
        const char *ciphers[3] = { "AES-128", "AES-192", "AES-256" };
        int kek_bits = kek.len * 8;
        switch (kek_bits) {
            case 128:
                cipher = ciphers[0];
                break;
            case 192:
                cipher = ciphers[1];
                break;
            case 256:
                cipher = ciphers[2];
                break;
            default:
                janet_panic("KEK length is invalid.");
        }
    }

    JanetBuffer *wrapped_key = janet_buffer(key.len + 8);
    size_t wrapped_key_len = key.len + 8;

    int ret = botan_nist_kw_enc(cipher, 0,
                                key.bytes, key.len,
                                kek.bytes, kek.len,
                                wrapped_key->data, &wrapped_key_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(wrapped_key->data, wrapped_key_len));
}

static Janet nist_key_unwrap(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    JanetByteView kek = janet_getbytes(argv, 0);
    JanetByteView wrapped_key = janet_getbytes(argv, 1);
    const char *cipher;
    if (argc == 3) {
        cipher = janet_getcstring(argv, 2);
    } else {
        const char *ciphers[3] = { "AES-128", "AES-192", "AES-256" };
        int kek_bits = kek.len * 8;
        switch (kek_bits) {
            case 128:
                cipher = ciphers[0];
                break;
            case 192:
                cipher = ciphers[1];
                break;
            case 256:
                cipher = ciphers[2];
                break;
            default:
                janet_panic("KEK length is invalid.");
        }
    }

    JanetBuffer *key = janet_buffer(wrapped_key.len);
    size_t key_len = wrapped_key.len;

    int ret = botan_nist_kw_dec(cipher, 0,
                                wrapped_key.bytes, wrapped_key.len,
                                kek.bytes, kek.len,
                                key->data, &key_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(key->data, key_len));
}

static JanetReg nist_key_wrap_cfuns[] = {
    {"nist-key-wrap", nist_key_wrap,
     "(nist_key_wrap kek key &opt cipher)\n\n"
     "This performs KW (key wrap) mode. The input must be a multiple of "
     "8 bytes long. If omitted, \"AES\" is used for `cipher`."
    },
    {"nist-key-unwrap", nist_key_unwrap,
     "(nist_key_wrap kek wrapperd &opt cipher)\n\n"
     "This unwraps the result of nist_key_wrap. If omitted, \"AES\" is "
     "used for `cipher`."
    },
    {NULL, NULL, NULL}
};

static void submod_nist_key_wrap(JanetTable *env) {
    janet_cfuns(env, "botan", nist_key_wrap_cfuns);
}

#endif /* BOTAN_NIST_KEY_WRAP_H */
