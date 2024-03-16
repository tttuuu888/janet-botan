/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef BOTAN_CIPHER_H
#define BOTAN_CIPHER_H

static Janet cfun_cipher_init(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    uint32_t flag = (argc == 1) ? 0 : 1;
    const char *name = janet_getcstring(argv, 0);
    botan_cipher_t cipher;

    int ret = botan_cipher_init(&cipher, name, flag);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_pointer(cipher);
}

static Janet cfun_cipher_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);

    int ret = botan_cipher_destroy(cipher);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_cipher_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    char name_buf[32];
    size_t name_len = 32;

    int ret = botan_cipher_name(cipher, name_buf, &name_len);
    JANET_BOTAN_ASSERT(ret);

    name_len -= 1;              /* A length except the last null character */
    return janet_wrap_string(janet_string((const uint8_t *)name_buf, name_len));
}

static Janet cfun_cipher_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);

    int ret = botan_cipher_clear(cipher);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_cipher_get_keyspec(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t bc = janet_getpointer(argv, 0);
    size_t min_key, max_key, mod_key;

    int ret = botan_cipher_get_keyspec(bc, &min_key, &max_key, &mod_key);
    JANET_BOTAN_ASSERT(ret);

    Janet spec[3] = {janet_wrap_number((double)min_key),
                     janet_wrap_number((double)max_key),
                     janet_wrap_number((double)mod_key)};
    return janet_wrap_tuple(janet_tuple_n(spec, 3));
}

static Janet cfun_cipher_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_cipher_set_key(cipher, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_cipher_is_authenticated(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);

    int ret = botan_cipher_is_authenticated(cipher);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet cfun_cipher_get_tag_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    size_t tag_len;

    int ret = botan_cipher_get_tag_length(cipher, &tag_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)tag_len);
}

static Janet cfun_cipher_valid_nonce_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    int64_t nonce_len = janet_getinteger64(argv, 1);

    int ret = botan_cipher_valid_nonce_length(cipher, nonce_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet cfun_cipher_get_default_nonce_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    size_t nonce_len;

    int ret = botan_cipher_get_default_nonce_length(cipher, &nonce_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)nonce_len);
}

static Janet cfun_cipher_get_update_granularity(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    size_t len;

    int ret = botan_cipher_get_update_granularity(cipher, &len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)len);
}

static Janet cfun_cipher_set_associated_data(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    JanetByteView ad = janet_getbytes(argv, 1);

    int ret = botan_cipher_set_associated_data(cipher, ad.bytes, ad.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_cipher_start(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    JanetByteView nonce = janet_getbytes(argv, 1);

    int ret = botan_cipher_start(cipher, nonce.bytes, nonce.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_cipher_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    JanetByteView input = janet_getbytes(argv, 1);
    size_t tag_len = 0;

    int ret = botan_cipher_get_tag_length(cipher, &tag_len);
    JANET_BOTAN_ASSERT(ret);

    size_t output_len = input.len + tag_len + 64;
    JanetBuffer *output = janet_buffer(output_len);
    size_t output_written = 0;
    size_t input_consumed = 0;
    ret = botan_cipher_update(cipher,
                              0,
                              output->data,
                              output_len,
                              &output_written,
                              input.bytes,
                              input.len,
                              &input_consumed);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(output->data, output_written));
}

static Janet cfun_cipher_finish(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_t cipher = janet_getpointer(argv, 0);
    JanetByteView input = janet_getbytes(argv, 1);
    size_t tag_len = 0;

    int ret = botan_cipher_get_tag_length(cipher, &tag_len);
    JANET_BOTAN_ASSERT(ret);

    size_t output_len = input.len + tag_len + 64;
    JanetBuffer *output = janet_buffer(output_len);
    size_t output_written = 0;
    size_t input_consumed = 0;

    ret = botan_cipher_update(cipher,
                              BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                              output->data,
                              output_len,
                              &output_written,
                              input.bytes,
                              input.len,
                              &input_consumed);
    JANET_BOTAN_ASSERT(ret);

    output->count = output_written;
    return janet_wrap_string(janet_string(output->data, output->count));
}

static JanetReg cipher_cfuns[] = {
    {"cipher/init", cfun_cipher_init, "(cipher/init name &opt decrypt)\n\n"
     "Creates an cipher object of the given name, e.g., \"AES-256/GCM\"."
     "Create an encryption cipher, or a decryption cipher if `decrypt` is supplied."
    },
    {"cipher/destroy", cfun_cipher_destroy, "(cipher/destroy cipher)\n\n"
     "Destroy the `cipher` object created by `cipher/init`."
    },
    {"cipher/name", cfun_cipher_name, "(cipher/name cipher)\n\n"
     "Returns the name of this algorithm."
    },
    {"cipher/clear", cfun_cipher_clear, "(cipher/clear cipher)\n\n"
     "Reset the state of `cipher` back to clean, "
     "as if no key and input has been supplied."
    },
    {"cipher/get-keyspec", cfun_cipher_get_keyspec,
     "(cipher/get-keyspec cipher)\n\n"
     "Return the key spec of this `cipher` in format of "
     "`[max-key-length min-key-length mod-key-length]`."
    },
    {"cipher/set-key", cfun_cipher_set_key, "(cipher/set-key cipher key)\n\n"
     "Set the symmetric key to be used."
    },
    {"cipher/is-authenticated", cfun_cipher_is_authenticated,
     "(cipher/is-authenticated cipher)\n\n"
     "Returns true if this is an AEAD mode."
    },
    {"cipher/get-tag-length", cfun_cipher_get_tag_length,
     "(cipher/get-tag-length cipher)\n\n"
     "Returns the tag length (0 for unauthenticated modes)."
    },
    {"cipher/valid-nonce-length", cfun_cipher_valid_nonce_length,
     "(cipher/valid-nonce-length cipher nonce-len)\n\n"
     "Returns true if `nonce_len` is a valid nonce len for this mode."
    },
    {"cipher/get-default-nonce-length", cfun_cipher_get_default_nonce_length,
     "(cipher/get-default-nonce-length cipher)\n\n"
     "Returns default nonce length."
    },
    {"cipher/get-update-granularity", cfun_cipher_get_update_granularity,
     "(cipher/get-update-granularity cipher)\n\n"
     "Return the update granularity of the cipher. `cipher/update` must "
     "be called with blocks of this size, except for the final."
    },
    {"cipher/set-associated-data", cfun_cipher_set_associated_data,
     "(cipher/set-associated-data cipher ad)\n\n"
     "Sets the associated data. Fails if this is not an AEAD mode."
    },
    {"cipher/start", cfun_cipher_start,
     "(cipher/start cipher nonce)\n\n"
     "Start processing a message using `nonce`."
    },
    {"cipher/update", cfun_cipher_update,
     "(cipher/update cipher input)\n\n"
     "Consumes `input` text and returns output. Input text must be of "
     "`cipher/get-update-granularity` length. Alternately, always call "
     "finish with the entire message, avoiding calls to update entirely."
    },
    {"cipher/finish", cfun_cipher_finish,
     "(cipher/finish cipher input)\n\n"
     "Finish processing (with an optional final `input`). May throw if "
     "message authentication checks fail, in which case all plaintext "
     "previously processed must be discarded. You may call `cipher/finish` "
     "with the entire message"
    },
    {NULL, NULL, NULL}
};

#endif /* BOTAN_CIPHER_H */
