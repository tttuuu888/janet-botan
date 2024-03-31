/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_CIPHER_H
#define BOTAN_CIPHER_H

typedef struct botan_cipher_obj {
    botan_cipher_t cipher;
} botan_cipher_obj_t;

/* Abstract Object functions */
static int cipher_gc_fn(void *data, size_t len);
static int cipher_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet cipher_new(int32_t argc, Janet *argv);
static Janet cipher_name(int32_t argc, Janet *argv);
static Janet cipher_clear(int32_t argc, Janet *argv);
static Janet cipher_get_keyspec(int32_t argc, Janet *argv);
static Janet cipher_set_key(int32_t argc, Janet *argv);
static Janet cipher_is_authenticated(int32_t argc, Janet *argv);
static Janet cipher_get_tag_length(int32_t argc, Janet *argv);
static Janet cipher_valid_nonce_length(int32_t argc, Janet *argv);
static Janet cipher_get_default_nonce_length(int32_t argc, Janet *argv);
static Janet cipher_get_update_granularity(int32_t argc, Janet *argv);
static Janet cipher_set_associated_data(int32_t argc, Janet *argv);
static Janet cipher_start(int32_t argc, Janet *argv);
static Janet cipher_update(int32_t argc, Janet *argv);
static Janet cipher_finish(int32_t argc, Janet *argv);

static JanetAbstractType cipher_obj_type = {
    "botan/cipher",
    cipher_gc_fn,
    NULL,
    cipher_get_fn,
    JANET_ATEND_GET
};

static JanetMethod cipher_methods[] = {
    {"name", cipher_name},
    {"clear", cipher_clear},
    {"get-keyspec", cipher_get_keyspec},
    {"set-key", cipher_set_key},
    {"is-authenticated", cipher_is_authenticated},
    {"get-tag-length", cipher_get_tag_length},
    {"valid-nonce-length", cipher_valid_nonce_length},
    {"get-default-nonce-length", cipher_get_default_nonce_length},
    {"get-update-granularity", cipher_get_update_granularity},
    {"set-associated-data", cipher_set_associated_data},
    {"start", cipher_start},
    {"update", cipher_update},
    {"finish", cipher_finish},
    {NULL, NULL},
};

static JanetAbstractType *get_cipher_obj_type() {
    return &cipher_obj_type;
}

/* Abstract Object functions */
static int cipher_gc_fn(void *data, size_t len) {
    botan_cipher_obj_t *obj = (botan_cipher_obj_t *)data;

    int ret = botan_cipher_destroy(obj->cipher);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int cipher_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), cipher_methods, out);
}

/* Janet functions */
static Janet cipher_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_abstract(&cipher_obj_type, sizeof(botan_cipher_obj_t));
    memset(obj, 0, sizeof(botan_cipher_obj_t));

    const char *name = janet_getcstring(argv, 0);
    JanetKeyword keyword = janet_getkeyword(argv, 1);
    uint32_t flag;
    if (janet_cstrcmp(keyword, "encrypt") == 0) {
        flag = 0;
    } else if (janet_cstrcmp(keyword, "decrypt") == 0) {
        flag = 1;
    } else {
        janet_panic("Unexpected argument");
    }

    int ret = botan_cipher_init(&obj->cipher, name, flag);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet cipher_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    char name_buf[32];
    size_t name_len = 32;

    int ret = botan_cipher_name(cipher, name_buf, &name_len);
    JANET_BOTAN_ASSERT(ret);

    if (name_buf[name_len - 1] == 0) {
        name_len -= 1;
    }

    return janet_wrap_string(janet_string((const uint8_t *)name_buf, name_len));
}

static Janet cipher_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;

    int ret = botan_cipher_clear(cipher);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet cipher_get_keyspec(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t bc = obj->cipher;
    size_t min_key, max_key, mod_key;

    int ret = botan_cipher_get_keyspec(bc, &min_key, &max_key, &mod_key);
    JANET_BOTAN_ASSERT(ret);

    Janet spec[3] = {janet_wrap_number((double)min_key),
                     janet_wrap_number((double)max_key),
                     janet_wrap_number((double)mod_key)};
    return janet_wrap_tuple(janet_tuple_n(spec, 3));
}

static Janet cipher_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_cipher_set_key(cipher, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet cipher_is_authenticated(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;

    int ret = botan_cipher_is_authenticated(cipher);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet cipher_get_tag_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    size_t tag_len;

    int ret = botan_cipher_get_tag_length(cipher, &tag_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)tag_len);
}

static Janet cipher_valid_nonce_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    int64_t nonce_len = janet_getinteger64(argv, 1);

    int ret = botan_cipher_valid_nonce_length(cipher, nonce_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet cipher_get_default_nonce_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    size_t nonce_len;

    int ret = botan_cipher_get_default_nonce_length(cipher, &nonce_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)nonce_len);
}

static Janet cipher_get_update_granularity(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    size_t len;

    int ret = botan_cipher_get_update_granularity(cipher, &len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)len);
}

static Janet cipher_set_associated_data(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    JanetByteView ad = janet_getbytes(argv, 1);

    int ret = botan_cipher_set_associated_data(cipher, ad.bytes, ad.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet cipher_start(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
    JanetByteView nonce = janet_getbytes(argv, 1);

    int ret = botan_cipher_start(cipher, nonce.bytes, nonce.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet cipher_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
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

static Janet cipher_finish(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_cipher_obj_t *obj = janet_getabstract(argv, 0, get_cipher_obj_type());
    botan_cipher_t cipher = obj->cipher;
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
    {"cipher/new", cipher_new, "(cipher/new name type)\n\n"
     "Creates an cipher object of the given name, e.g., \"AES-256/GCM\"."
     "Create an encryption cipher if `:encrypt` type is given, create "
     "decryption cipher if `:decrypt` type is supplied."
    },
    {"cipher/name", cipher_name, "(cipher/name cipher)\n\n"
     "Returns the name of this algorithm."
    },
    {"cipher/clear", cipher_clear, "(cipher/clear cipher)\n\n"
     "Reset the state of `cipher` back to clean, "
     "as if no key and input has been supplied, return self"
    },
    {"cipher/get-keyspec", cipher_get_keyspec,
     "(cipher/get-keyspec cipher)\n\n"
     "Return the key spec of this `cipher` in format of "
     "`[max-key-length min-key-length mod-key-length]`."
    },
    {"cipher/set-key", cipher_set_key, "(cipher/set-key cipher key)\n\n"
     "Set the symmetric key to be used, return self."
    },
    {"cipher/is-authenticated", cipher_is_authenticated,
     "(cipher/is-authenticated cipher)\n\n"
     "Returns true if this is an AEAD mode."
    },
    {"cipher/get-tag-length", cipher_get_tag_length,
     "(cipher/get-tag-length cipher)\n\n"
     "Returns the tag length (0 for unauthenticated modes)."
    },
    {"cipher/valid-nonce-length", cipher_valid_nonce_length,
     "(cipher/valid-nonce-length cipher nonce-len)\n\n"
     "Returns true if `nonce-len` is a valid nonce len for this mode."
    },
    {"cipher/get-default-nonce-length", cipher_get_default_nonce_length,
     "(cipher/get-default-nonce-length cipher)\n\n"
     "Returns default nonce length."
    },
    {"cipher/get-update-granularity", cipher_get_update_granularity,
     "(cipher/get-update-granularity cipher)\n\n"
     "Return the update granularity of the cipher. `cipher/update` must "
     "be called with blocks of this size, except for the final."
    },
    {"cipher/set-associated-data", cipher_set_associated_data,
     "(cipher/set-associated-data cipher ad)\n\n"
     "Sets the associated data, return self. Fails if this is not an AEAD mode."
    },
    {"cipher/start", cipher_start,
     "(cipher/start cipher nonce)\n\n"
     "Start processing a message using `nonce`, return self"
    },
    {"cipher/update", cipher_update,
     "(cipher/update cipher input)\n\n"
     "Consumes `input` text and returns output. Input text must be of "
     "`cipher/get-update-granularity` length. Alternately, always call "
     "finish with the entire message, avoiding calls to update entirely."
    },
    {"cipher/finish", cipher_finish,
     "(cipher/finish cipher input)\n\n"
     "Finish processing (with an optional final `input`). May throw if "
     "message authentication checks fail, in which case all plaintext "
     "previously processed must be discarded. You may call `cipher/finish` "
     "with the entire message."
    },
    {NULL, NULL, NULL}
};

static void submod_cipher(JanetTable *env) {
    janet_cfuns(env, "botan", cipher_cfuns);
    janet_register_abstract_type(get_cipher_obj_type());
}

#endif /* BOTAN_CIPHER_H */
