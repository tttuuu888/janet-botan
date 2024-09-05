/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_BLOCK_CIPHER_H
#define BOTAN_BLOCK_CIPHER_H

typedef struct botan_block_cipher_obj {
    botan_block_cipher_t block_cipher;
} botan_block_cipher_obj_t;

/* Abstract Object functions */
static int block_cipher_gc_fn(void *data, size_t len);
static int block_cipher_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet block_cipher_new(int32_t argc, Janet *argv);
static Janet block_cipher_block_size(int32_t argc, Janet *argv);
static Janet block_cipher_name(int32_t argc, Janet *argv);
static Janet block_cipher_get_keyspec(int32_t argc, Janet *argv);
static Janet block_cipher_clear(int32_t argc, Janet *argv);
static Janet block_cipher_set_key(int32_t argc, Janet *argv);
static Janet block_cipher_encrypt_blocks(int32_t argc, Janet *argv);
static Janet block_cipher_decrypt_blocks(int32_t argc, Janet *argv);

static JanetAbstractType block_cipher_obj_type = {
    "botan/block-cipher",
    block_cipher_gc_fn,
    NULL,
    block_cipher_get_fn,
    JANET_ATEND_GET
};

static JanetMethod block_cipher_methods[] = {
    {"block-size", block_cipher_block_size},
    {"name", block_cipher_name},
    {"get-keyspec", block_cipher_get_keyspec},
    {"clear", block_cipher_clear},
    {"set-key", block_cipher_set_key},
    {"encrypt", block_cipher_encrypt_blocks},
    {"decrypt", block_cipher_decrypt_blocks},
    {NULL, NULL},
};

static JanetAbstractType *get_block_cipher_obj_type() {
    return &block_cipher_obj_type;
}

/* Abstract Object functions */
static int block_cipher_gc_fn(void *data, size_t len) {
    botan_block_cipher_obj_t *obj = (botan_block_cipher_obj_t *)data;

    int ret = botan_block_cipher_destroy(obj->block_cipher);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int block_cipher_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), block_cipher_methods, out);
}

/* Janet functions */
static Janet block_cipher_new(int32_t argc, Janet *argv) {
    botan_block_cipher_obj_t *obj = janet_abstract(&block_cipher_obj_type, sizeof(botan_block_cipher_obj_t));
    janet_fixarity(argc, 1);
    const char *name = (const char *)janet_getstring(argv, 0);

    int ret = botan_block_cipher_init(&obj->block_cipher, name);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet block_cipher_block_size(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;

    int size = botan_block_cipher_block_size(bc);
    JANET_BOTAN_ASSERT(size);

    return janet_wrap_number((double)size);
}

static Janet block_cipher_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;
    size_t len = 32;
    char name[32] = {0,};

    int ret = botan_block_cipher_name(bc, name, &len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string((const uint8_t *)name, strlen(name)));
}

static Janet block_cipher_get_keyspec(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;
    size_t min_key, max_key, mod_key;

    int ret = botan_block_cipher_get_keyspec(bc, &min_key, &max_key, &mod_key);
    JANET_BOTAN_ASSERT(ret);

    Janet spec[3] = {janet_wrap_number((double)min_key),
                     janet_wrap_number((double)max_key),
                     janet_wrap_number((double)mod_key)};
    return janet_wrap_tuple(janet_tuple_n(spec, 3));
}

static Janet block_cipher_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;
    size_t spec;

    int ret = botan_block_cipher_get_keyspec(bc, NULL, NULL, &spec);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet block_cipher_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_block_cipher_set_key(bc, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet block_cipher_encrypt_blocks(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;
    JanetByteView input = janet_getbytes(argv, 1);
    JanetBuffer *output = janet_buffer(input.len);

    int size = botan_block_cipher_block_size(bc);
    JANET_BOTAN_ASSERT(size);

    int blocks = input.len / size;
    int ret = botan_block_cipher_encrypt_blocks(bc, input.bytes, output->data, blocks);
    JANET_BOTAN_ASSERT(ret);

    output->count = input.len;
    return janet_wrap_buffer(output);
}

static Janet block_cipher_decrypt_blocks(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_block_cipher_obj_t *obj = janet_getabstract(argv, 0, get_block_cipher_obj_type());
    botan_block_cipher_t bc = obj->block_cipher;
    JanetByteView input = janet_getbytes(argv, 1);
    JanetBuffer *output = janet_buffer(input.len);

    int size = botan_block_cipher_block_size(bc);
    JANET_BOTAN_ASSERT(size);

    int blocks = input.len / size;
    int ret = botan_block_cipher_decrypt_blocks(bc, input.bytes, output->data, blocks);
    JANET_BOTAN_ASSERT(ret);

    output->count = input.len;
    return janet_wrap_buffer(output);
}

static JanetReg block_cipher_cfuns[] = {
    {"block-cipher/new", block_cipher_new,
     "(block-cipher/new name)\n\n"
     "Create a new cipher mode object, `name` should be for example "
     "\"AES-128\" or \"Threefish-512\". Returns `bc-obj`."
    },
    {"block-cipher/block-size", block_cipher_block_size,
     "(block-cipher/block-size bc-obj)\n\n"
     "Return the block size of this cipher."
    },
    {"block-cipher/name", block_cipher_name,
     "(block-cipher/name bc-obj)\n\n"
     "Return the name of this block cipher algorithm, which may nor may not "
     " exactly match what was passed to `block-cipher/init`."
    },
    {"block-cipher/get-keyspec", block_cipher_get_keyspec,
     "(block-cipher/get-keyspec mac)\n\n"
     "Return the key spec of this cipher in format of "
     "[max-key-length min-key-length mod-key-length]."
    },
    {"block-cipher/clear", block_cipher_clear,
     "(block-cipher/clear bc-obj)\n\n"
     "Clear the internal state (such as keys) of this cipher object, "
     "but do not deallocate it. Returns `bc-obj`."
    },
    {"block-cipher/set-key", block_cipher_set_key,
     "(block-cipher/set-key bc-obj key)\n\n"
     "Set the cipher key, which is required before encrypting or decrypting. "
     "Returns `bc-obj`."
    },
    {"block-cipher/encrypt", block_cipher_encrypt_blocks,
     "(block-cipher/encrypt bc-obj input)\n\n"
     "Encrypt `input` data. The key must have been set beforehand. "
     "Returns encrypted data in buffer format."
    },
    {"block-cipher/decrypt", block_cipher_decrypt_blocks,
     "(block-cipher/decrypt bc-obj input)\n\n"
     "Decrypt `input` data. The key must have been set beforehand. "
     "Returns decrypted data in buffer format."
    },
    {NULL, NULL, NULL}
};

static void submod_block_cipher(JanetTable *env) {
    janet_cfuns(env, "botan", block_cipher_cfuns);
    janet_register_abstract_type(get_block_cipher_obj_type());
}

#endif /* BOTAN_BLOCK_CIPHER_H */
