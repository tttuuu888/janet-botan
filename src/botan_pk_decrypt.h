/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_DECRYPT_H
#define BOTAN_PK_DECRYPT_H

typedef struct botan_pk_decrypt_obj {
    botan_pk_op_decrypt_t pk_decrypt;
} botan_pk_decrypt_obj_t;

/* Abstract Object functions */
static int pk_decrypt_gc_fn(void *data, size_t len);
static int pk_decrypt_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_decrypt_new(int32_t argc, Janet *argv);
static Janet pk_decrypt_decrypt(int32_t argc, Janet *argv);

static JanetAbstractType pk_decrypt_obj_type = {
    "botan/pk-decrypt",
    pk_decrypt_gc_fn,
    NULL,
    pk_decrypt_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_decrypt_methods[] = {
    {"decrypt", pk_decrypt_decrypt},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_decrypt_obj_type() {
    return &pk_decrypt_obj_type;
}

/* Abstract Object functions */
static int pk_decrypt_gc_fn(void *data, size_t len) {
    botan_pk_decrypt_obj_t *obj = (botan_pk_decrypt_obj_t *)data;

    int ret = botan_pk_op_decrypt_destroy(obj->pk_decrypt);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_decrypt_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_decrypt_methods, out);
}

/* Janet functions */
static Janet pk_decrypt_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_decrypt_obj_t *obj = janet_abstract(&pk_decrypt_obj_type, sizeof(botan_pk_decrypt_obj_t));
    memset(obj, 0, sizeof(botan_pk_decrypt_obj_t));

    botan_private_key_obj_t *obj2 = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj2->private_key;

    const char *padding = janet_getcstring(argv, 1);

    int ret = botan_pk_op_decrypt_create(&obj->pk_decrypt, key, padding, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_decrypt_decrypt(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_pk_decrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_decrypt_obj_type());
    botan_pk_op_decrypt_t op = obj->pk_decrypt;

    JanetByteView msg = janet_getbytes(argv, 1);
    size_t out_len = 0;

    ret = botan_pk_op_decrypt_output_length(op, msg.len, &out_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_pk_op_decrypt(op, out->data, &out_len, (const uint8_t *)msg.bytes, msg.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static JanetReg pk_decrypt_cfuns[] = {
    {"pk-decrypt/new", pk_decrypt_new,
     "(pk-decrypt/new privkey padding)\n\n"
     "Create a new operation object which can be used to decrypt using "
     "the provided key and the specified padding scheme (such as "
     "\"OAEP(SHA-256)\" for use with RSA)"
    },
    {"pk-decrypt/decrypt", pk_decrypt_decrypt,
     "(pk-decrypt/decrypt op message)\n\n"
     "Decrypt the provided data using the key."
    },

    {NULL, NULL, NULL}
};

static void submod_pk_decrypt(JanetTable *env) {
    janet_cfuns(env, "botan", pk_decrypt_cfuns);
    janet_register_abstract_type(get_pk_decrypt_obj_type());
}

#endif /* BOTAN_PK_DECRYPT_H */
