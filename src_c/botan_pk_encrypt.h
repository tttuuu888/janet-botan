/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_ENCRYPT_H
#define BOTAN_PK_ENCRYPT_H

typedef struct botan_pk_encrypt_obj {
    botan_pk_op_encrypt_t pk_encrypt;
} botan_pk_encrypt_obj_t;

/* Abstract Object functions */
static int pk_encrypt_gc_fn(void *data, size_t len);
static int pk_encrypt_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_encrypt_new(int32_t argc, Janet *argv);
static Janet pk_encrypt_encrypt(int32_t argc, Janet *argv);

static JanetAbstractType pk_encrypt_obj_type = {
    "botan/pk-encrypt",
    pk_encrypt_gc_fn,
    NULL,
    pk_encrypt_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_encrypt_methods[] = {
    {"encrypt", pk_encrypt_encrypt},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_encrypt_obj_type() {
    return &pk_encrypt_obj_type;
}

/* Abstract Object functions */
static int pk_encrypt_gc_fn(void *data, size_t len) {
    botan_pk_encrypt_obj_t *obj = (botan_pk_encrypt_obj_t *)data;

    int ret = botan_pk_op_encrypt_destroy(obj->pk_encrypt);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_encrypt_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_encrypt_methods, out);
}

/* Janet functions */
static Janet pk_encrypt_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_encrypt_obj_t *obj = janet_abstract(&pk_encrypt_obj_type, sizeof(botan_pk_encrypt_obj_t));
    memset(obj, 0, sizeof(botan_pk_encrypt_obj_t));

    botan_public_key_obj_t *obj2 = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj2->public_key;

    const char *padding = janet_getcstring(argv, 1);

    int ret = botan_pk_op_encrypt_create(&obj->pk_encrypt, key, padding, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_encrypt_encrypt(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);

    int ret;
    botan_pk_encrypt_obj_t *obj = janet_getabstract(argv, 0, get_pk_encrypt_obj_type());
    botan_pk_op_encrypt_t op = obj->pk_encrypt;

    const char *msg = (const char *)janet_getstring(argv, 1);
    size_t msg_len = strlen(msg);
    size_t out_len = 0;
    botan_rng_t rng;

    if (argc == 3) {
        botan_rng_obj_t *obj2 = janet_getabstract(argv, 2, get_rng_obj_type());
        rng = obj2->rng;
    } else {
        botan_rng_obj_t *obj2 = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
        memset(obj2, 0, sizeof(botan_rng_obj_t));

        ret = botan_rng_init(&obj2->rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng = obj2->rng;
    }

    ret = botan_pk_op_encrypt_output_length(op, msg_len, &out_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_pk_op_encrypt(op, rng, out->data, &out_len, msg, msg_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static JanetReg pk_encrypt_cfuns[] = {
    {"pk-encrypt/new", pk_encrypt_new,
     "(pk-encrypt/new pubkey padding)\n\n"
     "Create a new operation object which can be used to encrypt using "
     "the provided key and the specified padding scheme (such as "
     "\"OAEP(SHA-256)\" for use with RSA)"
    },
    {"pk-encrypt/encrypt", pk_encrypt_encrypt,
     "(pk-encrypt/encrypt op message &opt rng)\n\n"
     "Encrypt the provided data using the key`. New rng is used by "
     "default, if `rng` is not provided."
    },

    {NULL, NULL, NULL}
};

static void submod_pk_encrypt(JanetTable *env) {
    janet_cfuns(env, "botan", pk_encrypt_cfuns);
    janet_register_abstract_type(get_pk_encrypt_obj_type());
}

#endif /* BOTAN_PK_ENCRYPT_H */
