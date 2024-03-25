/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_VERIFY_H
#define BOTAN_PK_VERIFY_H

typedef struct botan_pk_verify_obj {
    botan_pk_op_verify_t pk_verify;
} botan_pk_verify_obj_t;

/* Abstract Object functions */
static int pk_verify_gc_fn(void *data, size_t len);
static int pk_verify_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_verify_new(int32_t argc, Janet *argv);
static Janet pk_verify_update(int32_t argc, Janet *argv);
static Janet pk_verify_finish(int32_t argc, Janet *argv);

static JanetAbstractType pk_verify_obj_type = {
    "botan/pk-verify",
    pk_verify_gc_fn,
    NULL,
    pk_verify_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_verify_methods[] = {
    {"update", pk_verify_update},
    {"finish", pk_verify_finish},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_verify_obj_type() {
    return &pk_verify_obj_type;
}

/* Abstract Object functions */
static int pk_verify_gc_fn(void *data, size_t len) {
    botan_pk_verify_obj_t *obj = (botan_pk_verify_obj_t *)data;

    int ret = botan_pk_op_verify_destroy(obj->pk_verify);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_verify_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_verify_methods, out);
}

/* Janet functions */
static Janet pk_verify_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_verify_obj_t *obj = janet_abstract(&pk_verify_obj_type, sizeof(botan_pk_verify_obj_t));
    memset(obj, 0, sizeof(botan_pk_verify_obj_t));

    botan_public_key_obj_t *obj2 = janet_getabstract(argv, 0, get_public_key_obj_type());
    botan_pubkey_t key = obj2->public_key;

    const char *padding = janet_getcstring(argv, 1);

    int ret = botan_pk_op_verify_create(&obj->pk_verify, key, padding, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_verify_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_pk_verify_obj_t *obj = janet_getabstract(argv, 0, get_pk_verify_obj_type());
    botan_pk_op_verify_t op = obj->pk_verify;

    JanetByteView msg = janet_getbytes(argv, 1);
    ret = botan_pk_op_verify_update(op, msg.bytes, msg.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet pk_verify_finish(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    int ret;
    botan_pk_verify_obj_t *obj = janet_getabstract(argv, 0, get_pk_verify_obj_type());
    botan_pk_op_verify_t op = obj->pk_verify;

    JanetByteView sig = janet_getbytes(argv, 1);

    ret = botan_pk_op_verify_finish(op, sig.bytes, sig.len);
    if (ret != 0 && ret != 1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 0);
}

static JanetReg pk_verify_cfuns[] = {
    {"pk-verify/new", pk_verify_new,
     "(pk-verify/new pubkey hash-and-padding)\n\n"
     "Create a verifyature operator for the provided key. The padding string "
     "specifies what hash function and padding should be used, for example "
     "\"PKCS1v15(SHA-256)\" for PKCS #1 v1.5 padding (used with RSA) or "
     "\"SHA-384\". Generally speaking only RSA has special padding modes; "
     "for other algorithms like ECDSA one just names the hash."
    },
    {"pk-verify/update", pk_verify_update,
     "(pk-verify/update op message)\n\n"
     "Add the message to be verifyed. Return the self object."
    },
    {"pk-verify/finish", pk_verify_finish,
     "(pk-verify/finish op signature)\n\n"
     "Verify if the signature provided matches with the message provided. "
     "Return boolean."
    },

    {NULL, NULL, NULL}
};

static void submod_pk_verify(JanetTable *env) {
    janet_cfuns(env, "botan", pk_verify_cfuns);
    janet_register_abstract_type(get_pk_verify_obj_type());
}

#endif /* BOTAN_PK_VERIFY_H */
