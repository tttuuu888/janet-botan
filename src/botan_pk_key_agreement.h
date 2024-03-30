/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PK_KEY_AGREEMENT_H
#define BOTAN_PK_KEY_AGREEMENT_H

typedef struct botan_pk_key_agreement_obj {
    botan_pk_op_ka_t pk_key_agreement;
    uint8_t *public_value;
    size_t public_value_size;
} botan_pk_key_agreement_obj_t;

/* Abstract Object functions */
static int pk_key_agreement_gc_fn(void *data, size_t len);
static int pk_key_agreement_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet pk_key_agreement_new(int32_t argc, Janet *argv);
static Janet pk_key_agreement_public_value(int32_t argc, Janet *argv);
static Janet pk_key_agreement_agree(int32_t argc, Janet *argv);

static JanetAbstractType pk_key_agreement_obj_type = {
    "botan/pk-key_agreement",
    pk_key_agreement_gc_fn,
    NULL,
    pk_key_agreement_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pk_key_agreement_methods[] = {
    {"public-value", pk_key_agreement_public_value},
    {"agree", pk_key_agreement_agree},
    {NULL, NULL},
};

static JanetAbstractType *get_pk_key_agreement_obj_type() {
    return &pk_key_agreement_obj_type;
}

/* Abstract Object functions */
static int pk_key_agreement_gc_fn(void *data, size_t len) {
    botan_pk_key_agreement_obj_t *obj = (botan_pk_key_agreement_obj_t *)data;

    int ret = botan_pk_op_key_agreement_destroy(obj->pk_key_agreement);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int pk_key_agreement_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pk_key_agreement_methods, out);
}

/* Janet functions */
static Janet pk_key_agreement_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_pk_key_agreement_obj_t *obj = janet_abstract(&pk_key_agreement_obj_type, sizeof(botan_pk_key_agreement_obj_t));
    memset(obj, 0, sizeof(botan_pk_key_agreement_obj_t));

    botan_private_key_obj_t *obj2 = janet_getabstract(argv, 0, get_private_key_obj_type());
    botan_privkey_t key = obj2->private_key;
    const char *kdf = (const char *)janet_getstring(argv, 1);

    int ret = botan_pk_op_key_agreement_create(&obj->pk_key_agreement, key, kdf, 0);
    JANET_BOTAN_ASSERT(ret);

    view_data_t data;
    ret = botan_pk_op_key_agreement_view_public(key, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    obj->public_value = janet_smalloc(data.len);
    obj->public_value_size = data.len;
    memcpy(obj->public_value, data.data, data.len);

    return janet_wrap_abstract(obj);
}

static Janet pk_key_agreement_public_value(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_pk_key_agreement_obj_t *obj = janet_getabstract(argv, 0, get_pk_key_agreement_obj_type());
    if (!obj->public_value) {
        janet_panic("No public value found.");
    }

    return janet_wrap_string(janet_string(obj->public_value, obj->public_value_size));
}

static Janet pk_key_agreement_agree(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    int ret;
    botan_pk_key_agreement_obj_t *obj = janet_getabstract(argv, 0, get_pk_key_agreement_obj_type());
    botan_pk_op_ka_t op = obj->pk_key_agreement;
    JanetByteView other_key = janet_getbytes(argv, 1);
    JanetByteView salt = janet_getbytes(argv, 2);
    size_t out_len = 0;
    if (argc == 4) {
        out_len = janet_getsize(argv, 3);
    } else {
        ret = botan_pk_op_key_agreement_size(op, &out_len);
        JANET_BOTAN_ASSERT(ret);
    }

    JanetBuffer *out = janet_buffer(out_len);
    ret = botan_pk_op_key_agreement(op, out->data, &out_len, other_key.bytes, other_key.len, salt.bytes, salt.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static JanetReg pk_key_agreement_cfuns[] = {
    {"pk-key-agreement/new", pk_key_agreement_new,
     "(pk-key-agreement/new privkey kdf)\n\n"
     "Set up to perform key derivation using the given private key and "
     "specified KDF."
    },
    {"pk-key-agreement/public-value", pk_key_agreement_public_value,
     "(pk-key_agreement/public-value op)\n\n"
     "Returns the public value to be passed to the other party"
    },
    {"pk-key-agreement/agree", pk_key_agreement_agree,
     "(pk-key_agreement/agree op other-key salt &opt key-len)\n\n"
     "Returns a key derived by the KDF. If `key-len` is omitted, default "
     "agreement size will be used."
    },

    {NULL, NULL, NULL}
};

static void submod_pk_key_agreement(JanetTable *env) {
    janet_cfuns(env, "botan", pk_key_agreement_cfuns);
    janet_register_abstract_type(get_pk_key_agreement_obj_type());
}

#endif /* BOTAN_PK_KEY_AGREEMENT_H */
