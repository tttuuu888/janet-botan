/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef BOTAN_HASH_H
#define BOTAN_HASH_H

typedef struct botan_hash_obj {
    botan_hash_t hash;
} botan_hash_obj_t;

/* Abstract Object functions */
static int hash_gc_fn(void *data, size_t len);
static int hash_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet hash_new(int32_t argc, Janet *argv);
static Janet hash_name(int32_t argc, Janet *argv);
static Janet hash_copy_state(int32_t argc, Janet *argv);
static Janet hash_clear(int32_t argc, Janet *argv);
static Janet hash_output_length(int32_t argc, Janet *argv);
static Janet hash_update(int32_t argc, Janet *argv);
static Janet hash_final(int32_t argc, Janet *argv);

static JanetAbstractType hash_obj_type = {
    "botan/hash",
    hash_gc_fn,
    NULL,
    hash_get_fn,
    JANET_ATEND_GET
};

static JanetMethod hash_methods[] = {
    {"name", hash_name},
    {"copy", hash_copy_state},
    {"clear", hash_clear},
    {"output-length", hash_output_length},
    {"update", hash_update},
    {"final", hash_final},
    {NULL, NULL},
};

static JanetAbstractType *get_hash_obj_type() {
    return &hash_obj_type;
}

/* Abstract Object functions */
static int hash_gc_fn(void *data, size_t len) {
    botan_hash_obj_t *obj = (botan_hash_obj_t *)data;

    int ret = botan_hash_destroy(obj->hash);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int hash_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), hash_methods, out);
}

/* Janet functions */
static Janet hash_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_obj_t *obj = janet_abstract(&hash_obj_type, sizeof(botan_hash_obj_t));
    memset(obj, 0, sizeof(botan_hash_obj_t));
    const char *name = janet_getcstring(argv, 0);

    int ret = botan_hash_init(&obj->hash, name, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet hash_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_obj_t *obj = janet_getabstract(argv, 0, get_hash_obj_type());
    botan_hash_t hash = obj->hash;
    char name_buf[32] = {0,};
    size_t name_len = 32;

    int ret = botan_hash_name(hash, name_buf, &name_len);
    JANET_BOTAN_ASSERT(ret);

    name_len -= 1;              /* A length except the last null character */
    return janet_wrap_string(janet_string((const uint8_t *)name_buf, name_len));
}

static Janet hash_copy_state(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_obj_t *obj = janet_getabstract(argv, 0, get_hash_obj_type());
    botan_hash_t hash = obj->hash;

    botan_hash_obj_t *obj2 = janet_abstract(&hash_obj_type, sizeof(botan_hash_obj_t));
    memset(obj2, 0, sizeof(botan_hash_obj_t));

    int ret = botan_hash_copy_state(&obj2->hash, hash);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj2);
}

static Janet hash_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_obj_t *obj = janet_getabstract(argv, 0, get_hash_obj_type());
    botan_hash_t hash = obj->hash;

    int ret = botan_hash_clear(hash);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet hash_output_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_obj_t *obj = janet_getabstract(argv, 0, get_hash_obj_type());
    botan_hash_t hash = obj->hash;
    size_t output_len;

    int ret = botan_hash_output_length(hash, &output_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)output_len);
}

static Janet hash_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_hash_obj_t *obj = janet_getabstract(argv, 0, get_hash_obj_type());
    botan_hash_t hash = obj->hash;
    JanetByteView input = janet_getbytes(argv, 1);

    int ret = botan_hash_update(hash, input.bytes, input.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet hash_final(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_obj_t *obj = janet_getabstract(argv, 0, get_hash_obj_type());
    botan_hash_t hash = obj->hash;
    size_t output_len;

    int ret = botan_hash_output_length(hash, &output_len);
    JANET_BOTAN_ASSERT(ret);

    uint8_t *output = janet_string_begin(output_len);
    ret = botan_hash_final(hash, output);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string_end(output));
}

static JanetReg hash_cfuns[] = {
    {"hash/new", hash_new, "(hash/new name)\n\n"
     "Creates a hash of the given name, e.g., \"SHA-384\"."
    },
    {"hash/name", hash_name, "(hash/name hash)\n\n"
     "Return the name of the hash function."
    },
    {"hash/copy", hash_copy_state, "(hash/copy hash)\n\n"
     "Return a new hash object copied from `hash`."
    },
    {"hash/clear", hash_clear, "(hash/clear hash)\n\n"
     "Reset the state of `hash` back to clean, "
     "as if no input has been supplied, return self."
    },
    {"hash/output-length", hash_output_length,
     "(hash/output-length hash)\n\n"
     "Return the output length of the `hash`"
    },
    {"hash/update", hash_update, "(hash/update hash input)\n\n"
     "Add input to the hash computation, return self."
    },
    {"hash/final", hash_final, "(hash/final hash)\n\n"
     "Finalize the hash and return the output"
    },
    {NULL, NULL, NULL}
};

static void submod_hash(JanetTable *env) {
    janet_cfuns(env, "botan", hash_cfuns);
    janet_register_abstract_type(get_hash_obj_type());
}

#endif /* BOTAN_HASH_H */
