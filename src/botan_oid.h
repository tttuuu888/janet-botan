/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_OID_H
#define BOTAN_OID_H

typedef struct botan_oid_obj {
    botan_asn1_oid_t oid;
} botan_oid_obj_t;

/* Abstract Object functions */
static int oid_gc_fn(void *data, size_t len);
static int oid_get_fn(void *data, Janet key, Janet *out);
static int oid_compare_fn(void *lhs, void *rhs);

/* Janet functions */
static Janet oid_register(int32_t argc, Janet *argv);
static Janet oid_to_string(int32_t argc, Janet *argv);
static Janet oid_to_name(int32_t argc, Janet *argv);
static Janet oid_equal(int32_t argc, Janet *argv);
static Janet oid_cmp(int32_t argc, Janet *argv);

static JanetAbstractType oid_obj_type = {
    "botan/oid",
    oid_gc_fn,
    NULL,
    oid_get_fn,
    NULL,   // put
    NULL,   // marshal
    NULL,   // unmarshal
    NULL,   // tostring
    oid_compare_fn,
    JANET_ATEND_HASH
};

static JanetMethod oid_methods[] = {
    {"register", oid_register},
    {"to-string", oid_to_string},
    {"to-name", oid_to_name},
    {"equal", oid_equal},
    {"cmp", oid_cmp},
    {NULL, NULL},
};

static JanetAbstractType *get_oid_obj_type() {
    return &oid_obj_type;
}

/* Abstract Object functions */
static int oid_gc_fn(void *data, size_t len) {
    botan_oid_obj_t *obj = (botan_oid_obj_t *)data;

    int ret = botan_oid_destroy(obj->oid);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int oid_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), oid_methods, out);
}

static int oid_compare_fn(void *lhs, void *rhs) {
    botan_oid_obj_t *obj1 = (botan_oid_obj_t *)lhs;
    botan_oid_obj_t *obj2 = (botan_oid_obj_t *)rhs;

    int result;
    int ret = botan_oid_cmp(&result, obj1->oid, obj2->oid);
    JANET_BOTAN_ASSERT(ret);

    return result;
}

/* Janet functions */
static Janet oid_from_string(int32_t argc, Janet *argv) {
    botan_oid_obj_t *obj = janet_abstract(&oid_obj_type, sizeof(botan_oid_obj_t));
    memset(obj, 0, sizeof(botan_oid_obj_t));

    janet_fixarity(argc, 1);

    const char *oid_str = janet_getcstring(argv, 0);
    int ret = botan_oid_from_string(&obj->oid, oid_str);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet oid_register(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_oid_obj_t *obj = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid = obj->oid;
    const char *name = janet_getcstring(argv, 1);

    int ret = botan_oid_register(oid, name);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet oid_to_string(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_oid_obj_t *obj = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid = obj->oid;

    view_data_t data;
    int ret = botan_oid_view_string(oid, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet oid_to_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_oid_obj_t *obj = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid = obj->oid;

    view_data_t data;
    int ret = botan_oid_view_name(oid, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet oid_equal(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_oid_obj_t *obj1 = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid1 = obj1->oid;

    botan_oid_obj_t *obj2 = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid2 = obj2->oid;

    int result = 0;
    int ret = botan_oid_cmp(&result, oid1, oid2);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(result == 0);
}

static Janet oid_cmp(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_oid_obj_t *obj1 = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid1 = obj1->oid;

    botan_oid_obj_t *obj2 = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid2 = obj2->oid;

    int result = 0;
    int ret = botan_oid_cmp(&result, oid1, oid2);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)result);
}

static JanetReg oid_cfuns[] = {
    {"oid/from-string", oid_from_string,
     "(oid/from-string str)\n\n"
     "Create an OID from a string, either dot notation (e.g. '1.2.3.4') or "
     "a registered name (e.g. 'RSA'). Returns the `oid-obj`."
    },
    {"oid/register", oid_register,
     "(oid/register oid-obj name)\n\n"
     "Register an OID so that it may later be retrieved by name."
     "Returns the `oid-obj` itself."
    },
    {"oid/to-string", oid_to_string,
     "(oid/to-string oid-obj)\n\n"
     "Returns the OID in dot notation string."
    },
    {"oid/to-name", oid_to_name,
     "(oid/to-name oid-obj)\n\n"
     "Returns the OID as a name if it has one, otherwise as dot notation."
    },
    {"oid/equal", oid_equal,
     "(oid/equal oid-obj-a oid-obj-b)\n\n"
     "Return True if `oid-obj-a` is equal to `oid-obj-b`, "
     "False if a is not equal to b."
    },
    {"oid/cmp", oid_cmp,
     "(oid/cmp oid-obj-a oid-obj-b)\n\n"
     "Three way comparison: set result to -1 if `oid-obj-a` is less than "
     "`oid-obj-b`, 0 if a is equal to b, and 1 if a is greater than b."
    },
    {NULL, NULL, NULL}
};

static void submod_oid(JanetTable *env) {
    janet_cfuns(env, "botan", oid_cfuns);
    janet_register_abstract_type(get_oid_obj_type());
}

#endif /* BOTAN_OID_H */
