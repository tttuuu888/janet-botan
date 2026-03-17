/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_XOF_H
#define BOTAN_XOF_H

typedef struct botan_xof_obj {
    botan_xof_t xof;
} botan_xof_obj_t;

/* Abstract Object functions */
static int xof_gc_fn(void *data, size_t len);
static int xof_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet xof_new(int32_t argc, Janet *argv);
static Janet xof_name(int32_t argc, Janet *argv);
static Janet xof_copy_state(int32_t argc, Janet *argv);
static Janet xof_block_size(int32_t argc, Janet *argv);
static Janet xof_accepts_input(int32_t argc, Janet *argv);
static Janet xof_clear(int32_t argc, Janet *argv);
static Janet xof_update(int32_t argc, Janet *argv);
static Janet xof_output(int32_t argc, Janet *argv);

static JanetAbstractType xof_obj_type = {
    "botan/xof",
    xof_gc_fn,
    NULL,
    xof_get_fn,
    JANET_ATEND_GET
};

static JanetMethod xof_methods[] = {
    {"name", xof_name},
    {"copy", xof_copy_state},
    {"block-size", xof_block_size},
    {"accepts-input", xof_accepts_input},
    {"clear", xof_clear},
    {"update", xof_update},
    {"output", xof_output},
    {NULL, NULL},
};

static JanetAbstractType *get_xof_obj_type() {
    return &xof_obj_type;
}

/* Abstract Object functions */
static int xof_gc_fn(void *data, size_t len) {
    botan_xof_obj_t *obj = (botan_xof_obj_t *)data;

    int ret = botan_xof_destroy(obj->xof);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int xof_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), xof_methods, out);
}

/* Janet functions */
static Janet xof_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_xof_obj_t *obj = janet_abstract(&xof_obj_type, sizeof(botan_xof_obj_t));
    memset(obj, 0, sizeof(botan_xof_obj_t));
    const char *name = janet_getcstring(argv, 0);

    int ret = botan_xof_init(&obj->xof, name, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet xof_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;
    char name_buf[64] = {0,};
    size_t name_len = 64;

    int ret = botan_xof_name(xof, name_buf, &name_len);
    JANET_BOTAN_ASSERT(ret);

    if (name_buf[name_len - 1] == 0) {
        name_len -= 1;
    }

    return janet_wrap_string(janet_string((const uint8_t *)name_buf, name_len));
}

static Janet xof_copy_state(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;

    botan_xof_obj_t *obj2 = janet_abstract(&xof_obj_type, sizeof(botan_xof_obj_t));
    memset(obj2, 0, sizeof(botan_xof_obj_t));

    int ret = botan_xof_copy_state(&obj2->xof, xof);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj2);
}

static Janet xof_block_size(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;
    size_t block_size;

    int ret = botan_xof_block_size(xof, &block_size);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)block_size);
}

static Janet xof_accepts_input(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;

    int ret = botan_xof_accepts_input(xof);

    return janet_wrap_boolean(ret == 1);
}

static Janet xof_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;

    int ret = botan_xof_clear(xof);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet xof_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;
    JanetByteView input = janet_getbytes(argv, 1);

    int ret = botan_xof_update(xof, input.bytes, input.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet xof_output(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_xof_obj_t *obj = janet_getabstract(argv, 0, get_xof_obj_type());
    botan_xof_t xof = obj->xof;
    size_t out_len = janet_getsize(argv, 1);

    uint8_t *output = janet_string_begin(out_len);
    int ret = botan_xof_output(xof, output, out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string_end(output));
}

static JanetReg xof_cfuns[] = {
    {"xof/new", xof_new, "(xof/new name)\n\n"
     "Creates a XOF of the given name, e.g., \"SHAKE-128\", "
     "\"Ascon-XOF128\". Returns `xof-obj`."
    },
    {"xof/name", xof_name, "(xof/name xof-obj)\n\n"
     "Return the name of the XOF."
    },
    {"xof/copy", xof_copy_state, "(xof/copy xof-obj)\n\n"
     "Return a new XOF object copied from `xof-obj`. Returns new `xof-obj`."
    },
    {"xof/block-size", xof_block_size, "(xof/block-size xof-obj)\n\n"
     "Return the block size of the XOF."
    },
    {"xof/accepts-input", xof_accepts_input,
     "(xof/accepts-input xof-obj)\n\n"
     "Return true if the XOF is still accepting input bytes. "
     "Typically, XOFs don't accept input as soon as the first output "
     "bytes were requested."
    },
    {"xof/clear", xof_clear, "(xof/clear xof-obj)\n\n"
     "Clear the state of `xof-obj`. Returns `xof-obj`."
    },
    {"xof/update", xof_update, "(xof/update xof-obj input)\n\n"
     "Add input to the XOF computation. Returns `xof-obj`."
    },
    {"xof/output", xof_output, "(xof/output xof-obj out-len)\n\n"
     "Generate `out-len` bytes of output from the XOF and return the output."
    },
    {NULL, NULL, NULL}
};

static void submod_xof(JanetTable *env) {
    janet_cfuns(env, "botan", xof_cfuns);
    janet_register_abstract_type(get_xof_obj_type());
}

#endif /* BOTAN_XOF_H */
