/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_FPE_H
#define BOTAN_FPE_H

typedef struct botan_fpe_obj {
    botan_fpe_t fpe;
} botan_fpe_obj_t;

/* Abstract Object functions */
static int fpe_gc_fn(void *data, size_t len);
static int fpe_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet fpe_new(int32_t argc, Janet *argv);
static Janet fpe_encrypt(int32_t argc, Janet *argv);
static Janet fpe_decrypt(int32_t argc, Janet *argv);

static JanetAbstractType fpe_obj_type = {
    "botan/fpe",
    fpe_gc_fn,
    NULL,
    fpe_get_fn,
    JANET_ATEND_GET
};

static JanetMethod fpe_methods[] = {
    {"encrypt", fpe_encrypt},
    {"decrypt", fpe_decrypt},
    {NULL, NULL},
};

static JanetAbstractType *get_fpe_obj_type() {
    return &fpe_obj_type;
}

/* Abstract Object functions */
static int fpe_gc_fn(void *data, size_t len) {
    botan_fpe_obj_t *obj = (botan_fpe_obj_t *)data;

    int ret = botan_fpe_destroy(obj->fpe);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int fpe_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), fpe_methods, out);
}

/* Janet functions */
static Janet fpe_new(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 4);

    botan_fpe_obj_t *obj = janet_abstract(&fpe_obj_type, sizeof(botan_fpe_obj_t));
    memset(obj, 0, sizeof(botan_fpe_obj_t));

    botan_mpi_obj_t *obj2 = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj2->mpi;

    JanetByteView key = janet_getbytes(argv, 1);

    size_t rounds = 5;
    if (argc >= 3) {
        rounds = janet_getsize(argv, 2);
    }

    uint32_t flags = 0;
    if (argc >= 4) {
        flags = 1;
    }

    int ret = botan_fpe_fe1_init(&obj->fpe, mpi, key.bytes, key.len, rounds, flags);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet fpe_encrypt(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_fpe_obj_t *obj = janet_getabstract(argv, 0, get_fpe_obj_type());
    botan_fpe_t fpe = obj->fpe;

    botan_mpi_obj_t *obj2 = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi = obj2->mpi;

    JanetByteView tweak = janet_getbytes(argv, 2);

    ret = botan_fpe_encrypt(fpe, mpi, tweak.bytes, tweak.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj2);
}

static Janet fpe_decrypt(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);

    int ret;
    botan_fpe_obj_t *obj = janet_getabstract(argv, 0, get_fpe_obj_type());
    botan_fpe_t fpe = obj->fpe;

    botan_mpi_obj_t *obj2 = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi = obj2->mpi;

    JanetByteView tweak = janet_getbytes(argv, 2);

    ret = botan_fpe_decrypt(fpe, mpi, tweak.bytes, tweak.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj2);
}

static JanetReg fpe_cfuns[] = {
    {"fpe/new", fpe_new,
     "(fpe/new modulus key &opt round compat-mode)\n\n"
     "Create a new FPE instance, FE1 scheme Rounds should be 16 or higher "
     "for best security. If omitted, default value for `round` is 5, "
     "`compact-mode` is false."
    },
    {"fpe/encrypt", fpe_encrypt,
     "(fpe/encrypt x tweak)\n\n"
     "Encrypt value under the FPE scheme using provided tweak. Return an "
     "MPI object."
    },
    {"fpe/decrypt", fpe_decrypt,
     "(fpe/decrypt x tweak)\n\n"
     "Decrypt value under the FPE scheme using provided tweak. Return an "
     "MPI object."
    },

    {NULL, NULL, NULL}
};

static void submod_fpe(JanetTable *env) {
    janet_cfuns(env, "botan", fpe_cfuns);
}

#endif /* BOTAN_FPE_H */
