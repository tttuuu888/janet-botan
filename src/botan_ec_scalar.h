/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_EC_SCALAR_H
#define BOTAN_EC_SCALAR_H

typedef struct botan_ec_scalar_obj {
    botan_ec_scalar_t ec_scalar;
} botan_ec_scalar_obj_t;

/* Abstract Object functions */
static int ec_scalar_gc_fn(void *data, size_t len);
static int ec_scalar_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet ec_scalar_random(int32_t argc, Janet *argv);
static Janet ec_scalar_from_mp(int32_t argc, Janet *argv);
static Janet ec_scalar_to_mp(int32_t argc, Janet *argv);

static JanetAbstractType ec_scalar_obj_type = {
    "botan/ec_scalar",
    ec_scalar_gc_fn,
    NULL,
    ec_scalar_get_fn,
    JANET_ATEND_GET
};

static JanetMethod ec_scalar_methods[] = {
    {"to-mp", ec_scalar_to_mp},
    {NULL, NULL},
};

static JanetAbstractType *get_ec_scalar_obj_type() {
    return &ec_scalar_obj_type;
}

/* Abstract Object functions */
static int ec_scalar_gc_fn(void *data, size_t len) {
    botan_ec_scalar_obj_t *obj = (botan_ec_scalar_obj_t *)data;

    int ret = botan_ec_scalar_destroy(obj->ec_scalar);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int ec_scalar_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), ec_scalar_methods, out);
}

/* Janet functions */
static Janet ec_scalar_random(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_ec_group_obj_t *grp_obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = grp_obj->ec_group;
    botan_rng_obj_t *rng_obj = janet_getabstract(argv, 1, get_rng_obj_type());
    botan_rng_t rng = rng_obj->rng;

    botan_ec_scalar_obj_t *obj = janet_abstract(&ec_scalar_obj_type, sizeof(botan_ec_scalar_obj_t));
    memset(obj, 0, sizeof(botan_ec_scalar_obj_t));

    int ret = botan_ec_scalar_random(&obj->ec_scalar, ec_group, rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_scalar_from_mp(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_ec_group_obj_t *grp_obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = grp_obj->ec_group;
    botan_mpi_obj_t *mp_obj = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mp = mp_obj->mpi;

    botan_ec_scalar_obj_t *obj = janet_abstract(&ec_scalar_obj_type, sizeof(botan_ec_scalar_obj_t));
    memset(obj, 0, sizeof(botan_ec_scalar_obj_t));

    int ret = botan_ec_scalar_from_mp(&obj->ec_scalar, ec_group, mp);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_scalar_to_mp(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_scalar_obj_t *obj = janet_getabstract(argv, 0, get_ec_scalar_obj_type());

    botan_mpi_obj_t *mp_obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(mp_obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&mp_obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_ec_scalar_to_mp(obj->ec_scalar, &mp_obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(mp_obj);
}

static JanetReg ec_scalar_cfuns[] = {
    {"ec-scalar/random", ec_scalar_random,
     "(ec-scalar/random ec-group-obj rng-obj)\n\n"
     "Returns a new random scalar in `ec-group-obj` drawn from `rng-obj`."
    },
    {"ec-scalar/from-mp", ec_scalar_from_mp,
     "(ec-scalar/from-mp ec-group-obj mp-obj)\n\n"
     "Returns a new scalar in `ec-group-obj` from the given MPI `mp-obj`. "
     "`mp-obj` must satisfy `0 < mp-obj < order`."
    },
    {"ec-scalar/to-mp", ec_scalar_to_mp,
     "(ec-scalar/to-mp ec-scalar-obj)\n\n"
     "Returns the MPI object representing the value of `ec-scalar-obj`."
    },
    {NULL, NULL, NULL}
};

static void submod_ec_scalar(JanetTable *env) {
    janet_cfuns(env, "botan", ec_scalar_cfuns);
    janet_register_abstract_type(get_ec_scalar_obj_type());
}

#endif /* BOTAN_EC_SCALAR_H */
