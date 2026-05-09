/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_EC_POINT_H
#define BOTAN_EC_POINT_H

typedef struct botan_ec_point_obj {
    botan_ec_point_t ec_point;
} botan_ec_point_obj_t;

/* Abstract Object functions */
static int ec_point_gc_fn(void *data, size_t len);
static int ec_point_get_fn(void *data, Janet key, Janet *out);
static int ec_point_compare_fn(void *lhs, void *rhs);

/* Janet functions */
static Janet ec_point_identity(int32_t argc, Janet *argv);
static Janet ec_point_generator(int32_t argc, Janet *argv);
static Janet ec_point_from_xy(int32_t argc, Janet *argv);
static Janet ec_point_from_bytes(int32_t argc, Janet *argv);
static Janet ec_point_get_x(int32_t argc, Janet *argv);
static Janet ec_point_get_y(int32_t argc, Janet *argv);
static Janet ec_point_get_xy(int32_t argc, Janet *argv);
static Janet ec_point_to_uncompressed(int32_t argc, Janet *argv);
static Janet ec_point_to_compressed(int32_t argc, Janet *argv);
static Janet ec_point_is_identity(int32_t argc, Janet *argv);
static Janet ec_point_negate(int32_t argc, Janet *argv);
static Janet ec_point_add(int32_t argc, Janet *argv);
static Janet ec_point_mul(int32_t argc, Janet *argv);

static JanetAbstractType ec_point_obj_type = {
    "botan/ec_point",
    ec_point_gc_fn,
    NULL,
    ec_point_get_fn,
    NULL,   // put
    NULL,   // marshal
    NULL,   // unmarshal
    NULL,   // tostring
    ec_point_compare_fn,
    JANET_ATEND_HASH
};

static JanetMethod ec_point_methods[] = {
    {"get-x", ec_point_get_x},
    {"get-y", ec_point_get_y},
    {"get-xy", ec_point_get_xy},
    {"to-uncompressed", ec_point_to_uncompressed},
    {"to-compressed", ec_point_to_compressed},
    {"is-identity", ec_point_is_identity},
    {"negate", ec_point_negate},
    {"add", ec_point_add},
    {"mul", ec_point_mul},
    {NULL, NULL},
};

static JanetAbstractType *get_ec_point_obj_type() {
    return &ec_point_obj_type;
}

/* Abstract Object functions */
static int ec_point_gc_fn(void *data, size_t len) {
    botan_ec_point_obj_t *obj = (botan_ec_point_obj_t *)data;

    int ret = botan_ec_point_destroy(obj->ec_point);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int ec_point_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), ec_point_methods, out);
}

static int ec_point_compare_fn(void *lhs, void *rhs) {
    botan_ec_point_obj_t *obj1 = (botan_ec_point_obj_t *)lhs;
    botan_ec_point_obj_t *obj2 = (botan_ec_point_obj_t *)rhs;

    int ret = botan_ec_point_equal(obj1->ec_point, obj2->ec_point);

    return (ret^1);
}

/* Janet functions */
static Janet ec_point_identity(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *grp_obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = grp_obj->ec_group;

    botan_ec_point_obj_t *obj = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(obj, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_identity(&obj->ec_point, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_point_generator(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *grp_obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = grp_obj->ec_group;

    botan_ec_point_obj_t *obj = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(obj, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_generator(&obj->ec_point, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_point_from_xy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_ec_group_obj_t *grp_obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = grp_obj->ec_group;
    botan_mpi_obj_t *x_obj = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t x = x_obj->mpi;
    botan_mpi_obj_t *y_obj = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t y = y_obj->mpi;

    botan_ec_point_obj_t *obj = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(obj, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_from_xy(&obj->ec_point, ec_group, x, y);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_point_from_bytes(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_ec_group_obj_t *grp_obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = grp_obj->ec_group;
    JanetByteView bytes = janet_getbytes(argv, 1);

    botan_ec_point_obj_t *obj = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(obj, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_from_bytes(&obj->ec_point, ec_group,
                                        (const uint8_t *)bytes.bytes, bytes.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_point_get_x(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    view_data_t data;
    int ret = botan_ec_point_view_x_bytes(obj->ec_point, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet ec_point_get_y(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    view_data_t data;
    int ret = botan_ec_point_view_y_bytes(obj->ec_point, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet ec_point_get_xy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    view_data_t data;
    int ret = botan_ec_point_view_xy_bytes(obj->ec_point, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet ec_point_to_uncompressed(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    view_data_t data;
    int ret = botan_ec_point_view_uncompressed(obj->ec_point, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet ec_point_to_compressed(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    view_data_t data;
    int ret = botan_ec_point_view_compressed(obj->ec_point, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet ec_point_is_identity(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    int ret = botan_ec_point_is_identity(obj->ec_point);
    if (ret < 0) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 1);
}

static Janet ec_point_negate(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_point_obj_t *obj = janet_getabstract(argv, 0, get_ec_point_obj_type());

    botan_ec_point_obj_t *out = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(out, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_negate(&out->ec_point, obj->ec_point);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(out);
}

static Janet ec_point_add(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_ec_point_obj_t *p1 = janet_getabstract(argv, 0, get_ec_point_obj_type());
    botan_ec_point_obj_t *p2 = janet_getabstract(argv, 1, get_ec_point_obj_type());

    botan_ec_point_obj_t *out = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(out, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_add(&out->ec_point, p1->ec_point, p2->ec_point);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(out);
}

static Janet ec_point_mul(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_ec_point_obj_t *p = janet_getabstract(argv, 0, get_ec_point_obj_type());
    botan_ec_scalar_obj_t *s = janet_getabstract(argv, 1, get_ec_scalar_obj_type());
    botan_rng_obj_t *rng_obj = janet_getabstract(argv, 2, get_rng_obj_type());

    botan_ec_point_obj_t *out = janet_abstract(&ec_point_obj_type, sizeof(botan_ec_point_obj_t));
    memset(out, 0, sizeof(botan_ec_point_obj_t));

    int ret = botan_ec_point_mul(&out->ec_point, p->ec_point, s->ec_scalar, rng_obj->rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(out);
}

static JanetReg ec_point_cfuns[] = {
    {"ec-point/identity", ec_point_identity,
     "(ec-point/identity ec-group-obj)\n\n"
     "Returns the identity element (point at infinity) of `ec-group-obj`."
    },
    {"ec-point/generator", ec_point_generator,
     "(ec-point/generator ec-group-obj)\n\n"
     "Returns the standard generator point of `ec-group-obj`."
    },
    {"ec-point/from-xy", ec_point_from_xy,
     "(ec-point/from-xy ec-group-obj x y)\n\n"
     "Returns a point on `ec-group-obj` from the affine integer coordinates "
     "`x` and `y` (MPI objects). Both must be within the field and satisfy "
     "the curve equation."
    },
    {"ec-point/from-bytes", ec_point_from_bytes,
     "(ec-point/from-bytes ec-group-obj bytes)\n\n"
     "Returns a point on `ec-group-obj` decoded from a SEC1 compressed or "
     "uncompressed encoding `bytes`."
    },
    {"ec-point/get-x", ec_point_get_x,
     "(ec-point/get-x ec-point-obj)\n\n"
     "Returns the fixed-length encoding of the affine x coordinate of "
     "`ec-point-obj`."
    },
    {"ec-point/get-y", ec_point_get_y,
     "(ec-point/get-y ec-point-obj)\n\n"
     "Returns the fixed-length encoding of the affine y coordinate of "
     "`ec-point-obj`."
    },
    {"ec-point/get-xy", ec_point_get_xy,
     "(ec-point/get-xy ec-point-obj)\n\n"
     "Returns the fixed-length concatenated encoding of the affine x and y "
     "coordinates of `ec-point-obj`."
    },
    {"ec-point/to-uncompressed", ec_point_to_uncompressed,
     "(ec-point/to-uncompressed ec-point-obj)\n\n"
     "Returns the SEC1 uncompressed encoding of `ec-point-obj`."
    },
    {"ec-point/to-compressed", ec_point_to_compressed,
     "(ec-point/to-compressed ec-point-obj)\n\n"
     "Returns the SEC1 compressed encoding of `ec-point-obj`."
    },
    {"ec-point/is-identity", ec_point_is_identity,
     "(ec-point/is-identity ec-point-obj)\n\n"
     "Returns true if `ec-point-obj` is the identity element, false otherwise."
    },
    {"ec-point/negate", ec_point_negate,
     "(ec-point/negate ec-point-obj)\n\n"
     "Returns the negation `-P` of `ec-point-obj`."
    },
    {"ec-point/add", ec_point_add,
     "(ec-point/add ec-point-obj1 ec-point-obj2)\n\n"
     "Returns the point `P + Q`."
    },
    {"ec-point/mul", ec_point_mul,
     "(ec-point/mul ec-point-obj ec-scalar-obj rng-obj)\n\n"
     "Returns the scalar multiplication `k*P`. `rng-obj` is used internally "
     "for side-channel blinding."
    },
    {NULL, NULL, NULL}
};

static void submod_ec_point(JanetTable *env) {
    janet_cfuns(env, "botan", ec_point_cfuns);
    janet_register_abstract_type(get_ec_point_obj_type());
}

#endif /* BOTAN_EC_POINT_H */
