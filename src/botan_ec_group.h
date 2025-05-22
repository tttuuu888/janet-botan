/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_EC_GROUP_H
#define BOTAN_EC_GROUP_H

typedef struct botan_ec_group_obj {
    botan_ec_group_t ec_group;
} botan_ec_group_obj_t;

/* Abstract Object functions */
static int ec_group_gc_fn(void *data, size_t len);
static int ec_group_get_fn(void *data, Janet key, Janet *out);
static int ec_group_compare_fn(void *lhs, void *rhs);

/* Janet functions */
static Janet ec_group_to_der(int32_t argc, Janet *argv);
static Janet ec_group_to_pem(int32_t argc, Janet *argv);
static Janet ec_group_get_curve_oid(int32_t argc, Janet *argv);
static Janet ec_group_get_p(int32_t argc, Janet *argv);
static Janet ec_group_get_a(int32_t argc, Janet *argv);
static Janet ec_group_get_b(int32_t argc, Janet *argv);
static Janet ec_group_get_gx(int32_t argc, Janet *argv);
static Janet ec_group_get_gy(int32_t argc, Janet *argv);
static Janet ec_group_get_order(int32_t argc, Janet *argv);

static JanetAbstractType ec_group_obj_type = {
    "botan/ec_group",
    ec_group_gc_fn,
    NULL,
    ec_group_get_fn,
    NULL,   // put
    NULL,   // marshal
    NULL,   // unmarshal
    NULL,   // tostring
    ec_group_compare_fn,
    JANET_ATEND_HASH
};

static JanetMethod ec_group_methods[] = {
    {"to-der", ec_group_to_der},
    {"to-pem", ec_group_to_pem},
    {"get-curve-oid", ec_group_get_curve_oid},
    {"get-p", ec_group_get_p},
    {"get-a", ec_group_get_a},
    {"get-a", ec_group_get_a},
    {"get-b", ec_group_get_b},
    {"get-gx", ec_group_get_gx},
    {"get-gy", ec_group_get_gy},
    {"get-order", ec_group_get_order},
    {NULL, NULL},
};

static JanetAbstractType *get_ec_group_obj_type() {
    return &ec_group_obj_type;
}

/* Abstract Object functions */
static int ec_group_gc_fn(void *data, size_t len) {
    botan_ec_group_obj_t *obj = (botan_ec_group_obj_t *)data;

    int ret = botan_ec_group_destroy(obj->ec_group);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int ec_group_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), ec_group_methods, out);
}

static int ec_group_compare_fn(void *lhs, void *rhs) {
    botan_ec_group_obj_t *obj1 = (botan_ec_group_obj_t *)lhs;
    botan_ec_group_obj_t *obj2 = (botan_ec_group_obj_t *)rhs;

    int ret = botan_ec_group_equal(obj1->ec_group, obj2->ec_group);

    return (ret^1);
}

/* Janet functions */
static Janet ec_group_supports_application_specific_group(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);

    int r = 0;
    int ret = botan_ec_group_supports_application_specific_group(&r);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(r != 0);
}

static Janet ec_group_supports_named_group(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    const char *name = janet_getcstring(argv, 0);

    int r = 0;
    int ret = botan_ec_group_supports_named_group(name, &r);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(r != 0);
}

static Janet ec_group_from_params(int32_t argc, Janet *argv) {
    botan_ec_group_obj_t *obj = janet_abstract(&ec_group_obj_type, sizeof(botan_ec_group_obj_t));
    memset(obj, 0, sizeof(botan_ec_group_obj_t));

    janet_fixarity(argc, 7);

    botan_oid_obj_t *obj0 = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid = obj0->oid;

    botan_mpi_obj_t *obj1 = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t p = obj1->mpi;

    botan_mpi_obj_t *obj2 = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t a = obj2->mpi;

    botan_mpi_obj_t *obj3 = janet_getabstract(argv, 3, get_mpi_obj_type());
    botan_mp_t b = obj3->mpi;

    botan_mpi_obj_t *obj4 = janet_getabstract(argv, 4, get_mpi_obj_type());
    botan_mp_t gx = obj4->mpi;

    botan_mpi_obj_t *obj5 = janet_getabstract(argv, 5, get_mpi_obj_type());
    botan_mp_t gy = obj5->mpi;

    botan_mpi_obj_t *obj6 = janet_getabstract(argv, 6, get_mpi_obj_type());
    botan_mp_t order = obj6->mpi;

    int ret = botan_ec_group_from_params(&obj->ec_group, oid, p, a, b, gx, gy, order);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_group_from_ber(int32_t argc, Janet *argv) {
    botan_ec_group_obj_t *obj = janet_abstract(&ec_group_obj_type, sizeof(botan_ec_group_obj_t));
    memset(obj, 0, sizeof(botan_ec_group_obj_t));

    janet_fixarity(argc, 1);

    JanetByteView ber = janet_getbytes(argv, 0);
    int ret = botan_ec_group_from_ber(&obj->ec_group, (const uint8_t *)ber.bytes, ber.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_group_from_pem(int32_t argc, Janet *argv) {
    botan_ec_group_obj_t *obj = janet_abstract(&ec_group_obj_type, sizeof(botan_ec_group_obj_t));
    memset(obj, 0, sizeof(botan_ec_group_obj_t));

    janet_fixarity(argc, 1);

    const char *pem = janet_getcstring(argv, 0);
    int ret = botan_ec_group_from_pem(&obj->ec_group, pem);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_group_from_oid(int32_t argc, Janet *argv) {
    botan_ec_group_obj_t *obj = janet_abstract(&ec_group_obj_type, sizeof(botan_ec_group_obj_t));
    memset(obj, 0, sizeof(botan_ec_group_obj_t));

    janet_fixarity(argc, 1);

    botan_oid_obj_t *obj1 = janet_getabstract(argv, 0, get_oid_obj_type());
    botan_asn1_oid_t oid = obj1->oid;

    int ret = botan_ec_group_from_oid(&obj->ec_group, oid);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_group_from_name(int32_t argc, Janet *argv) {
    botan_ec_group_obj_t *obj = janet_abstract(&ec_group_obj_type, sizeof(botan_ec_group_obj_t));
    memset(obj, 0, sizeof(botan_ec_group_obj_t));

    janet_fixarity(argc, 1);

    const char *name = janet_getcstring(argv, 0);
    int ret = botan_ec_group_from_name(&obj->ec_group, name);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet ec_group_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    view_data_t data;
    int ret = botan_ec_group_view_der(ec_group, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet ec_group_to_pem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    view_data_t str;
    int ret = botan_ec_group_view_pem(ec_group, &str, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(str.data, str.len));
}

static Janet ec_group_get_curve_oid(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_oid_obj_t *obj1 = janet_abstract(&oid_obj_type, sizeof(botan_oid_obj_t));
    memset(obj1, 0, sizeof(botan_oid_obj_t));

    int ret = botan_ec_group_get_curve_oid(&obj1->oid, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet ec_group_get_p(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_mpi_obj_t *obj1 = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj1, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_ec_group_get_p(&obj1->mpi, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet ec_group_get_a(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_mpi_obj_t *obj1 = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj1, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_ec_group_get_a(&obj1->mpi, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet ec_group_get_b(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_mpi_obj_t *obj1 = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj1, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_ec_group_get_b(&obj1->mpi, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet ec_group_get_gx(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_mpi_obj_t *obj1 = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj1, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_ec_group_get_g_x(&obj1->mpi, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet ec_group_get_gy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_mpi_obj_t *obj1 = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj1, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_ec_group_get_g_y(&obj1->mpi, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet ec_group_get_order(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_ec_group_obj_t *obj = janet_getabstract(argv, 0, get_ec_group_obj_type());
    botan_ec_group_t ec_group = obj->ec_group;

    botan_mpi_obj_t *obj1 = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj1, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_ec_group_get_order(&obj1->mpi, ec_group);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static JanetReg ec_group_cfuns[] = {
    {"ec-group/supports-application-specific-group", ec_group_supports_application_specific_group,
     "(ec-group/supports-application-specific-group)\n\n"
     "Returns true if it is possible to register an application specific "
     "elliptic curve, false otherwise."
    },
    {"ec-group/supports-named-group", ec_group_supports_named_group,
     "(ec-group/supports-named-group name)\n\n"
     "Returns true if `name` is a supported EC group, false otherwise."
    },
    {"ec-group/from-params", ec_group_from_params,
     "(ec-group/from-params oid p a b gx gy order)\n\n"
     "Create a new EC Group from the given parameters. "
     "The `oid` is an OID object, `p`, `a`, `b`, `gx`, gy` and `order` are "
     "MPI objects."
    },
    {"ec-group/from-ber", ec_group_from_ber,
     "(ec-group/from-ber ber)\n\n"
     "Create a new EC Group from a BER encoded ECC domain parameter set."
    },
    {"ec-group/from-pem", ec_group_from_pem,
     "(ec-group/from-pem pem)\n\n"
     "Create a new EC Group from the PEM/ASN.1 encoding."
    },
    {"ec-group/from-oid", ec_group_from_oid,
     "(ec-group/from-oid oid)\n\n"
     "Create a new EC Group from a group named by an object identifier."
    },
    {"ec-group/from-name", ec_group_from_name,
     "(ec-group/from-name name)\n\n"
     "Create a new EC Group from a common group name (e.g., \"secp256r1\")."
    },
    {"ec-group/to-der", ec_group_to_der,
     "(ec-group/to-der ec-group-obj)\n\n"
     "Returns an EC Group in DER encoding."
    },
    {"ec-group/to-pem", ec_group_to_pem,
     "(ec-group/to-pem ec-group-obj)\n\n"
     "Returns an EC Group in PEM encoding."
    },
    {"ec-group/get-curve-oid", ec_group_get_curve_oid,
     "(ec-group/get-curve-oid ec-group-obj)\n\n"
     "Returns the curve OID object of an EC Group."
    },
    {"ec-group/get-p", ec_group_get_p,
     "(ec-group/get-p ec-group-obj)\n\n"
     "Returns the MPI object representing the prime modulus of the elliptic "
     "curve field."
    },
    {"ec-group/get-a", ec_group_get_a,
     "(ec-group/get-a ec-group-obj)\n\n"
     "Returns the MPI object representing the `a` parameter of the elliptic "
     "curve equation."
    },
    {"ec-group/get-b", ec_group_get_b,
     "(ec-group/get-b ec-group-obj)\n\n"
     "Returns the MPI object representing the `b` parameter of the elliptic "
     "curve equation."
    },
    {"ec-group/get-gx", ec_group_get_gx,
     "(ec-group/get-gx ec-group-obj)\n\n"
     "Returns the MPI object representing the `x` coordinate of the base "
     "point."
    },
    {"ec-group/get-gy", ec_group_get_gy,
     "(ec-group/get-gy ec-group-obj)\n\n"
     "Returns the MPI object representing the `y` coordinate of the base "
     "point."
    },
    {"ec-group/get-order", ec_group_get_order,
     "(ec-group/get-order ec-group-obj)\n\n"
     "Returns the MPI object representing the order of the base point."
    },
    {NULL, NULL, NULL}
};

static void submod_ec_group(JanetTable *env) {
    janet_cfuns(env, "botan", ec_group_cfuns);
    janet_register_abstract_type(get_ec_group_obj_type());
}

#endif /* BOTAN_EC_GROUP_H */
