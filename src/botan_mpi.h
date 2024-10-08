/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_MPI_H
#define BOTAN_MPI_H

typedef struct botan_mpi_obj {
    botan_mp_t mpi;
} botan_mpi_obj_t;

/* Abstract Object functions */
static int mpi_gc_fn(void *data, size_t len);
static int mpi_get_fn(void *data, Janet key, Janet *out);
static int mpi_compare_fn(void *p1, void *p2);

/* Janet functions */
static Janet mpi_new(int32_t argc, Janet *argv);
static Janet mpi_new_int(int32_t argc, Janet *argv);
static Janet mpi_new_str(int32_t argc, Janet *argv);
static Janet mpi_new_hex_str(int32_t argc, Janet *argv);
static Janet mpi_new_mpi(int32_t argc, Janet *argv);
static Janet mpi_new_rng(int32_t argc, Janet *argv);
static Janet mpi_inverse_mod(int32_t argc, Janet *argv);
static Janet mpi_pow_mod(int32_t argc, Janet *argv);
static Janet mpi_mod_mul(int32_t argc, Janet *argv);
static Janet mpi_gcd(int32_t argc, Janet *argv);
static Janet mpi_is_prime(int32_t argc, Janet *argv);
static Janet mpi_get_bit(int32_t argc, Janet *argv);
static Janet mpi_set_bit(int32_t argc, Janet *argv);
static Janet mpi_clear_bit(int32_t argc, Janet *argv);
static Janet mpi_is_zero(int32_t argc, Janet *argv);
static Janet mpi_is_positive(int32_t argc, Janet *argv);
static Janet mpi_is_negative(int32_t argc, Janet *argv);
static Janet mpi_flip_sign(int32_t argc, Janet *argv);
static Janet mpi_add(int32_t argc, Janet *argv);
static Janet mpi_sub(int32_t argc, Janet *argv);
static Janet mpi_mul(int32_t argc, Janet *argv);
static Janet mpi_div(int32_t argc, Janet *argv);
static Janet mpi_swap(int32_t argc, Janet *argv);
static Janet mpi_lshift(int32_t argc, Janet *argv);
static Janet mpi_rshift(int32_t argc, Janet *argv);
static Janet mpi_num_bytes(int32_t argc, Janet *argv);
static Janet mpi_to_u32(int32_t argc, Janet *argv);
static Janet mpi_to_bin(int32_t argc, Janet *argv);

static JanetAbstractType mpi_obj_type = {
    "botan/mpi",
    mpi_gc_fn,
    NULL,                       /* gcmark */
    mpi_get_fn,
    NULL,                       /* put */
    NULL,                       /* marshal */
    NULL,                       /* unmarshal */
    NULL,                       /* tostring */
    mpi_compare_fn,
    JANET_ATEND_COMPARE
};

static JanetMethod mpi_methods[] = {
    {"inverse-mod", mpi_inverse_mod},
    {"pow-mod", mpi_pow_mod},
    {"mod-mul", mpi_mod_mul},
    {"gcd", mpi_gcd},
    {"is-prime", mpi_is_prime},
    {"get-bit", mpi_get_bit},
    {"set-bit", mpi_get_bit},
    {"clear-bit", mpi_clear_bit},
    {"is-zero", mpi_is_zero},
    {"is-positive", mpi_is_positive},
    {"is-negative", mpi_is_negative},
    {"flip-sign", mpi_flip_sign},
    {"add", mpi_add},
    {"sub", mpi_sub},
    {"mul", mpi_mul},
    {"div", mpi_div},
    {"swap", mpi_swap},
    {"lshift", mpi_lshift},
    {"rshift", mpi_rshift},
    {"num-bytes", mpi_num_bytes},
    {"to-u32", mpi_to_u32},
    {"to-bin", mpi_to_bin},
    {NULL, NULL},
};

static JanetAbstractType *get_mpi_obj_type() {
    return &mpi_obj_type;
}

/* Abstract Object functions */
static int mpi_gc_fn(void *data, size_t len) {
    botan_mpi_obj_t *obj = (botan_mpi_obj_t *)data;

    int ret = botan_mp_destroy(obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int mpi_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), mpi_methods, out);
}

static int mpi_compare_fn(void *p1, void *p2) {
    botan_mpi_obj_t *obj1 = (botan_mpi_obj_t *)p1;
    botan_mpi_obj_t *obj2 = (botan_mpi_obj_t *)p2;

    int result = 0;
    int ret = botan_mp_cmp(&result, obj1->mpi, obj2->mpi);
    JANET_BOTAN_ASSERT(ret);

    return result;
}

/* Janet functions */
static Janet mpi_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);
    botan_mpi_obj_t *obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_new_int(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    int64_t x = janet_getinteger64(argv, 0);
    ret = botan_mp_set_from_int(obj->mpi, x);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_new_str(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    JanetByteView val = janet_getbytes(argv, 0);
    ret = botan_mp_set_from_str(obj->mpi, (const char *)val.bytes);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_new_hex_str(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj->mpi);
    JANET_BOTAN_ASSERT(ret);
    JanetByteView val = janet_getbytes(argv, 0);

    ret = botan_mp_set_from_radix_str(obj->mpi, (const char *)val.bytes, 16);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_new_mpi(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    botan_mpi_obj_t *obj2 = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi2 = obj2->mpi;
    ret = botan_mp_set_from_mp(obj->mpi, mpi2);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_new_rng(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj->mpi);
    JANET_BOTAN_ASSERT(ret);

    botan_rng_obj_t *obj2 = janet_getabstract(argv, 0, get_rng_obj_type());
    botan_rng_t rng = obj2->rng;
    size_t bits = janet_getsize(argv, 1);
    ret = botan_mp_rand_bits(obj->mpi, rng, bits);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_inverse_mod(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mpi_obj_t *obj_mod = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_mod_inverse(obj_out->mpi, obj->mpi, obj_mod->mpi);
    JANET_BOTAN_ASSERT(ret);

    if (obj_out->mpi == (botan_mp_t)-1) {
        return janet_wrap_nil();
    }

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_pow_mod(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_exp = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_exp = obj_exp->mpi;

    botan_mpi_obj_t *obj_mod = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_mod = obj_mod->mpi;

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_powmod(obj_out->mpi, mpi, mpi_exp, mpi_mod);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_mod_mul(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_other = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_other = obj_other->mpi;

    botan_mpi_obj_t *obj_exp = janet_getabstract(argv, 2, get_mpi_obj_type());
    botan_mp_t mpi_exp = obj_exp->mpi;

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_mod_mul(obj_out->mpi, mpi, mpi_other, mpi_exp);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_gcd(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_other = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_other = obj_other->mpi;

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_gcd(obj_out->mpi, mpi, mpi_other);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_is_prime(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_rng_obj_t *obj2 = janet_getabstract(argv, 1, get_rng_obj_type());
    botan_rng_t rng = obj2->rng;

    size_t prob = janet_optsize(argv, argc, 2, 128);
    int ret = botan_mp_is_prime(mpi, rng, prob);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet mpi_get_bit(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t bit = janet_getsize(argv, 1);

    int ret = botan_mp_get_bit(mpi, bit);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet mpi_set_bit(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t bit = janet_getsize(argv, 1);

    int ret = botan_mp_set_bit(mpi, bit);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_clear_bit(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t bit = janet_getsize(argv, 1);

    int ret = botan_mp_clear_bit(mpi, bit);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_is_zero(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    int ret = botan_mp_is_zero(mpi);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet mpi_is_positive(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    int ret = botan_mp_is_positive(mpi);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet mpi_is_negative(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    int ret = botan_mp_is_negative(mpi);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 1);
}

static Janet mpi_flip_sign(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    int ret = botan_mp_flip_sign(mpi);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet mpi_add(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    if (janet_checktype(argv[1], JANET_NUMBER)) {
        uint64_t input = janet_getuinteger64(argv, 1);
        if (input > UINT32_MAX) {
            janet_panic("The argument size exceeds the uint32_t range.");
        }

        uint32_t x = (uint32_t)input;

        ret = botan_mp_add_u32(obj_out->mpi, mpi, x);
        JANET_BOTAN_ASSERT(ret);
    } else if (janet_checktype(argv[1], JANET_ABSTRACT)) {
        botan_mpi_obj_t *obj_other = janet_getabstract(argv, 1, get_mpi_obj_type());
        botan_mp_t mpi_other = obj_other->mpi;

        ret = botan_mp_add(obj_out->mpi, mpi, mpi_other);
        JANET_BOTAN_ASSERT(ret);
    } else {
        janet_panic("Unexpected argument");
    }

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_sub(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    if (janet_checktype(argv[1], JANET_NUMBER)) {
        uint64_t input = janet_getuinteger64(argv, 1);
        if (input > UINT32_MAX) {
            janet_panic("The argument size exceeds the uint32_t range.");
        }

        uint32_t x = (uint32_t)input;

        ret = botan_mp_sub_u32(obj_out->mpi, mpi, x);
        JANET_BOTAN_ASSERT(ret);
    } else if (janet_checktype(argv[1], JANET_ABSTRACT)) {
        botan_mpi_obj_t *obj_other = janet_getabstract(argv, 1, get_mpi_obj_type());
        botan_mp_t mpi_other = obj_other->mpi;

        ret = botan_mp_sub(obj_out->mpi, mpi, mpi_other);
        JANET_BOTAN_ASSERT(ret);
    } else {
        janet_panic("Unexpected argument");
    }

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_mul(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_other = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_other = obj_other->mpi;

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_mul(obj_out->mpi, mpi, mpi_other);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_div(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;

    botan_mpi_obj_t *obj_other = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi_other = obj_other->mpi;

    botan_mpi_obj_t *obj_quotient = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_quotient, 0, sizeof(botan_mpi_obj_t));
    int ret = botan_mp_init(&obj_quotient->mpi);
    JANET_BOTAN_ASSERT(ret);

    botan_mpi_obj_t *obj_remainder = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_remainder, 0, sizeof(botan_mpi_obj_t));
    ret = botan_mp_init(&obj_remainder->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_div(obj_quotient->mpi, obj_remainder->mpi, mpi, mpi_other);
    JANET_BOTAN_ASSERT(ret);

    Janet result[2] = {janet_wrap_abstract(obj_quotient),
                       janet_wrap_abstract(obj_remainder)};
    return janet_wrap_tuple(janet_tuple_n(result, 2));
}

static Janet mpi_swap(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj1 = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi1 = obj1->mpi;

    botan_mpi_obj_t *obj2 = janet_getabstract(argv, 1, get_mpi_obj_type());
    botan_mp_t mpi2 = obj2->mpi;

    int ret = botan_mp_swap(mpi1, mpi2);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj1);
}

static Janet mpi_lshift(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t shift = janet_getsize(argv, 1);

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_lshift(obj_out->mpi, mpi, shift);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_rshift(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t shift = janet_getsize(argv, 1);

    botan_mpi_obj_t *obj_out = janet_abstract(&mpi_obj_type, sizeof(botan_mpi_obj_t));
    memset(obj_out, 0, sizeof(botan_mpi_obj_t));

    int ret = botan_mp_init(&obj_out->mpi);
    JANET_BOTAN_ASSERT(ret);

    ret = botan_mp_rshift(obj_out->mpi, mpi, shift);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj_out);
}

static Janet mpi_num_bytes(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t bytes;

    int ret = botan_mp_num_bytes(mpi, &bytes);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)bytes);
}

static Janet mpi_to_u32(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    uint32_t val;

    int ret = botan_mp_to_uint32(mpi, &val);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)val);
}

static Janet mpi_to_bin(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_mpi_obj_t *obj = janet_getabstract(argv, 0, get_mpi_obj_type());
    botan_mp_t mpi = obj->mpi;
    size_t bytes;

    int ret = botan_mp_num_bytes(mpi, &bytes);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *vec = janet_buffer(bytes);

    ret = botan_mp_to_bin(mpi, vec->data);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(vec->data, bytes));
}

static JanetReg mpi_cfuns[] = {
    {"mpi/new", mpi_new,
     "(mpi/new)\n\n"
     "Create a new zero-valued MPI. Returns `mpi-obj`."
    },
    {"mpi/from-int", mpi_new_int,
     "(mpi/from-int value)\n\n"
     "Create an MPI object with an integer `value`. Returns `mpi-obj`."
    },
    {"mpi/from-str", mpi_new_str,
     "(mpi/from-str value)\n\n"
     "Create an MPI object with an integer string `value`. Returns `mpi-obj`."
    },
    {"mpi/from-hex-str", mpi_new_hex_str,
     "(mpi/from-hex-str value)\n\n"
     "Create an MPI object with a hex string `value`. Returns `mpi-obj`."
    },
    {"mpi/from-mpi", mpi_new_mpi,
     "(mpi/from-mpi mpi-obj)\n\n"
     "Create an MPI object with an MPI object `mpi`. Returns new `mpi-obj`."
    },
    {"mpi/from-rng", mpi_new_rng,
     "(mpi/from-rng rng bits)\n\n"
     "Create a `bits` size random MPI object with `rng`. Returns `mpi-obj`."
    },
    {"mpi/inverse-mod", mpi_inverse_mod,
     "(mpi/inverse-mod mpi-obj modulus)\n\n"
     "Create the inverse of `mpi-obj` modulo `modulus`, or nil if no inverse exists."
     "Returns new `mpi-obj`."
    },
    {"mpi/pow-mod", mpi_pow_mod,
     "(mpi/pow-mod mpi-obj exponent modulus)\n\n"
     "Create new `mpi-obj` to the `exponent` `mpi-obj` power modulo `modulus` `mpi-obj`."
     "Returns new `mpi-obj`."
    },
    {"mpi/mod-mul", mpi_mod_mul,
     "(mpi/mod-mul mpi-obj other-mpi-obj modulus)\n\n"
     "Create new `mpi-obj` of the multiplication product of `mpi-obj` and "
     "`other-mpi-obj` modulo `modulus`. Returns new `mpi-obj`."
    },
    {"mpi/gcd", mpi_gcd,
     "(mpi/gcd mpi-obj other-mpi-obj)\n\n"
     "Create new `mpi-obj` of the greatest common divisor of `mpi-obj` and `other-mpi-obj`."
    },
    {"mpi/is-prime", mpi_is_prime,
     "(mpi/is-prime mpi-obj rng &opt prob)\n\n"
     "Return true if `mpi-obj` is prime, otherwise returns false. "
     "Default value of prob is 128."
    },
    {"mpi/get-bit", mpi_get_bit,
     "(mpi/get-bit mpi-obj bit)\n\n"
     "Returns 0 if the specified `bit` of `mpi-obj` is not set, 1 if it is set."
    },
    {"mpi/set-bit", mpi_set_bit,
     "(mpi/set-bit mpi-obj bit)\n\n"
     "Set the specified `bit` of `mpi-obj`. Returns `mpi-obj`."
    },
    {"mpi/clear-bit", mpi_clear_bit,
     "(mpi/clear-bit mpi-obj bit)\n\n"
     "Clears the specified `bit` of `mpi-obj`. Returns `mpi-obj`."
    },
    {"mpi/is-zero", mpi_is_zero,
     "(mpi/is-zero mpi-obj)\n\n"
     "Return true if `mpi-obj` is zero, otherwise returns false."
    },
    {"mpi/is-positive", mpi_is_positive,
     "(mpi/is-positive mpi-obj)\n\n"
     "Return true if `mpi-obj` is greater than or equal to zero. otherwise return false."
    },
    {"mpi/is-negative", mpi_is_negative,
     "(mpi/is-negative mpi-obj)\n\n"
     "Return true if `mpi-obj` is less than zero, otherwise return false."
    },
    {"mpi/flip-sign", mpi_flip_sign,
     "(mpi/flip-sign mpi-obj)\n\n"
     "Flip the sign of `mpi-obj`. Returns `mpi-obj`."
    },
    {"mpi/add", mpi_add,
     "(mpi/add mpi-obj x)\n\n"
     "Add x to `mpi-obj` and return the new `mpi-obj`. `x` can be either "
     "`mpi-obj` or u32 number."
    },
    {"mpi/sub", mpi_sub,
     "(mpi/sub mpi-obj x)\n\n"
     "Subtract x from `mpi-obj` and return the new `mpi-obj`. `x` can be "
     "either `mpi-obj` or u32 number."
    },
    {"mpi/mul", mpi_mul,
     "(mpi/sub mpi-obj-1 mpi-obj-2)\n\n"
     "Multiply two `mpi-obj` and return the new `mpi-obj` as a result."
    },
    {"mpi/div", mpi_div,
     "(mpi/div mpi-obj-1 mpi-obj-2)\n\n"
     "Divide `mpi-obj-1` by `mpi-obj-2`. Create new quotient `mpi-obj` and remainder "
     "`mpi-obj`. Return quotient `mpi-obj` and remainder `mpi-obj` in tuple."
    },
    {"mpi/swap", mpi_swap,
     "(mpi/swap mpi-obj-1 mpi-obj-2)\n\n"
     "Swap `mpi-obj-1` and `mpi-obj-2` values, Return `mpi-obj-1`."
    },
    {"mpi/lshift", mpi_lshift,
     "(mpi/lshift mpi-obj shift)\n\n"
     "Left shift by specified `shift` bit count. Return new `mpj-obj`."
    },
    {"mpi/rshift", mpi_rshift,
     "(mpi/rshift mpi-obj shift)\n\n"
     "Right shift by specified `shift` bit count. Return new `mpj-obj`."
    },
    {"mpi/num-bytes", mpi_num_bytes,
     "(mpi/num-bytes mpi-obj)\n\n"
     "Return the number of significant bytes in the `mpi-obj`."
    },
    {"mpi/to-u32", mpi_to_u32,
     "(mpi/to-u32 mpi-obj)\n\n"
     "Convert the `mpi-obj` to a uint32_t, if possible. Fails if `mpi-obj` is negative "
     "or too large."
    },
    {"mpi/to-bin", mpi_to_bin,
     "(mpi/to-bin mpi-obj)\n\n"
     "Convert the `mpi-obj` to a binary and return as a string."
    },

    {NULL, NULL, NULL}
};

static void submod_mpi(JanetTable *env) {
    janet_cfuns(env, "botan", mpi_cfuns);
    janet_register_abstract_type(get_mpi_obj_type());
}

#endif /* BOTAN_MPI_H */
