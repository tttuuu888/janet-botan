/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_SRP6_SERVER_SESSION_H
#define BOTAN_SRP6_SERVER_SESSION_H

typedef struct botan_srp6_server_session_obj {
    botan_srp6_server_session_t srp6_server_session;
    const char *group;
    size_t group_size;
} botan_srp6_server_session_obj_t;

/* Abstract Object functions */
static int srp6_server_session_gc_fn(void *data, size_t len);
static int srp6_server_session_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet srp6_server_session_step1(int32_t argc, Janet *argv);
static Janet srp6_server_session_step2(int32_t argc, Janet *argv);

static JanetAbstractType srp6_server_session_obj_type = {
    "botan/srp6_server_session",
    srp6_server_session_gc_fn,
    NULL,
    srp6_server_session_get_fn,
    JANET_ATEND_GET
};

static JanetMethod srp6_server_session_methods[] = {
    {"step1", srp6_server_session_step1},
    {"step2", srp6_server_session_step2},
    {NULL, NULL},
};

static JanetAbstractType *get_srp6_server_session_obj_type() {
    return &srp6_server_session_obj_type;
}

/* Abstract Object functions */
static int srp6_server_session_gc_fn(void *data, size_t len) {
    botan_srp6_server_session_obj_t *obj = (botan_srp6_server_session_obj_t *)data;

    int ret = botan_srp6_server_session_destroy(obj->srp6_server_session);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int srp6_server_session_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), srp6_server_session_methods, out);
}

/* Janet functions */
static Janet srp6_server_session_new(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_srp6_server_session_obj_t *obj = janet_abstract(&srp6_server_session_obj_type, sizeof(botan_srp6_server_session_obj_t));
    memset(obj, 0, sizeof(botan_srp6_server_session_obj_t));

    int ret = botan_srp6_server_session_init(&obj->srp6_server_session);
    JANET_BOTAN_ASSERT(ret);

    const char *group = janet_getcstring(argv, 0);
    size_t group_size = 0;

    ret = botan_srp6_group_size(group, &group_size);
    JANET_BOTAN_ASSERT(ret);

    obj->group = group;
    obj->group_size = group_size;

    return janet_wrap_abstract(obj);
}

static Janet srp6_server_session_step1(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);

    botan_srp6_server_session_obj_t *obj = janet_getabstract(argv, 0, get_srp6_server_session_obj_type());
    botan_srp6_server_session_t srp6 = obj->srp6_server_session;
    JanetByteView verifier = janet_getbytes(argv, 1);
    const char *group = obj->group;
    const char *hash = janet_getcstring(argv, 2);
    botan_rng_obj_t *obj2 = janet_getabstract(argv, 3, get_rng_obj_type());
    botan_rng_t rng = obj2->rng;

    size_t out_len = obj->group_size;
    JanetBuffer *out = janet_buffer(out_len);

    int ret = botan_srp6_server_session_step1(srp6, verifier.bytes, verifier.len,
                                          group, hash, rng, out->data, &out_len);
    if (!ret) {
        return janet_wrap_string(janet_string(out->data, out_len));
    } else if (ret && ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    out = janet_buffer(out_len);
    ret = botan_srp6_server_session_step1(srp6, verifier.bytes, verifier.len,
                                          group, hash, rng, out->data, &out_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(out->data, out_len));
}

static Janet srp6_server_session_step2(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_srp6_server_session_obj_t *obj = janet_getabstract(argv, 0, get_srp6_server_session_obj_type());
    botan_srp6_server_session_t srp6 = obj->srp6_server_session;
    JanetByteView A = janet_getbytes(argv, 1);
    JanetBuffer *K = janet_buffer(obj->group_size);
    size_t K_len = obj->group_size;

    int ret = botan_srp6_server_session_step2(srp6, A.bytes, A.len, K->data, &K_len);
    if (!ret) {
        return janet_wrap_string(janet_string(K->data, K_len));
    } else if (ret && ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    K = janet_buffer(obj->group_size);
    ret = botan_srp6_server_session_step2(srp6, A.bytes, A.len, K->data, &K_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(K->data, K_len));
}

static Janet srp6_generate_verifier(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 5);

    const char *identifier = janet_getcstring(argv, 0);
    const char *password = janet_getcstring(argv, 1);
    JanetByteView salt = janet_getbytes(argv, 2);
    const char *group = janet_getcstring(argv, 3);
    const char *hash = janet_getcstring(argv, 4);

    size_t verifier_len = 0;
    int ret = botan_srp6_group_size(group, &verifier_len);
    JANET_BOTAN_ASSERT(ret);

    JanetBuffer *verifier = janet_buffer(verifier_len);
    ret = botan_srp6_generate_verifier(identifier, password,
                                       salt.bytes, salt.len,
                                       group, hash,
                                       verifier->data, &verifier_len);
    if (!ret) {
        return janet_wrap_string(janet_string(verifier->data, verifier_len));
    } else if (ret && ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
        JANET_BOTAN_ASSERT(ret);
    }

    verifier = janet_buffer(verifier_len);
    ret = botan_srp6_generate_verifier(identifier, password,
                                       salt.bytes, salt.len,
                                       group, hash,
                                       verifier->data, &verifier_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(verifier->data, verifier_len));
}

static Janet srp6_client_agree(int32_t argc, Janet *argv) {
    janet_arity(argc, 6, 7);

    int ret;
    const char *username = janet_getcstring(argv, 0);
    const char *password = janet_getcstring(argv, 1);
    const char *group = janet_getcstring(argv, 2);
    const char *hash = janet_getcstring(argv, 3);
    JanetByteView salt = janet_getbytes(argv, 4);
    JanetByteView B = janet_getbytes(argv, 5);
    botan_rng_t rng;

    if (argc == 7) {
        botan_rng_obj_t *obj2 = janet_getabstract(argv, 6, get_rng_obj_type());
        rng = obj2->rng;
    } else {
        botan_rng_obj_t *obj2 = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
        memset(obj2, 0, sizeof(botan_rng_obj_t));
        ret = botan_rng_init(&obj2->rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng = obj2->rng;
    }

    size_t size = 0;
    ret = botan_srp6_group_size(group, &size);

    JanetBuffer *A = janet_buffer(size);
    JanetBuffer *K = janet_buffer(size);
    size_t A_len = size;
    size_t K_len = size;

    ret = botan_srp6_client_agree(username, password, group, hash,
                                  salt.bytes, salt.len,
                                  B.bytes, B.len,
                                  rng,
                                  A->data, &A_len,
                                  K->data, &K_len);
     if (ret && ret != BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
         JANET_BOTAN_ASSERT(ret);
     } else if (ret == BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE) {
         if (A_len > size) {
             A = janet_buffer(A_len);
         }
         if (K_len > size) {
             K = janet_buffer(K_len);
         }
         ret = botan_srp6_client_agree(username, password, group, hash,
                                       salt.bytes, salt.len,
                                       B.bytes, B.len,
                                       rng,
                                       A->data, &A_len,
                                       K->data, &K_len);
         JANET_BOTAN_ASSERT(ret);
     }

     Janet result[2] = {
         janet_wrap_string(janet_string(A->data, A_len)),
         janet_wrap_string(janet_string(K->data, K_len)),
     };
     return janet_wrap_tuple(janet_tuple_n(result, 2));
}

static JanetReg srp6_server_session_cfuns[] = {
    {"srp6-server-session/new", srp6_server_session_new,
     "(srp6-server-session/new group-id)\n\n"
     "Create srp6 server session object along with `group-id`."
    },
    {"srp6-server-session/step1", srp6_server_session_step1,
     "(srp6-server-session/step1 srp6-obj verifier hash rng)\n\n"
     "Takes a verifier (generated by srp6-generate-verifier) along with the "
     "group-id, and output a value B which is provided to the client."
    },
    {"srp6-server-session/step2", srp6_server_session_step2,
     "(srp6-server-session/step2 srp6-obj A)\n\n"
     "Takes the parameter A generated by srp6-client-agree, and return the "
     "shared secret key.\n\n"
     "In the event of an impersonation attack (or wrong username/password, "
     "etc) no error occurs, but the key returned will be different on the two "
     "sides. The two sides must verify each other, for example by using the "
     "shared secret to key an HMAC and then exchanging authenticated messages."
    },
    {"srp6-generate-verifier", srp6_generate_verifier,
     "(srp6-generate-verifier identifier password salt group-id hash)\n\n"
     "Generates a new verifier using the specified `password` and `salt`. "
     "This is stored by the server. The salt must also be stored. Later, "
     "the given username(`identifier`) and `password` are used to by the "
     "client during the key agreement step."
    },
    {"srp6-client-agree", srp6_client_agree,
     "(srp6-client-agree username password group-id hash salt B &opt rng)\n\n"
     "The client receives these parameters from the server, except for the "
     "`username` and `password` which are provided by the user. The parameter "
     "B is the output of step1.\n\n"
     "The client agreement step outputs a shared symmetric key along with the "
     "parameter A which is returned to the server (and allows it the compute "
     "the shared key)."
    },
    {NULL, NULL, NULL}
};

static void submod_srp6_server_session(JanetTable *env) {
    janet_cfuns(env, "botan", srp6_server_session_cfuns);
    janet_register_abstract_type(get_srp6_server_session_obj_type());
}

#endif /* BOTAN_SRP6_SERVER_SESSION_H */
