/*
 * Copyright (c) 2026, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_X509_CRL_H
#define BOTAN_X509_CRL_H

/* External C++ functions for x509 crl */
extern int jbotan_x509_crl_to_pem(
    botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_str_fn view);
extern int jbotan_x509_crl_to_der(
    botan_x509_crl_t crl, botan_view_ctx ctx, botan_view_bin_fn view);

/* Janet functions x509-crl */
static Janet x509_crl_create(int32_t argc, Janet *argv);
static Janet x509_crl_revoke(int32_t argc, Janet *argv);
static Janet x509_crl_verify(int32_t argc, Janet *argv);
static Janet x509_crl_to_pem(int32_t argc, Janet *argv);
static Janet x509_crl_to_der(int32_t argc, Janet *argv);
static Janet x509_crl_this_update(int32_t argc, Janet *argv);
static Janet x509_crl_next_update(int32_t argc, Janet *argv);
static Janet x509_crl_entries_count(int32_t argc, Janet *argv);
static Janet x509_crl_get_entry(int32_t argc, Janet *argv);
static Janet x509_crl_is_revoked(int32_t argc, Janet *argv);

static JanetMethod x509_crl_methods[] = {
    {"to-pem", x509_crl_to_pem},
    {"to-der", x509_crl_to_der},
    {"this-update", x509_crl_this_update},
    {"next-update", x509_crl_next_update},
    {"entries-count", x509_crl_entries_count},
    {"get-entry", x509_crl_get_entry},
    {"is-revoked", x509_crl_is_revoked},
    {"revoke", x509_crl_revoke},
    {"verify", x509_crl_verify},
    {NULL, NULL},
};

/* Abstract Object functions x509-crl */
static int x509_crl_gc_fn(void *data, size_t len) {
    botan_x509_crl_obj_t *obj = (botan_x509_crl_obj_t *)data;

    int ret = botan_x509_crl_destroy(obj->x509_crl);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int x509_crl_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), x509_crl_methods, out);
}

static const char *x509_crl_reason_str(int code) {
    switch (code) {
        case 0:  return "Unspecified";
        case 1:  return "Key Compromise";
        case 2:  return "CA Compromise";
        case 3:  return "Affiliation Changed";
        case 4:  return "Superseded";
        case 5:  return "Cessation of Operation";
        case 6:  return "Certificate Hold";
        case 8:  return "Remove from CRL";
        case 9:  return "Privilege Withdrawn";
        case 10: return "AA Compromise";
        default: return "Unknown";
    }
}

static void x509_crl_format_time(uint64_t epoch, char *out, size_t out_len) {
    time_t t = (time_t)epoch;
    struct tm *tm_ptr = gmtime(&t);
    if (tm_ptr) {
        strftime(out, out_len, "%Y-%m-%d %H:%M:%S UTC", tm_ptr);
    } else {
        out[0] = '\0';
    }
}

static void x509_crl_format_hex_bytes(JanetBuffer *buffer, const uint8_t *bytes,
                                      size_t len, const char *indent,
                                      size_t bytes_per_line) {
    char hex[4];
    for (size_t i = 0; i < len; i++) {
        if (i % bytes_per_line == 0) {
            if (i > 0) janet_buffer_push_u8(buffer, '\n');
            janet_buffer_push_cstring(buffer, indent);
        } else {
            janet_buffer_push_u8(buffer, ':');
        }
        snprintf(hex, sizeof(hex), "%02x", bytes[i]);
        janet_buffer_push_cstring(buffer, hex);
    }
    janet_buffer_push_u8(buffer, '\n');
}

static void x509_crl_describe(botan_x509_crl_t crl, JanetBuffer *buffer) {
    char timebuf[32];
    char numbuf[32];
    char hex[4];
    int ret;
    int reason_code;
    uint64_t epoch;
    size_t count;
    view_data_t data;

    janet_buffer_push_cstring(buffer, "X.509 CRL\n");

    /* This Update */
    ret = botan_x509_crl_this_update(crl, &epoch);
    JANET_BOTAN_ASSERT(ret);

    x509_crl_format_time(epoch, timebuf, sizeof(timebuf));
    janet_formatb(buffer, "    This Update: %s\n", timebuf);

    /* Next Update (optional in spec) */
    ret = botan_x509_crl_next_update(crl, &epoch);
    if (ret == 0) {
        x509_crl_format_time(epoch, timebuf, sizeof(timebuf));
        janet_formatb(buffer, "    Next Update: %s\n", timebuf);
    }

    /* CRL Number (optional, big-endian integer) */
    ret = botan_x509_crl_view_binary_values(crl, BOTAN_X509_SERIAL_NUMBER, 0, &data,
                                            (botan_view_bin_fn)view_bin_func);
    if (ret == 0 && data.len > 0) {
        uint64_t n = 0;
        for (size_t i = 0; i < data.len && i < 8; i++) {
            n = (n << 8) | data.data[i];
        }
        snprintf(numbuf, sizeof(numbuf), "%llu", (unsigned long long)n);
        janet_buffer_push_cstring(buffer, "    CRL Number: ");
        janet_buffer_push_cstring(buffer, numbuf);
        janet_buffer_push_u8(buffer, '\n');
    }

    /* Authority Key Identifier (optional) */
    ret = botan_x509_crl_view_binary_values(crl, BOTAN_X509_AUTHORITY_KEY_IDENTIFIER, 0,
                                            &data, (botan_view_bin_fn)view_bin_func);
    if (ret == 0 && data.len > 0) {
        janet_buffer_push_cstring(buffer, "    Authority Key Identifier:\n");
        x509_crl_format_hex_bytes(buffer, data.data, data.len, "        ", 16);
    }

    /* Revoked Certificates */
    ret = botan_x509_crl_entries_count(crl, &count);
    JANET_BOTAN_ASSERT(ret);

    snprintf(numbuf, sizeof(numbuf), "%llu", (unsigned long long)count);
    janet_buffer_push_cstring(buffer, "Revoked Certificates: ");
    janet_buffer_push_cstring(buffer, numbuf);
    janet_buffer_push_u8(buffer, '\n');
    for (size_t i = 0; i < count; i++) {
        botan_x509_crl_entry_t entry = NULL;
        ret = botan_x509_crl_entries(crl, i, &entry);
        JANET_BOTAN_ASSERT(ret);

        ret = botan_x509_crl_entry_view_serial_number(entry, &data, (botan_view_bin_fn)view_bin_func);
        JANET_BOTAN_ASSERT(ret);

        janet_buffer_push_cstring(buffer, "    Serial Number: ");
        for (size_t j = 0; j < data.len; j++) {
            snprintf(hex, sizeof(hex), "%02x", data.data[j]);
            janet_buffer_push_cstring(buffer, hex);
        }
        janet_buffer_push_u8(buffer, '\n');

        ret = botan_x509_crl_entry_revocation_date(entry, &epoch);
        JANET_BOTAN_ASSERT(ret);

        x509_crl_format_time(epoch, timebuf, sizeof(timebuf));
        janet_formatb(buffer, "        Revocation Date: %s\n", timebuf);

        ret = botan_x509_crl_entry_reason(entry, &reason_code);
        JANET_BOTAN_ASSERT(ret);
        janet_formatb(buffer, "        Reason: %s\n", x509_crl_reason_str(reason_code));

        ret = botan_x509_crl_entry_destroy(entry);
        JANET_BOTAN_ASSERT(ret);
    }

    /* Signature */
    ret = botan_x509_crl_view_binary_values(crl, BOTAN_X509_SIGNATURE_BITS, 0, &data,
                                            (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    janet_buffer_push_cstring(buffer, "Signature:\n");
    x509_crl_format_hex_bytes(buffer, data.data, data.len, "    ", 16);
}

static void x509_crl_tostring_fn(void *p, JanetBuffer *buffer) {
    botan_x509_crl_obj_t *obj = (botan_x509_crl_obj_t *)p;
    janet_buffer_push_u8(buffer, '\n');
    x509_crl_describe(obj->x509_crl, buffer);
}

struct crl_reason_pair {
    const char *name;
    int value;
};

static struct crl_reason_pair crl_reason_table[] = {
    {"unspecified",            0},
    {"key-compromise",         1},
    {"ca-compromise",          2},
    {"affiliation-changed",    3},
    {"superseded",             4},
    {"cessation-of-operation", 5},
    {"certificate-hold",       6},
    {"remove-from-crl",        8},
    {"privilege-withdrawn",    9},
    {"aa-compromise",          10}
};
static const size_t crl_reason_table_len = sizeof(crl_reason_table)/sizeof(crl_reason_table[0]);

static int crl_reason_from_janet(Janet val) {
    if (janet_checktype(val, JANET_NUMBER)) {
        return (int)janet_unwrap_number(val);
    }
    if (janet_checktype(val, JANET_KEYWORD)) {
        JanetKeyword kw = janet_unwrap_keyword(val);
        for (size_t i = 0; i < crl_reason_table_len; i++) {
            if (!janet_cstrcmp(kw, crl_reason_table[i].name))
                return crl_reason_table[i].value;
        }
        janet_panicf("unknown CRL reason keyword :%s, expected one of: "
                     ":unspecified, :key-compromise, :ca-compromise, "
                     ":affiliation-changed, :superseded, :cessation-of-operation, "
                     ":certificate-hold, :remove-from-crl, :privilege-withdrawn, "
                     ":aa-compromise", kw);
    }
    janet_panic("CRL reason must be a keyword or integer");
    return 0;
}

/* Janet functions x509-crl */
static Janet x509_crl_load(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    JanetByteView crl = janet_getbytes(argv, 0);

    int ret = botan_x509_crl_load(&obj->x509_crl, crl.bytes, crl.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_load_file(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    const char *filename = janet_getcstring(argv, 0);

    int ret = botan_x509_crl_load_file(&obj->x509_crl, filename);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_to_pem(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    view_data_t data;
    int ret = jbotan_x509_crl_to_pem(crl, &data, (botan_view_str_fn)view_str_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_crl_to_der(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    view_data_t data;
    int ret = jbotan_x509_crl_to_der(crl, &data, (botan_view_bin_fn)view_bin_func);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string(data.data, data.len));
}

static Janet x509_crl_this_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    uint64_t time_since_epoch;
    int ret = botan_x509_crl_this_update(crl, &time_since_epoch);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_crl_next_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    uint64_t time_since_epoch;
    int ret = botan_x509_crl_next_update(crl, &time_since_epoch);
    if (ret == BOTAN_FFI_ERROR_NO_VALUE) {
        return janet_wrap_nil();
    }

    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)time_since_epoch);
}

static Janet x509_crl_entries_count(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    size_t count;
    int ret = botan_x509_crl_entries_count(crl, &count);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)count);
}

static Janet x509_crl_get_entry(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;
    size_t index = janet_getsize(argv, 1);

    botan_x509_crl_entry_obj_t *entry_obj = janet_abstract(&x509_crl_entry_obj_type, sizeof(botan_x509_crl_entry_obj_t));
    memset(entry_obj, 0, sizeof(botan_x509_crl_entry_obj_t));

    int ret = botan_x509_crl_entries(crl, index, &entry_obj->entry);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(entry_obj);
}

static Janet x509_crl_is_revoked(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_crl_t crl = obj->x509_crl;

    botan_x509_cert_obj_t *obj2 = janet_getabstract(argv, 1, get_x509_cert_obj_type());
    botan_x509_cert_t cert = obj2->x509_cert;

    int ret = botan_x509_is_revoked(crl, cert);
    /* ret: 0 = revoked, -1 = not revoked */
    if (ret != 0 && ret != -1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 0);
}

static Janet x509_crl_entry_create(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_cert_obj_t *cert_obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    int reason_code = crl_reason_from_janet(argv[1]);

    botan_x509_crl_entry_obj_t *entry_obj = janet_abstract(&x509_crl_entry_obj_type, sizeof(botan_x509_crl_entry_obj_t));
    memset(entry_obj, 0, sizeof(botan_x509_crl_entry_obj_t));

    int ret = botan_x509_crl_entry_create(&entry_obj->entry, cert_obj->x509_cert, reason_code);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(entry_obj);
}

static Janet x509_crl_create(int32_t argc, Janet *argv) {
    janet_arity(argc, 4, -1);

    botan_x509_cert_obj_t *ca_cert_obj = janet_getabstract(argv, 0, get_x509_cert_obj_type());
    botan_private_key_obj_t *ca_key_obj = janet_getabstract(argv, 1, get_private_key_obj_type());
    uint64_t issue_time = (uint64_t)janet_getnumber(argv, 2);
    uint32_t next_update = (uint32_t)janet_getnumber(argv, 3);

    botan_rng_t rng = 0;
    botan_rng_obj_t *rng_obj = NULL;
    const char *hash_fn = NULL;
    const char *padding = NULL;
    int rng_created = 0;

    for (int i = 4; i < argc; i += 2) {
        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "rng")) {
            rng_obj = janet_getabstract(argv, i + 1, get_rng_obj_type());
        } else if (!janet_cstrcmp(keyword, "hash")) {
            hash_fn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "padding")) {
            padding = janet_getcstring(argv, i + 1);
        } else {
            janet_panicf("unknown keyword :%s", keyword);
        }
    }

    if (rng_obj) {
        rng = rng_obj->rng;
    } else {
        int ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng_created = 1;
    }

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    int ret = botan_x509_crl_create(&obj->x509_crl, rng,
                                    ca_cert_obj->x509_cert, ca_key_obj->private_key,
                                    issue_time, next_update,
                                    hash_fn, padding);

    if (rng_created) botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_revoke(int32_t argc, Janet *argv) {
    janet_arity(argc, 6, -1);

    botan_x509_crl_obj_t *crl_obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_x509_cert_obj_t *ca_cert_obj = janet_getabstract(argv, 1, get_x509_cert_obj_type());
    botan_private_key_obj_t *ca_key_obj = janet_getabstract(argv, 2, get_private_key_obj_type());
    uint64_t issue_time = (uint64_t)janet_getnumber(argv, 3);
    uint32_t next_update = (uint32_t)janet_getnumber(argv, 4);

    /* entries: tuple of crl-entry objects */
    JanetView entries = janet_getindexed(argv, 5);

    botan_rng_t rng = 0;
    botan_rng_obj_t *rng_obj = NULL;
    const char *hash_fn = NULL;
    const char *padding = NULL;
    int rng_created = 0;

    for (int i = 6; i < argc; i += 2) {
        JanetKeyword keyword = janet_getkeyword(argv, i);
        if (!janet_cstrcmp(keyword, "rng")) {
            rng_obj = janet_getabstract(argv, i + 1, get_rng_obj_type());
        } else if (!janet_cstrcmp(keyword, "hash")) {
            hash_fn = janet_getcstring(argv, i + 1);
        } else if (!janet_cstrcmp(keyword, "padding")) {
            padding = janet_getcstring(argv, i + 1);
        } else {
            janet_panicf("unknown keyword :%s", keyword);
        }
    }

    botan_x509_crl_entry_t *entry_arr = janet_smalloc(sizeof(botan_x509_crl_entry_t) * entries.len);
    for (int32_t j = 0; j < entries.len; j++) {
        botan_x509_crl_entry_obj_t *e = janet_getabstract(entries.items, j, get_x509_crl_entry_obj_type());
        entry_arr[j] = e->entry;
    }

    if (rng_obj) {
        rng = rng_obj->rng;
    } else {
        int ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);
        rng_created = 1;
    }

    botan_x509_crl_obj_t *obj = janet_abstract(&x509_crl_obj_type, sizeof(botan_x509_crl_obj_t));
    memset(obj, 0, sizeof(botan_x509_crl_obj_t));

    int ret = botan_x509_crl_update(&obj->x509_crl, crl_obj->x509_crl, rng,
                                    ca_cert_obj->x509_cert, ca_key_obj->private_key,
                                    issue_time, next_update,
                                    entry_arr, (size_t)entries.len,
                                    hash_fn, padding);

    janet_sfree(entry_arr);
    if (rng_created) botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet x509_crl_verify(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_x509_crl_obj_t *obj = janet_getabstract(argv, 0, get_x509_crl_obj_type());
    botan_public_key_obj_t *key_obj = janet_getabstract(argv, 1, get_public_key_obj_type());

    int ret = botan_x509_crl_verify_signature(obj->x509_crl, key_obj->public_key);
    if (ret != 0 && ret != 1) {
        JANET_BOTAN_ASSERT(ret);
    }

    return janet_wrap_boolean(ret == 1);
}

static JanetReg x509_crl_cfuns[] = {
    {"x509-crl/to-pem", x509_crl_to_pem,
     "(x509-crl/to-pem crl)\n\n"
     "Encode the CRL as a PEM string."
    },
    {"x509-crl/to-der", x509_crl_to_der,
     "(x509-crl/to-der crl)\n\n"
     "Encode the CRL as DER binary data."
    },
    {"x509-crl/load", x509_crl_load,
     "(x509-crl/load crl)\n\n"
     "Load a CRL from the DER or PEM representation."
    },
    {"x509-crl/load-file", x509_crl_load_file,
     "(x509-crl/load file-name)\n\n"
     "Load a CRL from a file."
    },
    {"x509-crl/this-update", x509_crl_this_update,
     "(x509-crl/this-update crl-obj)\n\n"
     "Return the time the CRL was issued, as seconds since epoch."
    },
    {"x509-crl/next-update", x509_crl_next_update,
     "(x509-crl/next-update crl-obj)\n\n"
     "Return the time the next CRL update is expected, as seconds since epoch. "
     "Return `nil` if the CRL has no nextUpdate field, which is optional."
    },
    {"x509-crl/entries-count", x509_crl_entries_count,
     "(x509-crl/entries-count crl-obj)\n\n"
     "Return the number of entries in the CRL."
    },
    {"x509-crl/get-entry", x509_crl_get_entry,
     "(x509-crl/get-entry crl-obj index)\n\n"
     "Return the CRL entry at the given `index`. Use `x509-crl/entries-count` "
     "to get the number of entries."
    },
    {"x509-crl/is-revoked", x509_crl_is_revoked,
     "(x509-crl/is-revoked crl cert)\n\n"
     "Check if the given `cert` is revoked on the given `crl`. "
     "Return true when the certificate is revoked."
    },
    {"x509-crl/create", x509_crl_create,
     "(x509-crl/create ca-cert ca-key issue-time next-update "
     "&keys {:rng rng :hash hash :padding padding})\n\n"
     "Create a new empty CRL signed by the given CA.\n\n"
     "* `ca-cert` - The CA certificate object.\n\n"
     "* `ca-key` - The CA's private key object.\n\n"
     "* `issue-time` - The time when the CRL becomes valid, as seconds "
     "since epoch.\n\n"
     "* `next-update` - The number of seconds after issue-time until the "
     "CRL expires.\n\n"
     "* `:rng` - A random number generator object. Default is system RNG.\n\n"
     "* `:hash` - Hash algorithm name. Default is \"SHA-256\".\n\n"
     "* `:padding` - Padding scheme. Default depends on key type: "
     "\"PKCS1v15\" for RSA, hash name for DSA/ECDSA, \"Pure\" for Ed25519/Ed448."
    },
    {"x509-crl/revoke", x509_crl_revoke,
     "(x509-crl/revoke crl ca-cert ca-key issue-time next-update entries "
     "&keys {:rng rng :hash hash :padding padding})\n\n"
     "Update a CRL with new revoked entries, creating a new CRL. "
     "The original CRL is not modified.\n\n"
     "* `crl` - The existing CRL to update.\n\n"
     "* `ca-cert` - The CA certificate object.\n\n"
     "* `ca-key` - The CA's private key object.\n\n"
     "* `issue-time` - The time when the new CRL becomes valid, as seconds "
     "since epoch.\n\n"
     "* `next-update` - The number of seconds after issue-time until the "
     "CRL expires.\n\n"
     "* `entries` - A tuple/array of CRL entry objects created with "
     "`x509-crl-entry/create`.\n\n"
     "* `:rng` - A random number generator object. Default is system RNG.\n\n"
     "* `:hash` - Hash algorithm name. Default is \"SHA-256\".\n\n"
     "* `:padding` - Padding scheme. Default depends on key type: "
     "\"PKCS1v15\" for RSA, hash name for DSA/ECDSA, \"Pure\" for Ed25519/Ed448."
    },
    {"x509-crl/verify", x509_crl_verify,
     "(x509-crl/verify crl pubkey)\n\n"
     "Verify the CRL signature against the given public key. "
     "Returns true if the signature is valid."
    },
    {NULL, NULL, NULL}
};

static void submod_x509_crl(JanetTable *env) {
    janet_cfuns(env, "botan", x509_crl_cfuns);
    janet_register_abstract_type(get_x509_crl_obj_type());
}

#endif /* BOTAN_X509_CRL_H */
