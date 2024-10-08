/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_VERSIONING_H
#define BOTAN_VERSIONING_H

static Janet cfun_ffi_api_version(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    uint32_t version = botan_ffi_api_version();
    return janet_wrap_number((double)version);
}

static Janet cfun_ffi_supports_api(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    int64_t version = janet_getinteger64(argv, 0);

    int ret = botan_ffi_supports_api((uint32_t)version);
    return janet_wrap_boolean(ret == 0);
}

static Janet cfun_version_string(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    const char *version = botan_version_string();
    return janet_wrap_string(janet_string((const uint8_t *)version, strlen(version)));
}

static Janet cfun_version_major(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    uint32_t version = botan_version_major();
    return janet_wrap_number((double)version);
}

static Janet cfun_version_minor(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    uint32_t version = botan_version_minor();
    return janet_wrap_number((double)version);
}

static Janet cfun_version_patch(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    uint32_t version = botan_version_patch();
    return janet_wrap_number((double)version);
}

static Janet cfun_version_datestamp(int32_t argc, Janet *argv) {
    (void)argv;
    janet_fixarity(argc, 0);

    uint32_t version = botan_version_datestamp();
    return janet_wrap_number((double)version);
}

static JanetReg versioning_cfuns[] = {
    {"ffi-api-version", cfun_ffi_api_version, "(ffi-api-version)\n\n"
      "Return the version of the currently supported FFI API."
    },
    {"ffi-supports-api", cfun_ffi_supports_api,
     "(ffi-supports-api version)\n\n"
     "Check if the FFI version specified is supported by this library. "
     "Returns a boolean."
    },
    {"version-string", cfun_version_string, "(version-string)\n\n"
     "Returns a string describing the version."
    },
    {"version-major", cfun_version_major, "(version-major)\n\n"
     "Returns the major version of the library."
    },
    {"version-minor", cfun_version_minor, "(version-minor)\n\n"
     "Returns the minor version of the library."
    },
    {"version-patch", cfun_version_patch, "(version-patch)\n\n"
     "Returns the patch version of the library."
    },
    {"version-datestamp", cfun_version_datestamp, "(version-datestamp)\n\n"
     "Returns the date this version was released as an integer YYYYMMDD,"
     "or 0 if an unreleased version."
    },
    {NULL, NULL, NULL}
};

static void submod_versioning(JanetTable *env) {
    janet_cfuns(env, "botan", versioning_cfuns);
}

#endif /* BOTAN_VERSIONING_H */
