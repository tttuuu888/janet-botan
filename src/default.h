/*
 * Copyright (c) 2024, Botan-janet Seungki Kim
 *
 * Botan-janet is released under the Simplified BSD License. (see LICENSE)
 */

#ifndef DEFAULT_H
#define DEFAULT_H

static Janet cfun_ffi_api_version(int32_t argc, Janet *argv) {
    (void)argc;
    (void)argv;
    uint32_t version = botan_ffi_api_version();
    return janet_wrap_number((double) version);
}

static JanetReg default_cfuns[] = {
    { "ffi-api-version", cfun_ffi_api_version, "(ffi-api-version)\n\n"
      "Return the version of the currently supported FFI API."
    },
    {NULL, NULL, NULL}
};

#endif /* DEFAULT_H */
