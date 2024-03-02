/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#ifndef RANDOM_H
#define RANDOM_H

static botan_rng_t local_rng;

static inline void local_init_once(void){
    static char local_rng_init = 0;
    if (local_rng_init != 0)
        return;

    int ret = botan_rng_init(&local_rng, "system");
    local_rng_init = 1;
}

static Janet cfun_rng_get(int32_t argc, Janet *argv) {
    local_init_once();
    janet_fixarity(argc, 1);

    int64_t len = janet_getinteger64(argv, 0);
    JanetArray *out = janet_array(len);
    uint8_t *out_raw = janet_smalloc(len);

    int ret = botan_rng_get(local_rng, out_raw, len);
    for(int i=0; i<len; i++)
        out->data[i] = janet_wrap_number(out_raw[i]);

    janet_sfree(out_raw);
    out->count = len;
    return janet_wrap_array(out);
}

static JanetReg random_cfuns[] = {
    {"rng-get", cfun_rng_get, "(rng-get len)\n\n"
     "Get random bytes of length len from a random number generator."
    },
    {NULL, NULL, NULL}
};

#endif /* RANDOM_H */
