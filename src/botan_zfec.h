/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_ZFEC_H
#define BOTAN_ZFEC_H

static Janet zfec_encode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    size_t k = janet_getsize(argv, 0);
    size_t n = janet_getsize(argv, 1);
    JanetByteView input = janet_getbytes(argv, 2);

    if (input.len % k != 0) {
        janet_panicf("Input length %d is not a multipl of of k\n", input.len);
    }

    size_t block_size = (input.len / k);
    size_t output_size = (n * block_size);
    uint8_t *encoded_buf = (uint8_t*)janet_smalloc(output_size);
    uint8_t **encoded = janet_smalloc(sizeof(uint8_t *) * n);
    for (int i=0; i<n; i++) {
        encoded[i] = &encoded_buf[i * block_size];
    }

    int ret;
    ret = botan_zfec_encode(k, n, input.bytes, input.len, encoded);
    JANET_BOTAN_ASSERT(ret);

    Janet *tup = janet_tuple_begin(n);
    for(int i=0; i<n; i++) {
        tup[i] = janet_wrap_string(janet_string(encoded[i], block_size));
    }

    return janet_wrap_tuple(janet_tuple_n(tup, n));
}

static Janet zfec_decode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 4);
    size_t k = janet_getsize(argv, 0);
    size_t n = janet_getsize(argv, 1);
    JanetTuple indexes = janet_gettuple(argv, 2);
    JanetTuple inputs = janet_gettuple(argv, 3);

    int32_t indexes_len = janet_tuple_length(indexes);
    int32_t inputs_len = janet_tuple_length(inputs);

    if (inputs_len < k) {
        janet_panic("Insufficient inputs for zfec decoding");
    }

    size_t *index_arr = janet_smalloc(sizeof(size_t *) * indexes_len);
    for (int i=0; i<indexes_len; i++) {
        index_arr[i] = janet_getsize(indexes, i);
    }

    JanetByteView input0 = janet_getbytes(inputs, 0);
    size_t share_size = input0.len;
    uint8_t **input_arr = janet_smalloc(sizeof(uint8_t *) * inputs_len);
    for (int i=0; i<inputs_len; i++) {
        JanetByteView input = janet_getbytes(inputs, i);
        if (input.len != share_size) {
            janet_panic("All input shares must be of the same length.");
        }
        input_arr[i] = (uint8_t *)input.bytes;
    }

    size_t output_size = (k * share_size);
    uint8_t *decoded_buf = (uint8_t*)janet_smalloc(output_size);
    uint8_t **decoded = janet_smalloc(sizeof(uint8_t *) * k);
    for (int i=0; i<k; i++) {
        decoded[i] = &decoded_buf[i * share_size];
    }

    int ret;
    ret = botan_zfec_decode(k, n, index_arr, (uint8_t* const*)input_arr, share_size, decoded);
    JANET_BOTAN_ASSERT(ret);

    Janet *tup = janet_tuple_begin(k);
    for(int i=0; i<k; i++) {
        tup[i] = janet_wrap_string(janet_string(decoded[i], share_size));
    }

    return janet_wrap_tuple(janet_tuple_n(tup, k));
}

static JanetReg zfec_cfuns[] = {
    {"zfec-encode", zfec_encode,
     "(zfec-encode k n input)\n\n"
     "Perform forward error correction encoding. `k` is the number of shares required "
     "to recover the original. `n` is the total number of shares. The `input` length "
     "must be a multiple of K bytes.  Return n list of strings, each one containing a "
     "single share."
    },
    {"zfec-decode", zfec_decode,
     "(zfec-decode k n indexes inputs)\n\n"
     "Decode some FEC shares. `k` is the number of shares required to recover the "
     "original. `n` is the total number of shares. The `indexes` is the list specifies "
     "which shares are presented in `inputs`. `inputs` is the list of the input "
     "shares (e.g. from a previous call to zfec_encode) which all must be the same "
     "length. Return a list of strings containing the original shares decoded from the "
     "provided shares (in `inputs`)."
    },
    {NULL, NULL, NULL}
};

static void submod_zfec(JanetTable *env) {
    janet_cfuns(env, "botan", zfec_cfuns);
}

#endif /* BOTAN_ZFEC_H */
