/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

static Janet cfun_block_cipher_init(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc;
    const char *name = (const char *)janet_getstring(argv, 0);

    int ret = botan_block_cipher_init(&bc, name);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_pointer(bc);
}

static Janet cfun_block_cipher_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);

    int ret = botan_block_cipher_destroy(bc);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_block_cipher_block_size(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);

    int size = botan_block_cipher_block_size(bc);
    JANET_BOTAN_ASSERT(size);

    return janet_wrap_number((double)size);
}

static Janet cfun_block_cipher_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    size_t len = 32;
    char name[32] = {0,};

    int ret = botan_block_cipher_name(bc, name, &len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string((const uint8_t *)name, strlen(name)));
}

static Janet cfun_block_cipher_get_keyspec(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    size_t min_key, max_key, mod_key;

    int ret = botan_block_cipher_get_keyspec(bc, &min_key, &max_key, &mod_key);
    JANET_BOTAN_ASSERT(ret);

    Janet spec[3] = {janet_wrap_number((double)min_key),
                     janet_wrap_number((double)max_key),
                     janet_wrap_number((double)mod_key)};
    return janet_wrap_tuple(janet_tuple_n(spec, 3));
}

static Janet cfun_block_cipher_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    size_t spec;

    int ret = botan_block_cipher_get_keyspec(bc, NULL, NULL, &spec);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_block_cipher_set_key(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    JanetByteView key = janet_getbytes(argv, 1);

    int ret = botan_block_cipher_set_key(bc, key.bytes, key.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_block_cipher_encrypt_blocks(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    JanetByteView input = janet_getbytes(argv, 1);
    JanetBuffer *output = janet_buffer(input.len);

    int size = botan_block_cipher_block_size(bc);
    JANET_BOTAN_ASSERT(size);

    int blocks = input.len / size;
    int ret = botan_block_cipher_encrypt_blocks(bc, input.bytes, output->data, blocks);
    JANET_BOTAN_ASSERT(ret);

    output->count = input.len;
    return janet_wrap_buffer(output);
}

static Janet cfun_block_cipher_decrypt_blocks(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    JanetByteView input = janet_getbytes(argv, 1);
    JanetBuffer *output = janet_buffer(input.len);

    int size = botan_block_cipher_block_size(bc);
    JANET_BOTAN_ASSERT(size);

    int blocks = input.len / size;
    int ret = botan_block_cipher_decrypt_blocks(bc, input.bytes, output->data, blocks);
    JANET_BOTAN_ASSERT(ret);

    output->count = input.len;
    return janet_wrap_buffer(output);
}

static JanetReg block_cipher_cfuns[] = {
    {"block-cipher/init", cfun_block_cipher_init,
     "(block-cipher/init name)\n\n"
     "Create a new cipher mode object, `name` should be for example "
     "\"AES-128\" or \"Threefish-512\""
    },
    {"block-cipher/destroy", cfun_block_cipher_destroy,
     "(block-cipher/destroy bc)\n\n"
     "Destroy the cipher object created by `block-cipher/init`."
    },
    {"block-cipher/block-size", cfun_block_cipher_block_size,
     "(block-cipher/block-size bc)\n\n"
     "Return the block size of this cipher."
    },
    {"block-cipher/name", cfun_block_cipher_name,
     "(block-cipher/name bc)\n\n"
     "Return the name of this block cipher algorithm, which may nor may not "
     " exactly match what was passed to `block-cipher/init`."
    },
    {"block-cipher/get-keyspec", cfun_block_cipher_get_keyspec,
     "(block-cipher/get-keyspec mac)\n\n"
     "Return the key spec of this cipher in format of "
     "[max-key-length min-key-length mod-key-length]."
    },
    {"block-cipher/clear", cfun_block_cipher_clear,
     "(block-cipher/clear bc)\n\n"
     "Clear the internal state (such as keys) of this cipher object, "
     "but do not deallocate it."
    },
    {"block-cipher/set-key", cfun_block_cipher_set_key,
     "(block-cipher/clear bc key)\n\n"
     "Set the cipher key, which is required before encrypting or decrypting."
    },
    {"block-cipher/encrypt", cfun_block_cipher_encrypt_blocks,
     "(block-cipher/encrypt bc input)\n\n"
     "Encrypt `input` data. The key must have been set beforehand."
    },
    {"block-cipher/decrypt", cfun_block_cipher_decrypt_blocks,
     "(block-cipher/decrypt bc input)\n\n"
     "Decrypt `input` data. The key must have been set beforehand."
    },
    {NULL, NULL, NULL}
};

#endif /* BLOCK_CIPHER_H */
