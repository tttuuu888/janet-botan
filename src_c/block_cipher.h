#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

static Janet cfun_block_cipher_init(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc;
    const char *name = janet_getstring(argv, 0);
    int ret = botan_block_cipher_init(&bc, name);
    if (ret)
        return janet_wrap_nil();

    return janet_wrap_pointer(bc);
}

static Janet cfun_block_cipher_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    int ret = botan_block_cipher_destroy(bc);
    return janet_wrap_nil();
}

static Janet cfun_block_cipher_block_size(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    int size = botan_block_cipher_block_size(bc);
    return janet_wrap_number((double)size);
}

static Janet cfun_block_cipher_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_block_cipher_t bc = janet_getpointer(argv, 0);
    size_t len = 32;
    char name[32] = {0,};
    int ret = botan_block_cipher_name(bc, name, &len);
    int name_len = strlen(name);
    uint8_t *out = janet_string_begin(name_len);
    memcpy(out, name, name_len);
    return janet_wrap_string(janet_string_end(out));
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
    {NULL, NULL, NULL}
};

#endif /* BLOCK_CIPHER_H */
