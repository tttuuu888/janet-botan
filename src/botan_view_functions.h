/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_VIEW_FUNCTIONS_H
#define BOTAN_VIEW_FUNCTIONS_H

typedef struct view_data {
    uint8_t *data;
    size_t len;
} view_data_t;

static int view_bin_func(botan_view_ctx view_ctx, const uint8_t *bin, size_t len) {
    if (!view_ctx || !bin) {
        return BOTAN_FFI_ERROR_NULL_POINTER;
    }

    view_data_t *data = (view_data_t *)view_ctx;
    data->data = janet_smalloc(len);
    memcpy(data->data, bin, len);
    data->len = len;

    return 0;
}

static int view_str_func(botan_view_ctx view_ctx, const char *str, size_t len) {
    if (!view_ctx || !str) {
        return BOTAN_FFI_ERROR_NULL_POINTER;
    }

    view_data_t *data = (view_data_t *)view_ctx;
    data->data = janet_smalloc(len);
    memcpy(data->data, str, len);
    data->len = len;
    if (data->data[len - 1] == 0) {
        data->len -= 1;
    }

    return 0;
}

#endif /* BOTAN_VIEW_FUNCTIONS_H */
