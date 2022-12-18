/* Copyright (c) 2022 Mark Friedenbach, Karl-Johan Alm
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef WEBCASH__WEBCASH_H
#define WEBCASH__WEBCASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "sha256.h"

typedef bool (*webcash_callback_retrieve_data)(const char* key, uint8_t** data, size_t* len);

typedef void (*webcash_callback_store_data)(const char* key, const uint8_t* data, const size_t len);

typedef void (*webcash_callback_payment_data)(const char* error_or_nil, void* user_info, const char* payment_key);

typedef void (*webcash_callback_raise)(const char* exception);

typedef void (*webcash_callback_error)(const char* error_or_nil, void* user_info);

struct webcash_callbacks {
    webcash_callback_retrieve_data retrieve_data;
    webcash_callback_store_data store_data;

    webcash_callback_raise raise;
};

/**
 * Initialize webcash library with the given set of callbacks
 *
 * Set up webcash internally, and configure wallet from state retrieved from caller.
 *
 * @return whether state from a previous session was found
 */
bool webcash_init(struct webcash_callbacks);

/**
 * Create a webcash wallet from scratch, using the provided entropy, if any.
 */
void webcash_create(struct webcash_callbacks, struct sha256* entropy);

// Manage collection of keys (your wallet)

struct webcash_wallet_secret;
struct webcash_wallet_output;

typedef uint64_t webcash_amount;

webcash_amount webcash_get_balance(void);

struct webcash_wallet_secret* webcash_wallet_reserve_secret(uint64_t timestamp, bool mine, bool sweep);

void webcash_generate_payment(webcash_amount amount, void* user_info, webcash_callback_payment_data callback);

void webcash_insert(const char* secret, bool mine);

void webcash_save(void);

// Communicate with webcash server itself

void webcash_check_wallet(void* user_info, webcash_callback_error callback);

void webcash_recover_wallet(void* user_info, webcash_callback_error callback, int gap_limit);

#ifdef __cplusplus
}
#endif

#endif  /* WEBCASH__WEBCASH_H */

/* End of File
 */
