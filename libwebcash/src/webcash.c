/* Copyright (c) 2022 Mark Friedenbach, Karl-Johan Alm
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <stdio.h>

#include "webcash.h"

struct webcash_item {
    int id;
    uint64_t timestamp;
};

struct webcash_wallet_secret {
    struct webcash_item item;
    const char* secret;
    bool mine;
    bool sweep;
};

struct webcash_wallet_output {
    struct webcash_item item;
    struct sha256 hash;
    struct webcash_wallet_secret secret;
    uint64_t amount;
    bool spent;
};

struct generic_info {
    void* user_info;
    void* cb;
};

void webcash_generate_payment(webcash_amount amount, void* user_info, webcash_callback_payment_data callback) {
    //
}
