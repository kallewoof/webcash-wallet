/* Copyright (c) 2022 Mark Friedenbach, Karl-Johan Alm
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sha256.h"
#include "webcash.h"

struct webcash_database_key {
    size_t id;
    time_t timestamp;
};

struct webcash_terms {
    struct webcash_database_key dbkey;
    char* body;
};

struct webcash_wallet_secret {
    struct webcash_wallet_secret *next;
    struct webcash_database_key dbkey;
    char* str;
    bool mine;
    bool sweep;
};

struct webcash_wallet_output {
    struct webcash_wallet_output *next;
    struct webcash_database_key dbkey;
    struct sha256 hash;
    struct webcash_wallet_secret* secret;
    uint64_t amount;
    bool spent;
};

enum webcash_chain_type {
    // Outputs added via explicit import.  These are shown as visible, discrete
    // inputs to the wallet.  The wallet always redeems received webcash upon
    // import under the assumption that the imported secret value is still known
    // to others or otherwise not secure.
    RECEIVE = 0,

    // Outputs generated as payments to others.  These are intended to be
    // immediately claimed by the other party, but we keep the key in this
    // wallet in case there are problems completing the transaction.
    PAYMENT = 1,

    // Internal webcash generated either to redeem payments or mined webcash,
    // change from a payment, or the consolidation of such outputs.  These
    // outputs count towards the current balance of the wallet, but aren't shown
    // explicitly.
    CHANGE = 2,

    // Outputs generated via a mining report.  These are seen as visible inputs
    // to a wallet, aggregated as "mining income."  The wallet always redeems
    // mining inputs for change immediately after generation, in case the mining
    // reports (which contain the secret) are made public.
    MINING = 3,

    MAX_CHAINS = 4,
};

struct webcash_wallet_hdkey {
    struct webcash_wallet_hdkey *next;
    struct webcash_database_key dbkey;
    size_t depth;
    struct webcash_wallet_secret* secret;
};

struct webcash_wallet_hdchain {
    struct webcash_database_key dbkey;
    bool mine; // <-- the lower 2 bits of chaincode
    bool sweep; //    come from these two fields.
    size_t mindepth;
    size_t maxdepth;
    struct webcash_wallet_hdkey* keys;
};

struct webcash_wallet_hdroot {
    struct webcash_database_key dbkey;
    struct sha256 seed;
    int version; // <-- 0 if uninitialized
    struct webcash_wallet_hdchain chain[MAX_CHAINS];
};

struct webcash_wallet {
    struct webcash_callbacks callbacks;
    struct webcash_wallet_secret* secrets;
    struct webcash_wallet_output* outputs;
    struct webcash_wallet_hdroot hdroot;
    size_t num_hdkeys;
};

bool g_is_initialized = false;
struct webcash_wallet g_wallet;

bool webcash_init(const struct webcash_callbacks callbacks) {
    if (g_is_initialized) {
        g_wallet.callbacks.raise("webcash_init() called twice");
        return false; // Never reached
    }
    return false; // need to call webcash_create()
}

// Call operating system to get random bytes
void GetStrongRandBytes(unsigned char* buf, int num) {
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        g_wallet.callbacks.raise("GetStrongRandBytes() failed to open /dev/urandom");
        return; // Never reached
    }
    if (fread(buf, 1, num, urandom) != num) {
        g_wallet.callbacks.raise("GetStrongRandBytes() failed to read from /dev/urandom");
        return; // Never reached
    }
    fclose(urandom);
}

void webcash_create(const struct webcash_callbacks callbacks, struct sha256* entropy) {
    if (g_is_initialized) {
        g_wallet.callbacks.raise("webcash_create() called on existing wallet");
        return; // Never reached
    }

    // This should load the wallet from the database, but for now we just
    // create a new, empty wallet.
    time_t timestamp = time(NULL);
    g_wallet.hdroot.dbkey.id = 0;
    g_wallet.hdroot.dbkey.timestamp = timestamp;
    GetStrongRandBytes(g_wallet.hdroot.seed.u8, 32);
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    if (entropy) {
        sha256_update(&ctx, entropy->u8, 32);
    }
    sha256_update(&ctx, g_wallet.hdroot.seed.u8, 32);
    sha256_done(&g_wallet.hdroot.seed, &ctx);
    g_wallet.hdroot.version = 1;
    g_wallet.num_hdkeys = 0;

    g_wallet.hdroot.chain[RECEIVE].dbkey.id = 0;
    g_wallet.hdroot.chain[RECEIVE].dbkey.timestamp = timestamp;
    g_wallet.hdroot.chain[RECEIVE].mine = false;
    g_wallet.hdroot.chain[RECEIVE].sweep = true;
    g_wallet.hdroot.chain[RECEIVE].mindepth = 0;
    g_wallet.hdroot.chain[RECEIVE].maxdepth = 0;
    g_wallet.hdroot.chain[RECEIVE].keys = NULL;

    g_wallet.hdroot.chain[PAYMENT].dbkey.id = 0;
    g_wallet.hdroot.chain[PAYMENT].dbkey.timestamp = timestamp;
    g_wallet.hdroot.chain[PAYMENT].mine = false;
    g_wallet.hdroot.chain[PAYMENT].sweep = false;
    g_wallet.hdroot.chain[PAYMENT].mindepth = 0;
    g_wallet.hdroot.chain[PAYMENT].maxdepth = 0;
    g_wallet.hdroot.chain[PAYMENT].keys = NULL;

    g_wallet.hdroot.chain[CHANGE].dbkey.id = 0;
    g_wallet.hdroot.chain[CHANGE].dbkey.timestamp = timestamp;
    g_wallet.hdroot.chain[CHANGE].mine = true;
    g_wallet.hdroot.chain[CHANGE].sweep = false;
    g_wallet.hdroot.chain[CHANGE].mindepth = 0;
    g_wallet.hdroot.chain[CHANGE].maxdepth = 0;
    g_wallet.hdroot.chain[CHANGE].keys = NULL;

    g_wallet.hdroot.chain[MINING].dbkey.id = 0;
    g_wallet.hdroot.chain[MINING].dbkey.timestamp = timestamp;
    g_wallet.hdroot.chain[MINING].mine = true;
    g_wallet.hdroot.chain[MINING].sweep = true;
    g_wallet.hdroot.chain[MINING].mindepth = 0;
    g_wallet.hdroot.chain[MINING].maxdepth = 0;
    g_wallet.hdroot.chain[MINING].keys = NULL;
}

static void BytesToHexString(char* hex, const uint8_t* bytes, size_t len) {
    char hexmap[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[2*i] = hexmap[(bytes[i] >> 4) & 0xf];
        hex[2*i + 1] = hexmap[bytes[i] & 0xf];
    }
}

struct webcash_wallet_secret* webcash_wallet_reserve_secret(uint64_t timestamp, bool mine, bool sweep) {
    if (!g_is_initialized) {
        g_wallet.callbacks.raise("webcash_wallet_reserve_secret() called before webcash_init()");
        return NULL; // Never reached
    }

    struct webcash_wallet_hdchain* chain = NULL;
    const uint64_t chaincode = 0;
    uint8_t chaincode_bytes[8] = {
        (uint8_t) (chaincode >> 54) & 0xff,
        (uint8_t) (chaincode >> 46) & 0xff,
        (uint8_t) (chaincode >> 38) & 0xff,
        (uint8_t) (chaincode >> 30) & 0xff,
        (uint8_t) (chaincode >> 22) & 0xff,
        (uint8_t) (chaincode >> 14) & 0xff,
        (uint8_t) (chaincode >> 6) & 0xff,
        (uint8_t) (chaincode << 2) & 0xfc,
    };
    if (!mine && sweep) {
        chaincode_bytes[7] |= 0; // RECEIVE
        chain = &g_wallet.hdroot.chain[RECEIVE];
    } else if (!mine && !sweep) {
        chaincode_bytes[7] |= 1; // PAYMENT
        chain = &g_wallet.hdroot.chain[PAYMENT];
    } else if (mine && !sweep) {
        chaincode_bytes[7] |= 2; // CHANGE
        chain = &g_wallet.hdroot.chain[CHANGE];
    } else if (mine && sweep) {
        chaincode_bytes[7] |= 3; // MINING
        chain = &g_wallet.hdroot.chain[MINING];
    }
    uint64_t depth = chain->maxdepth++;
    uint8_t depth_bytes[8] = {
        (uint8_t) (depth >> 56) & 0xff,
        (uint8_t) (depth >> 48) & 0xff,
        (uint8_t) (depth >> 40) & 0xff,
        (uint8_t) (depth >> 32) & 0xff,
        (uint8_t) (depth >> 24) & 0xff,
        (uint8_t) (depth >> 16) & 0xff,
        (uint8_t) (depth >> 8) & 0xff,
        (uint8_t) (depth >> 0) & 0xff,
    };

    // Secret derivation uses a tagged-hash function, which is a sha256 context
    // initialized with the hash of the tag string, repeated twice.
    static const char *tag_str = "webcashwalletv1";
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, tag_str, strlen(tag_str));
    struct sha256 tag;
    sha256_done(&tag, &ctx);

    sha256_init(&ctx);
    sha256_update(&ctx, tag.u8, sizeof(tag.u8));
    sha256_update(&ctx, tag.u8, sizeof(tag.u8));
    sha256_update(&ctx, chaincode_bytes, sizeof(chaincode_bytes));
    sha256_update(&ctx, depth_bytes, sizeof(depth_bytes));
    struct sha256 secret;
    sha256_done(&secret, &ctx);

    struct webcash_wallet_hdkey* hdkey = malloc(sizeof(struct webcash_wallet_hdkey));
    if (hdkey == NULL) {
        g_wallet.callbacks.raise("webcash_wallet_reserve_secret() failed to allocate memory");
        return NULL; // Never reached
    }
    hdkey->dbkey.id = g_wallet.num_hdkeys++;
    hdkey->dbkey.timestamp = timestamp;
    hdkey->depth = (size_t)depth;
    hdkey->secret = malloc(sizeof(struct webcash_wallet_secret));
    if (hdkey->secret == NULL) {
        g_wallet.callbacks.raise("webcash_wallet_reserve_secret() failed to allocate memory");
        return NULL; // Never reached
    }
    hdkey->secret->dbkey.id = g_wallet.secrets->dbkey.id++;
    hdkey->secret->dbkey.timestamp = timestamp;
    hdkey->secret->str = malloc(64 + 1);
    if (hdkey->secret->str == NULL) {
        g_wallet.callbacks.raise("webcash_wallet_reserve_secret() failed to allocate memory");
        return NULL; // Never reached
    }
    BytesToHexString(hdkey->secret->str, secret.u8, 32);
    hdkey->secret->mine = mine;
    hdkey->secret->sweep = sweep;

    // insert webcash_wallet_secret into master list of secrets
    hdkey->secret->next = g_wallet.secrets;
    g_wallet.secrets = hdkey->secret;

    // insert webcash_wallet_hdkey into hdchain's list of keys
    hdkey->next = chain->keys;
    chain->keys = hdkey;

    // return the secret for the caller to use
    return hdkey->secret;
}

webcash_amount webcash_get_balance(void) {
    if (!g_is_initialized) {
        g_wallet.callbacks.raise("webcash_get_balance() called before webcash_init()");
        return 0; // Never reached
    }
    webcash_amount balance = 0;
    struct webcash_wallet_output* output = g_wallet.outputs;
    while (output != NULL) {
        if (!output->spent) {
            balance += output->amount;
        }
        output = output->next;
    }
    return balance;
}

struct generic_info {
    void* user_info;
    void* cb;
};

void webcash_generate_payment(webcash_amount amount, void* user_info, webcash_callback_payment_data callback) {
    //
}
