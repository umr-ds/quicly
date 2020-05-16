/*
 * Copyright (c) 2020 Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef issued_cid_h
#define issued_cid_h

#include "quicly/cid.h"

#ifdef __cplusplus
extern "C" {
#endif

enum en_quicly_issued_cid_state_t {
    /**
     * this entry is free for use
     */
    QUICLY_ISSUED_CID_STATE_IDLE,
    /**
     * this entry is to be sent at the next round of send operation
     */
    QUICLY_ISSUED_CID_STATE_PENDING,
    /**
     * this entry has been sent and is waiting for ACK (or to be deemed lost)
     */
    QUICLY_ISSUED_CID_STATE_INFLIGHT,
    /**
     * this CID has been delivered to the peer (ACKed) and in use
     */
    QUICLY_ISSUED_CID_STATE_DELIVERED,
};

/**
 * records information for sending NEW_CONNECTION_ID frame
 */
typedef struct st_quicly_issued_cid_t {
    enum en_quicly_issued_cid_state_t state;
    uint64_t sequence;
    quicly_cid_t cid;
    uint8_t stateless_reset_token[QUICLY_STATELESS_RESET_TOKEN_LEN];
} quicly_issued_cid_t;

/**
 * manages a list of connection IDs we issue to the peer
 */
typedef struct st_quicly_issued_cid_set_t {
    /**
     * storage to retain issued CIDs
     *
     * Pending CIDs (state == STATE_PENDING) are moved to the front of the array, in the order it was marked as pending.
     * This ensures that pending CIDs are sent in FIFO manner. Order of CIDs with other states is not defined.
     *
     * Actual size of the array is constrained by _size.
     */
    quicly_issued_cid_t cids[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
    /**
     * how many entries are actually usable in `cids`?
     */
    size_t _size;
    quicly_cid_encryptor_t *_encryptor;
    /**
     * Identifier of the connection used by quicly. Three tuple of (node_id, thread_id, master_id) is used to identify the
     * connection. `path_id` is maintained by the "issued_cid" module, and used for identifying each CID being issued.
     */
    quicly_cid_plaintext_t plaintext;
} quicly_issued_cid_set_t;

/**
 * initialize the structure
 *
 * If `encryptor` is non-NULL, it is initialized with size==1 (sequence==0 is registered as DELIVERED).
 * Otherwise, it is initialized with size==0, and the size shall never be increased.
 */
void quicly_issued_cid_init_set(quicly_issued_cid_set_t *set, quicly_cid_encryptor_t *encryptor,
                                const quicly_cid_plaintext_t *new_cid);
/**
 * sets a new size of issued CIDs.
 *
 * The new size must be equal to or grater than the current size, and must be equal to or less than the elements of `cids`.
 *
 * Returns true if there is something to send.
 */
int quicly_issued_cid_set_size(quicly_issued_cid_set_t *set, size_t new_cap);
/**
 * returns true if all entries in the given set is in IDLE state
 */
static int quicly_issued_cid_is_empty(const quicly_issued_cid_set_t *set);
static size_t quicly_issued_cid_get_size(const quicly_issued_cid_set_t *set);
/**
 * tells the module that the first `num_sent` pending CIDs have been sent
 */
void quicly_issued_cid_on_sent(quicly_issued_cid_set_t *set, size_t num_sent);
/**
 * tells the module that the given sequence number was ACKed
 */
void quicly_issued_cid_on_acked(quicly_issued_cid_set_t *set, uint64_t sequence);
/**
 * tells the module that the given sequence number was lost
 *
 * returns true if there is something to send
 */
int quicly_issued_cid_on_lost(quicly_issued_cid_set_t *set, uint64_t sequence);
/**
 * remove the specified CID from the storage.
 *
 * This makes one slot for CIDs empty. The CID generator callback is then called to fill the slot with a new CID.
 * @return true if there is something to send
 */
int quicly_issued_cid_retire(quicly_issued_cid_set_t *set, uint64_t sequence);

inline int quicly_issued_cid_is_empty(const quicly_issued_cid_set_t *set)
{
    for (size_t i = 0; i < set->_size; i++) {
        if (set->cids[i].state != QUICLY_ISSUED_CID_STATE_IDLE)
            return 0;
    }
    return 1;
}

inline size_t quicly_issued_cid_get_size(const quicly_issued_cid_set_t *set)
{
    return set->_size;
}

#ifdef __cplusplus
}
#endif

#endif