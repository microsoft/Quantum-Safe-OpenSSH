/*
* Copyright 2018 Amazon.com, Inc. or its affiliates. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef KEX_PQ_H
#define KEX_PQ_H

#include "includes.h"

#ifdef WITH_PQ_KEX

#include "packet.h"
#include "kexoqs.h"

/* Hybrid key exchange context */
typedef struct pq_kex_ctx {

	const char *pq_kex_name;	/* Named SSH hybrid key exchange method */

#ifdef WITH_OQS
	/* libOQS specifics */
	OQS_KEX_CTX *oqs_kex_ctx;	/* Liboqs context */
#endif /* WITH_OQS */

} PQ_KEX_CTX;

/*
 * Headers: Named PQ-only key exchange methods
 */

#ifdef WITH_OQS

/* PQ-only liboqs */
/* Exchange hash */
int pq_oqs_hash (
	int hash_alg,
	const char *client_version_string,
	const char *server_version_string,
	const struct sshbuf *ckexinit,
	const struct sshbuf *skexinit,
	const u_char *serverhostkeyblob, size_t serverhostkeyblob_len,
	const uint8_t *oqs_client_public, size_t oqs_client_public_len,
	const uint8_t *oqs_server_public, size_t oqs_server_public_len,
	const u_char *oqs_shared_secret, size_t oqs_shared_secret_len,
	u_char *hash, size_t *hash_len);
/* Shared functions */
int pq_oqs_init(PQ_KEX_CTX **pq_kex_ctx, char *pq_kex_name);
void pq_oqs_free(PQ_KEX_CTX *pq_kex_ctx);
/* Client specific function */
int  pq_oqs_client(struct ssh *);
/* Server specific function */
int  pq_oqs_server(struct ssh *);
#endif /* WITH_OQS */
#endif /* WITH_PQ_KEX */

/* Helper functions to register PQ-only key exchange call-backs */
typedef int (*pq_func_cb)(struct ssh *);

static inline pq_func_cb
get_pq_oqs_client_cb() {

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)
    return pq_oqs_client;
#else
    return NULL;
#endif
}

static inline pq_func_cb
get_pq_oqs_server_cb() {

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)
    return pq_oqs_server;
#else
    return NULL;
#endif
}

#endif /* KEX_PQ_H */
