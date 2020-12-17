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

#ifndef KEX_HYBRID_H
#define KEX_HYBRID_H

#include "includes.h"

#ifdef WITH_HYBRID_KEX

#include "packet.h"
#include "kexoqs.h"

/* Hybrid key exchange context */
typedef struct hybrid_kex_ctx {

	const char *hybrid_kex_name;	/* Named SSH hybrid key exchange method */

#ifdef OPENSSL_HAS_ECC
	/* ECDH specifics */
	int ec_nid;	/* Elliptic curve reference */
	EC_KEY *ecdh_local_key;	/* Local ecdh key */
	const EC_GROUP *ecdh_group;	/* Elliptic curve group used */
	const EC_POINT *ecdh_local_public; /* Public ecdh part from local */
	const EC_POINT *ecdh_remote_public; /* Public ecdh part from remote */
#endif /* OPENSSL_HAS_ECC */

#ifdef WITH_OQS
	/* libOQS specifics */
	OQS_KEX_CTX *oqs_kex_ctx;	/* Liboqs context */
#endif /* WITH_OQS */

} HYBRID_KEX_CTX;

/*
 * Header: Special ECDH version needed for hybrid key exchange
 */

#ifdef OPENSSL_HAS_ECC

/* Public functions */
void hybrid_ecdh_init(HYBRID_KEX_CTX *hybrid_kex_ctx, int ec_nid);
void hybrid_ecdh_free(HYBRID_KEX_CTX *hybrid_kex_ctx);
int hybrid_ecdh_gen(HYBRID_KEX_CTX *hybrid_kex_ctx);
int hybrid_ecdh_deserialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx);
int hybrid_ecdh_serialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx);
int hybrid_ecdh_shared_secret(HYBRID_KEX_CTX *hybrid_kex_ctx,
	u_char **ecdh_shared_secret, size_t *ecdh_shared_secret_len);

#endif /* OPENSSL_HAS_ECC */

/*
 * Headers: Named hybrid key exchange methods
 */

#if defined(OPENSSL_HAS_ECC) && defined(WITH_OQS)

/* ECDH+liboqs */
/* Exchange hash */
int hybrid_ecdh_oqs_hash (
	int hash_alg,
	const char *client_version_string,
	const char *server_version_string,
	const struct sshbuf *ckexinit,
	const struct sshbuf *skexinit,
	const u_char *serverhostkeyblob, size_t serverhostkeyblob_len,
	const EC_GROUP *ecdh_group,
	const EC_POINT *ecdh_client_public,
	const EC_POINT *ecdh_server_public,
	const uint8_t *oqs_client_public, size_t oqs_client_public_len,
	const uint8_t *oqs_server_public, size_t oqs_server_public_len,
	const u_char *shared_secret, size_t shared_secret_len,
	u_char *hash, size_t *hash_len);
/* Shared functions */
int hybrid_ecdh_oqs_init(HYBRID_KEX_CTX **hybrid_kex_ctx,
	char *hybrid_kex_name, int ec_nid);
void hybrid_ecdh_oqs_free(HYBRID_KEX_CTX *hybrid_kex_ctx);
int hybrid_ecdh_oqs_combine_shared_secrets(u_char *ecdh_shared_secret,
	size_t ecdh_shared_secret_len, u_char *oqs_shared_secret,
	size_t oqs_shared_secret_len, u_char **combined_shared_secret,
	size_t *combined_shared_secret_len);
/* Client specific function */
int hybrid_ecdh_oqs_client(struct ssh *ssh);
/* Server specific function */
int hybrid_ecdh_oqs_server(struct ssh *ssh);

#endif /* defined(OPENSSL_HAS_ECC) && defined(WITH_OQS) */
#endif /* WITH_HYBRID_KEX */

/* Helper functions to register hybrid key exchange call-backs */
typedef int (*hybrid_func_cb)(struct ssh *);

static inline hybrid_func_cb
get_hybrid_ecdh_oqs_client_cb() {

#if defined(OPENSSL_HAS_ECC) && defined(WITH_OQS) && defined(WITH_HYBRID_KEX)
    return hybrid_ecdh_oqs_client;
#else
    return NULL;
#endif
}

static inline hybrid_func_cb
get_hybrid_ecdh_oqs_server_cb() {

#if defined(OPENSSL_HAS_ECC) && defined(WITH_OQS) && defined(WITH_HYBRID_KEX)
    return hybrid_ecdh_oqs_server;
#else
    return NULL;
#endif
}

#endif /* KEX_HYBRID_H */
