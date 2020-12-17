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

#ifndef KEX_OQS_H
#define KEX_OQS_H

#include "includes.h"

#ifdef WITH_OQS

#include "packet.h"
#include "oqs/oqs.h"

#define HYBRID_ECDH_OQS_NAMESPACE_SUFFIX "@openquantumsafe.org"
#define HYBRID_ECDH_OQS_KEX_SUFFIX(X) X HYBRID_ECDH_OQS_NAMESPACE_SUFFIX

#define PQ_OQS_NAMESPACE_SUFFIX "@openquantumsafe.org"
#define PQ_OQS_KEX_SUFFIX(X) X PQ_OQS_NAMESPACE_SUFFIX

typedef enum oqs_client_or_server {
	OQS_IS_CLIENT,
	OQS_IS_SERVER
} oqs_client_or_server_t;

/*
 * State information needed for the liboqs part
 * of the hybrid key exchange
 */
typedef struct oqs_kex_ctx {

	OQS_KEM *oqs_kem;	/* liboqs KEM algorithm context */
	char *oqs_method;	/* liboqs algorithm name */
	uint8_t *oqs_local_priv;	/* Local private key */
	size_t oqs_local_priv_len;	/* Local private key length */
	uint8_t *oqs_local_msg;		/* Local message */
	size_t oqs_local_msg_len;	/* Local message length */
	uint8_t *oqs_remote_msg;	/* Remote message. */
	size_t oqs_remote_msg_len;	/* Remote message length */

} OQS_KEX_CTX;

/*
 * liboqs algorithm information and stores message names used
 * during the hybrid key exchange
 */
typedef struct oqs_alg {

	char *kex_alg; 					/* SSH kex exchange name */
	char *alg_name; 				/* liboqs algorithm name */
	int ssh2_init_msg; 				/* Msg number/name mapping */
	int ssh2_reply_msg; 			/* Msg number/name mapping */

} OQS_ALG;

/* Public client functions */
int oqs_client_gen(OQS_KEX_CTX *oqs_kex_ctx);
int oqs_client_extract(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx);
int oqs_client_shared_secret(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **oqs_shared_secret, size_t *oqs_shared_secret_len);
/* Public server  fucntions */
int oqs_server_gen_msg_and_ss(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **oqs_shared_secret, size_t *oqs_shared_secret_len);
/* Public shared functions */
int oqs_init(OQS_KEX_CTX **oqs_kex_ctx, char *ssh_kex_name);
void oqs_free(OQS_KEX_CTX *oqs_kex_ctx);
const OQS_ALG * oqs_mapping(const char *ssh_kex_name);
int oqs_ssh2_init_msg(const OQS_ALG *oqs_alg);
int oqs_ssh2_reply_msg(const OQS_ALG *oqs_alg);
int oqs_deserialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	oqs_client_or_server_t client_or_server);
int oqs_serialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	oqs_client_or_server_t client_or_server);

#endif /* WITH_OQS */
#endif /* KEX_OQS_H */
