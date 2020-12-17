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

#include "includes.h"

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)

#include <signal.h>
#include <string.h>

#include "sshkey.h"
#include "digest.h"
#include "ssherr.h"
#include "kex.h"
#include "ssh2.h"
#include "dispatch.h"
#include "packet.h"
#include "sshbuf.h"
#include "log.h"

/* Server private */
static int
pq_oqs_c2s_deserialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx);
static int
pq_oqs_s2c_serialise(struct ssh *ssh, PQ_KEX_CTX *pq_kex_ctx,
	u_char *server_host_key_blob, size_t server_host_key_blob_len,
	u_char *signature, size_t signature_len);
static int
pq_oqs_server_hostkey(struct ssh *ssh, struct sshkey **server_host_public,
	struct sshkey **server_host_private, u_char **server_host_key_blob,
	size_t *server_host_key_blob_len);
static int
input_pq_oqs_init(int type, u_int32_t seq, struct ssh *ssh);

/*
 * @brief Logic that handles packet deserialisation of the client kex message
 * when using a liboqs kex
 */
static int
pq_oqs_c2s_deserialise(struct ssh *ssh,
	PQ_KEX_CTX *pq_kex_ctx) {

	int r = 0;

	if ((r = oqs_deserialise(ssh, pq_kex_ctx->oqs_kex_ctx, OQS_IS_SERVER) != 0))
		goto out;

	r = sshpkt_get_end(ssh);

out:
	return r;
}

/*
 * @brief Logic that handles packet serialisation of the client kex message
 * when using a liboqs kex
 */
static int
pq_oqs_s2c_serialise(struct ssh *ssh,
	PQ_KEX_CTX *pq_kex_ctx, u_char *server_host_key_blob,
	size_t server_host_key_blob_len, u_char *signature,
	size_t signature_len) {

	int r = 0;

	if ((r = sshpkt_put_string(ssh, server_host_key_blob,
			server_host_key_blob_len)) != 0 ||
		(r = oqs_serialise(ssh, pq_kex_ctx->oqs_kex_ctx, OQS_IS_SERVER)) != 0)
		goto out;

	r = sshpkt_put_string(ssh, signature, signature_len);

out:
	return r;
}

/*
 * @brief Retrieves host key
 */
static int
pq_oqs_server_hostkey(struct ssh *ssh, struct sshkey **server_host_public,
	struct sshkey **server_host_private, u_char **server_host_key_blob,
	size_t *server_host_key_blob_len) {

	struct kex *kex = NULL;
	struct sshkey *tmp_server_host_public = NULL;
	struct sshkey *tmp_server_host_private = NULL;
	u_char *tmp_server_host_key_blob = NULL;
	size_t tmp_server_host_key_blob_len = 0;
	int r = 0;

	kex = ssh->kex;

	/* Retrieve host public and private key */
	if (kex->load_host_public_key == NULL ||
	    kex->load_host_private_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (((tmp_server_host_public = kex->load_host_public_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh)) == NULL) ||
	    (tmp_server_host_private = kex->load_host_private_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh)) == NULL) {
		r = SSH_ERR_NO_HOSTKEY_LOADED;
		goto out;
	}

	/* Write to blob to prepare transfer over the wire */
	if ((r = sshkey_to_blob(tmp_server_host_public, &tmp_server_host_key_blob,
	    &tmp_server_host_key_blob_len)) != 0)
		goto out;

	*server_host_public = tmp_server_host_public;
	*server_host_private = tmp_server_host_private;
	*server_host_key_blob = tmp_server_host_key_blob;
	*server_host_key_blob_len = tmp_server_host_key_blob_len;

	tmp_server_host_public = NULL;
	tmp_server_host_private = NULL;
	tmp_server_host_key_blob = NULL;

out:
	return r;
}

/*
 * @brief Initialise server to receive liboqs PQ-only key exchange
 * method client-side message
 */
int
pq_oqs_server(struct ssh *ssh) {

	PQ_KEX_CTX *pq_kex_ctx = NULL;
	const OQS_ALG *oqs_alg = NULL;
	int r = 0;

	/* Test whether we are prepared to handle this packet */
	if (ssh == NULL ||
		ssh->kex == NULL ||
		(pq_kex_ctx = ssh->kex->pq_kex_ctx) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
		error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	debug("expecting %i msg", oqs_ssh2_init_msg(oqs_alg));
	ssh_dispatch_set(ssh, oqs_ssh2_init_msg(oqs_alg),
		&input_pq_oqs_init);

out:
	return r;
}

/*
 * @brief Handles the client key exchange message when using a liboqs
 * PQ-only key exchange method
 */
static int
input_pq_oqs_init(int type, u_int32_t seq,
	struct ssh *ssh) {

	PQ_KEX_CTX *pq_kex_ctx = NULL;
	OQS_KEX_CTX *oqs_kex_ctx = NULL;
	const OQS_ALG *oqs_alg = NULL;
	struct kex *kex = NULL;
	struct sshkey *server_host_public = NULL;
	struct sshkey *server_host_private = NULL;
	struct sshbuf *shared_secret_ssh_buf = NULL;
	u_char *oqs_shared_secret = NULL;
	u_char *server_host_key_blob = NULL;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t server_host_key_blob_len = 0;
	size_t signature_len = 0;
	size_t hash_len = 0;
	size_t oqs_shared_secret_len = 0;
	int r = 0;

	/* Test whether we are prepared to handle this packet */
	if (ssh == NULL ||
		(kex = ssh->kex) == NULL ||
		(pq_kex_ctx = kex->pq_kex_ctx) == NULL ||
		(oqs_kex_ctx = pq_kex_ctx->oqs_kex_ctx) == NULL) {

		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Load public and private host key */
	if ((r = pq_oqs_server_hostkey(ssh, &server_host_public,
		&server_host_private, &server_host_key_blob,
		&server_host_key_blob_len)) != 0)
		goto out;

	/* Deserialise client to server packet */
	if ((r = pq_oqs_c2s_deserialise(ssh, pq_kex_ctx)) != 0)
		goto out;

	/*
	 * libOQS API only supports generating the liboqs public key
	 * msg and shared secret simultaneously.
	 */
	if ((r = oqs_server_gen_msg_and_ss(oqs_kex_ctx,
		&oqs_shared_secret, &oqs_shared_secret_len)) != 0)
		goto out;

	/*
	 * Compute exchange hash
	 * kex->peer is client
	 * kex->my is server
	 */
	hash_len = sizeof(hash);
	if ((r = pq_oqs_hash(
		kex->hash_alg,
		kex->client_version_string,
		kex->server_version_string,
		kex->peer,
		kex->my,
		server_host_key_blob, server_host_key_blob_len,
		oqs_kex_ctx->oqs_remote_msg, oqs_kex_ctx->oqs_remote_msg_len,
		oqs_kex_ctx->oqs_local_msg, oqs_kex_ctx->oqs_local_msg_len,
		oqs_shared_secret, oqs_shared_secret_len,
		hash, &hash_len)) !=0)
		goto out;

	/* Save session id */
	if (kex->session_id == NULL) {
		kex->session_id_len = hash_len;
		kex->session_id = malloc(kex->session_id_len);
		if (kex->session_id == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	/* Sign exchange hash */
	if ((r = kex->sign(server_host_private, server_host_public,
		&signature, &signature_len, hash, hash_len, kex->hostkey_alg,
		ssh->compat)) < 0)
		goto out;

	if ((oqs_alg = oqs_mapping(pq_kex_ctx->pq_kex_name)) == NULL) {
		error("Unsupported libOQS algorithm \"%.100s\"", pq_kex_ctx->pq_kex_name);
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Send pq-only liboqs server to client packet */
	if ((r = sshpkt_start(ssh, oqs_ssh2_reply_msg(oqs_alg))) != 0 ||
		(r = pq_oqs_s2c_serialise(ssh, pq_kex_ctx, server_host_key_blob,
			server_host_key_blob_len, signature, signature_len)) != 0 ||
		(r = sshpkt_send(ssh)) != 0)
		goto out;

	/*
	 * sshbuf_put_string() will encode the shared secret as a mpint
	 * as required by SSH spec (RFC4253)
	 */
	if ((shared_secret_ssh_buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_string(shared_secret_ssh_buf, (const u_char *) oqs_shared_secret,
		oqs_shared_secret_len)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hash_len, shared_secret_ssh_buf)) == 0)
		r = kex_send_newkeys(ssh);

out:
	explicit_bzero(hash, sizeof(hash));
	pq_oqs_free(pq_kex_ctx);
	/* sshbuf_free zeroises memory */
	if (shared_secret_ssh_buf != NULL)
		sshbuf_free(shared_secret_ssh_buf);
	if (oqs_shared_secret != NULL) {
		explicit_bzero(oqs_shared_secret, oqs_shared_secret_len);
		free(oqs_shared_secret);
	}
	if (server_host_key_blob != NULL)
		free(server_host_key_blob);
	if (signature != NULL)
		free(signature);

	return r;
}

#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */
