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

#if defined(OPENSSL_HAS_ECC) && defined(WITH_OQS) && defined(WITH_HYBRID_KEX)

#include <openssl/ecdh.h>
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

/* Client private */
static int
input_hybrid_ecdh_oqs_reply(int type, u_int32_t seq, struct ssh *ssh);
static int
hybrid_ecdh_oqs_s2c_deserialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx,
	struct sshkey **server_host_key, u_char **server_host_key_blob,
	size_t *server_host_key_blob_len, u_char **signature, size_t *signature_len);
static int
hybrid_ecdh_oqs_c2s_serialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx);
static int
hybrid_ecdh_oqs_verify_hostkey(struct ssh *ssh,
	struct sshkey *server_host_key);
static int
hybrid_ecdh_oqs_deserialise_hostkey(struct ssh *ssh, struct sshkey **server_host_key,
	u_char **server_host_key_blob, size_t *server_host_key_blob_len);

/*
 * @brief Logic that handles packet deserialisation of the kex packet from server
 * to client when using a ecdh+liboqs key exchange method
 */
static int
hybrid_ecdh_oqs_s2c_deserialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx,
	struct sshkey **server_host_key, u_char **server_host_key_blob,
	size_t *server_host_key_blob_len, u_char **signature, size_t *signature_len) {

	int r = 0;

	/*
	 * hybrid_ecdh_oqs_server_hostkey() immediately verify
	 * the host key after extracting it
	 */
	if ((r = hybrid_ecdh_oqs_deserialise_hostkey(ssh, server_host_key,
		server_host_key_blob, server_host_key_blob_len)) != 0 ||
		(r = hybrid_ecdh_deserialise(ssh, hybrid_kex_ctx) != 0) ||
		(r = oqs_deserialise(ssh, hybrid_kex_ctx->oqs_kex_ctx, OQS_IS_CLIENT) != 0) ||
		(r = sshpkt_get_string(ssh, signature, signature_len)) != 0)
		goto out;

	r = sshpkt_get_end(ssh);

	out:
		return r;
}

/*
 * @brief Logic that handles packet serialisation of the kex packet to client
 * from server when using a ecdh+liboqs key exchange method
 */
static int
hybrid_ecdh_oqs_c2s_serialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx) {

	int r = 0;

	if ((r = hybrid_ecdh_serialise(ssh, hybrid_kex_ctx)) == 0)
		r = oqs_serialise(ssh, hybrid_kex_ctx->oqs_kex_ctx, OQS_IS_CLIENT);

	return r;
}

/*
 * @brief Verifies host key
 */
static int
hybrid_ecdh_oqs_verify_hostkey(struct ssh *ssh,
	struct sshkey *server_host_key) {

	struct kex *kex = NULL;
	int r = 0;

	kex = ssh->kex;

	/* If we can't verify the host key then abort */
	if (kex->verify_host_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	/* Verify host key */
	if (kex->verify_host_key(server_host_key, ssh) == -1) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

out:
	return r;
}

/*
 * @brief Extracts host key from incoming packet and
 * verifies it
 */
static int
hybrid_ecdh_oqs_deserialise_hostkey(struct ssh *ssh,
	struct sshkey **server_host_key, u_char **server_host_key_blob,
	size_t *server_host_key_blob_len) {

	struct sshkey *tmp_server_host_key = NULL;
	u_char *tmp_server_host_key_blob = NULL;
	size_t tmp_server_host_key_blob_len = 0;
	int r = 0;

	/* Extract host key from packet */
	if ((r = sshpkt_get_string(ssh, &tmp_server_host_key_blob,
		&tmp_server_host_key_blob_len)) != 0 ||
		(r = sshkey_from_blob(tmp_server_host_key_blob,
		tmp_server_host_key_blob_len, &tmp_server_host_key)) != 0)
		goto out;

	/* Immediately verify host key */
	if ((r = hybrid_ecdh_oqs_verify_hostkey(ssh,
		tmp_server_host_key)) != 0)
		goto out;

	*server_host_key = tmp_server_host_key;
	*server_host_key_blob = tmp_server_host_key_blob;
	*server_host_key_blob_len = tmp_server_host_key_blob_len;

	tmp_server_host_key = NULL;
	tmp_server_host_key_blob = NULL;

out:
	if (tmp_server_host_key_blob != NULL)
		free(tmp_server_host_key_blob);
	if (tmp_server_host_key != NULL)
		sshkey_free(tmp_server_host_key);

	return r;
}

/*
 * @brief Handles the first client ecdh+liboqs key exchange message
 */
int
hybrid_ecdh_oqs_client(struct ssh *ssh) {

	HYBRID_KEX_CTX *hybrid_kex_ctx = NULL;
	OQS_KEX_CTX *oqs_kex_ctx = NULL;
	const OQS_ALG *oqs_alg = NULL;
	int r = 0;

	/* Test whether we are prepared to handle this packet */
	if (ssh == NULL ||
		ssh->kex == NULL ||
		(hybrid_kex_ctx = ssh->kex->hybrid_kex_ctx) == NULL ||
		(oqs_kex_ctx = hybrid_kex_ctx->oqs_kex_ctx) == NULL) {

		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((oqs_alg = oqs_mapping(hybrid_kex_ctx->hybrid_kex_name)) == NULL) {
		error("Unsupported libOQS algorithm \"%.100s\"", hybrid_kex_ctx->hybrid_kex_name);
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Generate ecdh public key */
	if ((r = hybrid_ecdh_gen(hybrid_kex_ctx)) != 0)
		goto out;

	/* Generate oqs public key */
	if ((r = oqs_client_gen(oqs_kex_ctx)) != 0)
		goto out;

	/* Send client hybrid ecdh+liboqs packet to server */
	if ((r = sshpkt_start(ssh, oqs_ssh2_init_msg(oqs_alg))) != 0 ||
		(r = hybrid_ecdh_oqs_c2s_serialise(ssh, hybrid_kex_ctx)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	/* Set handler for recieving server reply */
	debug("expecting %i msg", oqs_ssh2_reply_msg(oqs_alg));
	ssh_dispatch_set(ssh, oqs_ssh2_reply_msg(oqs_alg),
		&input_hybrid_ecdh_oqs_reply);

out:
	if (r != 0) {
		hybrid_ecdh_free(hybrid_kex_ctx);
		oqs_free(oqs_kex_ctx);
	}

	return r;
}

/*
 * @brief Handles the ecdh+liboqs key exchange reply from server
 */
static int
input_hybrid_ecdh_oqs_reply(int type, u_int32_t seq, struct ssh *ssh) {

	HYBRID_KEX_CTX *hybrid_kex_ctx = NULL;
	OQS_KEX_CTX *oqs_kex_ctx = NULL;
	struct sshkey *server_host_key = NULL;
	struct sshbuf *shared_secret_ssh_buf = NULL;
	struct kex *kex = NULL;
	u_char *server_host_key_blob = NULL;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char *ecdh_shared_secret = NULL;
	u_char *oqs_shared_secret = NULL;
	u_char *shared_secret = NULL;
	size_t ecdh_shared_secret_len = 0;
	size_t oqs_shared_secret_len = 0;
	size_t shared_secret_len = 0;
	size_t signature_len = 0;
	size_t server_host_key_blob_len = 0;
	size_t hash_len = 0;
	int r = 0;

	/* Test whether we are prepared to handle this packet */
	if (ssh == NULL ||
		(kex = ssh->kex) == NULL ||
		(hybrid_kex_ctx = kex->hybrid_kex_ctx) == NULL ||
		(oqs_kex_ctx = hybrid_kex_ctx->oqs_kex_ctx) == NULL) {

		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Extract from server to client packet */
	if ((r = hybrid_ecdh_oqs_s2c_deserialise(ssh, hybrid_kex_ctx,
		&server_host_key, &server_host_key_blob,
		&server_host_key_blob_len, &signature, &signature_len)) != 0)
		goto out;

	/*
	 * Compute shared secret for each key exchange scheme part of the
	 * hybrid key exchange method
	 */
	if ((r = hybrid_ecdh_shared_secret(hybrid_kex_ctx, &ecdh_shared_secret,
		&ecdh_shared_secret_len)) != 0)
		goto out;
	if ((r = oqs_client_shared_secret(oqs_kex_ctx, &oqs_shared_secret,
		&oqs_shared_secret_len)) != 0)
		goto out;

	if ((r = hybrid_ecdh_oqs_combine_shared_secrets(ecdh_shared_secret,
		ecdh_shared_secret_len, oqs_shared_secret, oqs_shared_secret_len,
		&shared_secret, &shared_secret_len)) != 0)
		goto out;

	/*
	 * Compute exchange hash
	 * kex->my is client
	 * kex->peer is server
	 */
	hash_len = sizeof(hash);
	if ((r = hybrid_ecdh_oqs_hash(
		kex->hash_alg,
		kex->client_version_string,
		kex->server_version_string,
		kex->my,
		kex->peer,
		server_host_key_blob, server_host_key_blob_len,
		hybrid_kex_ctx->ecdh_group,
		hybrid_kex_ctx->ecdh_local_public,
		hybrid_kex_ctx->ecdh_remote_public,
		oqs_kex_ctx->oqs_local_msg, oqs_kex_ctx->oqs_local_msg_len,
		oqs_kex_ctx->oqs_remote_msg, oqs_kex_ctx->oqs_remote_msg_len,
		shared_secret, shared_secret_len,
		hash, &hash_len)) != 0)
		goto out;

	/* Verify signature over exchange hash */
	if ((r = sshkey_verify(server_host_key, signature, signature_len, hash,
		hash_len, kex->hostkey_alg, ssh->compat))!= 0)
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

	/*
	 * sshbuf_put_string() will encode the shared secret as a mpint
	 * as required by SSH spec (RFC4253)
	 */
	if ((shared_secret_ssh_buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_string(shared_secret_ssh_buf, (const u_char *) shared_secret,
		shared_secret_len)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hash_len, shared_secret_ssh_buf)) == 0)
		r = kex_send_newkeys(ssh);

out:
	explicit_bzero(hash, sizeof(hash));
	hybrid_ecdh_oqs_free(hybrid_kex_ctx);
	/* sshbuf_free zeroises memory */
	if (shared_secret_ssh_buf != NULL)
		sshbuf_free(shared_secret_ssh_buf);
	if (server_host_key != NULL)
		sshkey_free(server_host_key);
	if (shared_secret != NULL) {
		explicit_bzero(shared_secret, shared_secret_len);
		free(shared_secret);
	}
	if (ecdh_shared_secret != NULL) {
		explicit_bzero(ecdh_shared_secret, ecdh_shared_secret_len);
		free(ecdh_shared_secret);
	}
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

#endif /* defined(OPENSSL_HAS_ECC) && defined(WITH_OQS) && defined(WITH_HYBRID_KEX) */
