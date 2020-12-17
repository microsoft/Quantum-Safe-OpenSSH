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

#if defined(OPENSSL_HAS_ECC) && defined(WITH_HYBRID_KEX)

#include <openssl/ecdh.h>
#include <signal.h>

#include "sshkey.h"
#include "ssherr.h"
#include "packet.h"
#include "kexhy.h"

/*
 * @brief Initialise hybrid key exchange ecdh specific context
 */
void
hybrid_ecdh_init(HYBRID_KEX_CTX *hybrid_kex_ctx, int ec_nid) {

	hybrid_kex_ctx->ec_nid = ec_nid;
	hybrid_kex_ctx->ecdh_local_key = NULL;
	hybrid_kex_ctx->ecdh_group = NULL;
	hybrid_kex_ctx->ecdh_local_public = NULL;
	hybrid_kex_ctx->ecdh_remote_public = NULL;
}

/*
 * @brief Free memory allocated for ecdh part of hybrid key exchange
 */
void
hybrid_ecdh_free(HYBRID_KEX_CTX *hybrid_kex_ctx) {

	/*
	 * EC_KEY_free() makes sure to also free the public part of the key.
	 * We don't have the private key for the remote, so we must explicitly
	 * free it.
	 */
	if (hybrid_kex_ctx->ecdh_local_key != NULL) {
		EC_KEY_free(hybrid_kex_ctx->ecdh_local_key);
		hybrid_kex_ctx->ecdh_local_key = NULL;
	}
	if (hybrid_kex_ctx->ecdh_local_public != NULL) {
		EC_POINT_clear_free((EC_POINT *) hybrid_kex_ctx->ecdh_remote_public);
		hybrid_kex_ctx->ecdh_remote_public = NULL;
	}
}

/*
 * @brief Computes the ECDH public and private key.
 */
int
hybrid_ecdh_gen(HYBRID_KEX_CTX *hybrid_kex_ctx) {

	EC_KEY *key = NULL;
	int r = 0;

	if ((key = EC_KEY_new_by_curve_name(hybrid_kex_ctx->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EC_KEY_generate_key(key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	hybrid_kex_ctx->ecdh_group = EC_KEY_get0_group(key);
	hybrid_kex_ctx->ecdh_local_public = EC_KEY_get0_public_key(key);
	hybrid_kex_ctx->ecdh_local_key = key;

	key = NULL;

out:
	if (key != NULL) {
		EC_KEY_free(key);
	}

	return r;
}

/*
 * @brief Deserialise the ECDH part of a hybrid key exchange packet from server
 */
int
hybrid_ecdh_deserialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx) {

	EC_POINT *public_point = NULL;
	int r = 0;

	if ((public_point = EC_POINT_new(hybrid_kex_ctx->ecdh_group)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshpkt_get_ec(ssh, public_point, hybrid_kex_ctx->ecdh_group)) != 0)
		goto out;

	/* Very important to verify public key! */
	if (sshkey_ec_validate_public(hybrid_kex_ctx->ecdh_group, (const EC_POINT *) public_point) != 0) {
		sshpkt_disconnect(ssh, "Invalid server ECDH public key");
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	hybrid_kex_ctx->ecdh_remote_public = (const EC_POINT *) public_point;

	public_point = NULL;

out:
	if (public_point != NULL) {
		EC_POINT_clear_free(public_point);
	}

	return r;
}

/*
 * @brief Serialise the ECDH part of a hybrid key exchange packet from server
 */
int
hybrid_ecdh_serialise(struct ssh *ssh, HYBRID_KEX_CTX *hybrid_kex_ctx) {

	return sshpkt_put_ec(ssh, hybrid_kex_ctx->ecdh_local_public,
		hybrid_kex_ctx->ecdh_group);
}

/*
 * @brief Computes the ECDH shared secret
 */
int
hybrid_ecdh_shared_secret(HYBRID_KEX_CTX *hybrid_kex_ctx, u_char **ecdh_shared_secret,
	size_t *ecdh_shared_secret_len) {

	EC_KEY *key = NULL;
	const EC_POINT *public_point = NULL;
	u_char *buf_ecdh_shared_secret = NULL;
	size_t buf_ecdh_shared_secret_len = 0;
	int r = 0;

	/* Round up to nearest multiple of 8 */
	buf_ecdh_shared_secret_len = (EC_GROUP_get_degree(hybrid_kex_ctx->ecdh_group) + 7) / 8;
	if ((buf_ecdh_shared_secret = calloc(sizeof(*buf_ecdh_shared_secret),
		buf_ecdh_shared_secret_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	public_point = hybrid_kex_ctx->ecdh_remote_public;
	key = hybrid_kex_ctx->ecdh_local_key;

	if (ECDH_compute_key(buf_ecdh_shared_secret, buf_ecdh_shared_secret_len, public_point,
		key, NULL) != (int) buf_ecdh_shared_secret_len) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	*ecdh_shared_secret = buf_ecdh_shared_secret;
	*ecdh_shared_secret_len = buf_ecdh_shared_secret_len;

	buf_ecdh_shared_secret = NULL;

out:
	/* Memory free'd by caller in case of fail */
	key = NULL;
	/* Memory free'd by caller in case of fail */
	public_point = NULL;

	if (buf_ecdh_shared_secret != NULL) {
		explicit_bzero(buf_ecdh_shared_secret, buf_ecdh_shared_secret_len);
		free(buf_ecdh_shared_secret);
	}

	return r;
}

#endif /* defined(OPENSSL_HAS_ECC) && defined(WITH_HYBRID_KEX) */
