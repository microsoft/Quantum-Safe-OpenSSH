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

#include <string.h>

#include "ssherr.h"
#include "digest.h"
#include "ssh2.h"
#include "kexhy.h"
#include "sshbuf.h"

/*
 * @brief Initialise values of hybrid key exchange context
 *
 */
int
hybrid_ecdh_oqs_init(HYBRID_KEX_CTX **hybrid_kex_ctx, char *hybrid_kex_name,
	int ec_nid) {

	HYBRID_KEX_CTX *buf_hybrid_kex_ctx = NULL;
	OQS_KEX_CTX *buf_oqs_kex_ctx = NULL;
	int alloc_hybrid_kex_ctx = 1; /* (0) reuse hybrid struct (1) allocated hybrid struct */
	int r = 0;

	/*
	 * If rekeying is performed we don't want to allocate again.
	 * Memory pointed to by *hybrid_kex_ctx is not free'ed before
	 * the program terminates.
	 */
	if (*hybrid_kex_ctx != NULL) {
		alloc_hybrid_kex_ctx = 0;
		buf_hybrid_kex_ctx = *hybrid_kex_ctx;
	}

	if (alloc_hybrid_kex_ctx == 1) {
		if ((buf_hybrid_kex_ctx = calloc(sizeof(*(buf_hybrid_kex_ctx)), 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}

	buf_hybrid_kex_ctx->hybrid_kex_name = hybrid_kex_name;
	buf_hybrid_kex_ctx->oqs_kex_ctx = NULL;

	hybrid_ecdh_init(buf_hybrid_kex_ctx, ec_nid);
	if ((r = oqs_init(&buf_oqs_kex_ctx, hybrid_kex_name)) != 0)
		goto out;

	buf_hybrid_kex_ctx->oqs_kex_ctx = buf_oqs_kex_ctx;
	buf_oqs_kex_ctx = NULL;
	*hybrid_kex_ctx = buf_hybrid_kex_ctx;
	buf_hybrid_kex_ctx = NULL;

out:
	if (buf_hybrid_kex_ctx != NULL) {
		hybrid_ecdh_free(buf_hybrid_kex_ctx);
		if (buf_hybrid_kex_ctx->oqs_kex_ctx != NULL)
			oqs_free(buf_hybrid_kex_ctx->oqs_kex_ctx);
		/*
		 * If reusing, buf_pq_kex_ctx will point to the
		 * reused memory and this wil eventually be freed
		 * by kex_free()
		 */
		if (alloc_hybrid_kex_ctx == 1)
			free(buf_hybrid_kex_ctx);
	}
	if (buf_oqs_kex_ctx != NULL)
		oqs_free(buf_oqs_kex_ctx);

	return r;
}


/*
 * @brief Free memory allocated hybrid key exchange ecdh+liboqs
 */
void
hybrid_ecdh_oqs_free(HYBRID_KEX_CTX *hybrid_kex_ctx) {

	if (hybrid_kex_ctx != NULL) {
		hybrid_ecdh_free(hybrid_kex_ctx);
	}
	if (hybrid_kex_ctx->oqs_kex_ctx != NULL) {
		oqs_free(hybrid_kex_ctx->oqs_kex_ctx);
		free(hybrid_kex_ctx->oqs_kex_ctx);
		hybrid_kex_ctx->oqs_kex_ctx = NULL;
	}
}

/*
 * @brief Combines the shared secret from ecdh and oqs key exchanges into
 * one shared secret
 */
int
hybrid_ecdh_oqs_combine_shared_secrets(u_char *ecdh_shared_secret,
	size_t ecdh_shared_secret_len, u_char *oqs_shared_secret,
	size_t oqs_shared_secret_len, u_char **combined_shared_secret,
	size_t *combined_shared_secret_len) {

	u_char *buf_combined_shared_secret = NULL;
	size_t buf_combined_shared_secret_len = 0;

	int r = 0;

	buf_combined_shared_secret_len = ecdh_shared_secret_len + oqs_shared_secret_len;

	/* Verify that we did not overflow */
	if (buf_combined_shared_secret_len < ecdh_shared_secret_len) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((buf_combined_shared_secret = calloc(sizeof(*buf_combined_shared_secret),
		buf_combined_shared_secret_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(buf_combined_shared_secret, ecdh_shared_secret, ecdh_shared_secret_len);
	memcpy(buf_combined_shared_secret + ecdh_shared_secret_len, oqs_shared_secret,
		oqs_shared_secret_len);

	*combined_shared_secret = buf_combined_shared_secret;
	*combined_shared_secret_len = buf_combined_shared_secret_len;

	buf_combined_shared_secret = NULL;

out:
	if (buf_combined_shared_secret != NULL) {
		explicit_bzero(buf_combined_shared_secret,
			buf_combined_shared_secret_len);
		free(buf_combined_shared_secret);
		buf_combined_shared_secret = NULL;
	}

	return r;
}

/*
 * @brief Computes the exchange hash for ecdh+liboqs key exchange methods
 */
int
hybrid_ecdh_oqs_hash (
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
	u_char *hash, size_t *hash_len) {

	struct sshbuf *hash_buf = NULL;
	int r = 0;

	if (*hash_len < ssh_digest_bytes(hash_alg)) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if ((hash_buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* We assume that sshbuf_put_*() correctly handles NULL parameters */
	if ((r = sshbuf_put_cstring(hash_buf, client_version_string)) != 0 ||
	    (r = sshbuf_put_cstring(hash_buf, server_version_string)) != 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(hash_buf, sshbuf_len(ckexinit)+1)) != 0 ||
	    (r = sshbuf_put_u8(hash_buf, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(hash_buf, ckexinit)) != 0 ||
	    (r = sshbuf_put_u32(hash_buf, sshbuf_len(skexinit)+1)) != 0 ||
	    (r = sshbuf_put_u8(hash_buf, SSH2_MSG_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(hash_buf, skexinit)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, serverhostkeyblob, serverhostkeyblob_len)) != 0 ||
	    (r = sshbuf_put_ec(hash_buf, ecdh_client_public, ecdh_group)) != 0)
		goto out;
	if ((r = sshbuf_put_string(hash_buf, oqs_client_public,
		oqs_client_public_len)) != 0 ||
	    (r = sshbuf_put_ec(hash_buf, ecdh_server_public, ecdh_group)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, oqs_server_public,
	    oqs_server_public_len)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, shared_secret, shared_secret_len)) != 0)
		goto out;

	if (ssh_digest_buffer(hash_alg, hash_buf, hash, *hash_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	*hash_len = ssh_digest_bytes(hash_alg);

out:
	if (hash_buf != NULL)
		sshbuf_free(hash_buf);

	return r;
}

#endif /* defined(OPENSSL_HAS_ECC) && defined(WITH_OQS) && defined(WITH_HYBRID_KEX) */
