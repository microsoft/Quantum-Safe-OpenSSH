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

#include "compat.h"
#include "ssherr.h"
#include "digest.h"
#include "ssh2.h"
#include "kexpq.h"
#include "sshbuf.h"

/*
 * @brief Initialise values of PQ-only key exchange context
 *
 */
int
pq_oqs_init(PQ_KEX_CTX **pq_kex_ctx, char *pq_kex_name) {

	PQ_KEX_CTX *buf_pq_kex_ctx = NULL;
	OQS_KEX_CTX *buf_oqs_kex_ctx = NULL;
	int alloc_pq_kex_ctx = 1; /* (0) reuse PQ-only struct (1) allocated PQ-only struct */
	int r = 0;

	/*
	 * If rekeying is performed we don't want to allocate again.
	 * Memory pointed to by *pq_kex_ctx is not free'ed before
	 * the program terminates.
	 */
	if (*pq_kex_ctx != NULL) {
		alloc_pq_kex_ctx = 0;
		buf_pq_kex_ctx = *pq_kex_ctx;
	}

	if (alloc_pq_kex_ctx == 1) {
		if ((buf_pq_kex_ctx = calloc(sizeof(*(buf_pq_kex_ctx)), 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}

	buf_pq_kex_ctx->pq_kex_name = pq_kex_name;
	buf_pq_kex_ctx->oqs_kex_ctx = NULL;

	if ((r = oqs_init(&buf_oqs_kex_ctx, pq_kex_name)) != 0)
		goto out;

	buf_pq_kex_ctx->oqs_kex_ctx = buf_oqs_kex_ctx;
	buf_oqs_kex_ctx = NULL;
	*pq_kex_ctx = buf_pq_kex_ctx;
	buf_pq_kex_ctx = NULL;

out:
	if (buf_pq_kex_ctx != NULL) {
		if (buf_pq_kex_ctx->oqs_kex_ctx != NULL)
			oqs_free(buf_pq_kex_ctx->oqs_kex_ctx);
		/*
		 * If reusing, buf_pq_kex_ctx will point to the
		 * reused memory and this wil eventually be freed
		 * by kex_free()
		 */
		if (alloc_pq_kex_ctx == 1)
			free(buf_pq_kex_ctx);
	}
	if (buf_oqs_kex_ctx != NULL)
		oqs_free(buf_oqs_kex_ctx);

	return r;
}

/*
 * @brief Free memory allocated PQ-only key exchange liboqs
 */
void
pq_oqs_free(PQ_KEX_CTX *pq_kex_ctx) {

	if (pq_kex_ctx->oqs_kex_ctx != NULL) {
		oqs_free(pq_kex_ctx->oqs_kex_ctx);
		free(pq_kex_ctx->oqs_kex_ctx);
		pq_kex_ctx->oqs_kex_ctx = NULL;
	}
}

/*
 * @brief Computes the exchange hash for liboqs PQ-only key exchange methods
 */
int
pq_oqs_hash (
	int hash_alg,
	const char *client_version_string,
	const char *server_version_string,
	const struct sshbuf *ckexinit,
	const struct sshbuf *skexinit,
	const u_char *serverhostkeyblob, size_t serverhostkeyblob_len,
	const uint8_t *oqs_client_public, size_t oqs_client_public_len,
	const uint8_t *oqs_server_public, size_t oqs_server_public_len,
	const u_char *oqs_shared_secret, size_t oqs_shared_secret_len,
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
	    (r = sshbuf_put_string(hash_buf, serverhostkeyblob, serverhostkeyblob_len)) != 0)
		goto out;
	if ((r = sshbuf_put_string(hash_buf, oqs_client_public,
		oqs_client_public_len)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, oqs_server_public,
	    oqs_server_public_len)) != 0 ||
	    (r = sshbuf_put_string(hash_buf, oqs_shared_secret, oqs_shared_secret_len)) != 0)
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

#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */
