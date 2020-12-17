/*
 * Copyright (c) 2001-2009 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
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

#ifdef GSSAPI

#include "includes.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include <string.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssh2.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "digest.h"

#include "ssh-gss.h"

int
kexgss_client(struct ssh *ssh) {
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok, gssbuf, msg_tok, *token_ptr;
	Gssctxt *ctxt;
	OM_uint32 maj_status, min_status, ret_flags;
	u_int klen, kout, slen = 0, strlen;
	DH *dh; 
	BIGNUM *dh_server_pub = NULL;
	BIGNUM *shared_secret = NULL;
	const BIGNUM *pub_key, *dh_p, *dh_g;
	BIGNUM *p = NULL;
	BIGNUM *g = NULL;	
	u_char *kbuf;
	u_char *serverhostkey = NULL;
	u_char *empty = "";
	char *msg;
	int type = 0;
	int first = 1;
	int nbits = 0, min = DH_GRP_MIN, max = DH_GRP_MAX;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;

	/* Initialise our GSSAPI world */	
	ssh_gssapi_build_ctx(&ctxt);
	if (ssh_gssapi_id_kex(ctxt, ssh->kex->name, ssh->kex->kex_type) 
	    == GSS_C_NO_OID)
		fatal("Couldn't identify host exchange");

	if (ssh_gssapi_import_name(ctxt, ssh->kex->gss_host))
		fatal("Couldn't import hostname");

	if (ssh->kex->gss_client && 
	    ssh_gssapi_client_identity(ctxt, ssh->kex->gss_client))
		fatal("Couldn't acquire client credentials");

	switch (ssh->kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
		dh = dh_new_group1();
		break;
	case KEX_GSS_GRP14_SHA1:
		dh = dh_new_group14();
		break;
	case KEX_GSS_GEX_SHA1:
		debug("Doing group exchange\n");
		nbits = dh_estimate(ssh->kex->we_need * 8);
		packet_start(SSH2_MSG_KEXGSS_GROUPREQ);
		packet_put_int(min);
		packet_put_int(nbits);
		packet_put_int(max);

		packet_send();

		packet_read_expect(SSH2_MSG_KEXGSS_GROUP);

		if ((p = BN_new()) == NULL)
			fatal("BN_new() failed");
		packet_get_bignum2(p);
		if ((g = BN_new()) == NULL)
			fatal("BN_new() failed");
		packet_get_bignum2(g);
		packet_check_eom();

		if (BN_num_bits(p) < min || BN_num_bits(p) > max)
			fatal("GSSGRP_GEX group out of range: %d !< %d !< %d",
			    min, BN_num_bits(p), max);

		dh = dh_new_group(g, p);
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, ssh->kex->kex_type);
	}
	
	/* Step 1 - e is dh->pub_key */
	dh_gen_key(dh, ssh->kex->we_need * 8);
	DH_get0_key(dh, &pub_key, NULL);
	DH_get0_pqg(dh, &dh_p, NULL, &dh_g);

	/* This is f, we initialise it now to make life easier */
	dh_server_pub = BN_new();
	if (dh_server_pub == NULL)
		fatal("dh_server_pub == NULL");

	token_ptr = GSS_C_NO_BUFFER;
			 
	do {
		debug("Calling gss_init_sec_context");
		
		maj_status = ssh_gssapi_init_ctx(ctxt,
		    ssh->kex->gss_deleg_creds, token_ptr, &send_tok,
		    &ret_flags);

		if (GSS_ERROR(maj_status)) {
			if (send_tok.length != 0) {
				packet_start(SSH2_MSG_KEXGSS_CONTINUE);
				packet_put_string(send_tok.value,
				    send_tok.length);
			}
			fatal("gss_init_context failed");
		}

		/* If we've got an old receive buffer get rid of it */
		if (token_ptr != GSS_C_NO_BUFFER)
			free(recv_tok.value);

		if (maj_status == GSS_S_COMPLETE) {
			/* If mutual state flag is not true, kex fails */
			if (!(ret_flags & GSS_C_MUTUAL_FLAG))
				fatal("Mutual authentication failed");

			/* If integ avail flag is not true kex fails */
			if (!(ret_flags & GSS_C_INTEG_FLAG))
				fatal("Integrity check failed");
		}

		/* 
		 * If we have data to send, then the last message that we
		 * received cannot have been a 'complete'. 
		 */
		if (send_tok.length != 0) {
			if (first) {
				packet_start(SSH2_MSG_KEXGSS_INIT);
				packet_put_string(send_tok.value,
				    send_tok.length);
				packet_put_bignum2(pub_key);
				first = 0;
			} else {
				packet_start(SSH2_MSG_KEXGSS_CONTINUE);
				packet_put_string(send_tok.value,
				    send_tok.length);
			}
			packet_send();
			gss_release_buffer(&min_status, &send_tok);

			/* If we've sent them data, they should reply */
			do {	
				type = packet_read();
				if (type == SSH2_MSG_KEXGSS_HOSTKEY) {
					debug("Received KEXGSS_HOSTKEY");
					if (serverhostkey)
						fatal("Server host key received more than once");
					serverhostkey = 
					    packet_get_string(&slen);
				}
			} while (type == SSH2_MSG_KEXGSS_HOSTKEY);

			switch (type) {
			case SSH2_MSG_KEXGSS_CONTINUE:
				debug("Received GSSAPI_CONTINUE");
				if (maj_status == GSS_S_COMPLETE) 
					fatal("GSSAPI Continue received from server when complete");
				recv_tok.value = packet_get_string(&strlen);
				recv_tok.length = strlen; 
				break;
			case SSH2_MSG_KEXGSS_COMPLETE:
				debug("Received GSSAPI_COMPLETE");
				packet_get_bignum2(dh_server_pub);
				msg_tok.value =  packet_get_string(&strlen);
				msg_tok.length = strlen; 

				/* Is there a token included? */
				if (packet_get_char()) {
					recv_tok.value=
					    packet_get_string(&strlen);
					recv_tok.length = strlen;
					/* If we're already complete - protocol error */
					if (maj_status == GSS_S_COMPLETE)
						packet_disconnect("Protocol error: received token when complete");
					} else {
						/* No token included */
						if (maj_status != GSS_S_COMPLETE)
							packet_disconnect("Protocol error: did not receive final token");
				}
				break;
			case SSH2_MSG_KEXGSS_ERROR:
				debug("Received Error");
				maj_status = packet_get_int();
				min_status = packet_get_int();
				msg = packet_get_string(NULL);
				(void) packet_get_string_ptr(NULL);
				fatal("GSSAPI Error: \n%.400s",msg);
			default:
				packet_disconnect("Protocol error: didn't expect packet type %d",
		    		type);
			}
			token_ptr = &recv_tok;
		} else {
			/* No data, and not complete */
			if (maj_status != GSS_S_COMPLETE)
				fatal("Not complete, and no token output");
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	/* 
	 * We _must_ have received a COMPLETE message in reply from the 
	 * server, which will have set dh_server_pub and msg_tok 
	 */

	if (type != SSH2_MSG_KEXGSS_COMPLETE)
		fatal("Didn't receive a SSH2_MSG_KEXGSS_COMPLETE when I expected it");

	/* Check f in range [1, p-1] */
	if (!dh_pub_is_valid(dh, dh_server_pub))
		packet_disconnect("bad server public DH value");

	/* compute K=f^x mod p */
	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	kout = DH_compute_key(kbuf, dh_server_pub, dh);
	if (kout < 0)
		fatal("DH_compute_key: failed");

	shared_secret = BN_new();
	if (shared_secret == NULL)
		fatal("kexgss_client: BN_new failed");

	if (BN_bin2bn(kbuf, kout, shared_secret) == NULL)
		fatal("kexdh_client: BN_bin2bn failed");

	memset(kbuf, 0, klen);
	free(kbuf);

	hashlen = sizeof(hash);
	switch (ssh->kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
	case KEX_GSS_GRP14_SHA1:
		kex_dh_hash(
		    ssh->kex->hash_alg,
		    ssh->kex->client_version_string,
		    ssh->kex->server_version_string,
		    sshbuf_ptr(ssh->kex->my), sshbuf_len(ssh->kex->my),
		    sshbuf_ptr(ssh->kex->peer), sshbuf_len(ssh->kex->peer),
		    (serverhostkey ? serverhostkey : empty), slen,
		    pub_key,		/* e */
		    dh_server_pub,	/* f */
		    shared_secret,	/* K */
		    hash, &hashlen
		);
		break;
	case KEX_GSS_GEX_SHA1:
		kexgex_hash(
		    ssh->kex->hash_alg,
		    ssh->kex->client_version_string,
		    ssh->kex->server_version_string,
		    sshbuf_ptr(ssh->kex->my), sshbuf_len(ssh->kex->my),
		    sshbuf_ptr(ssh->kex->peer), sshbuf_len(ssh->kex->peer),
		    (serverhostkey ? serverhostkey : empty), slen,
 		    min, nbits, max,
		    dh_p, dh_g,
		    pub_key,
		    dh_server_pub,
		    shared_secret,
		    hash, &hashlen
		);
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, ssh->kex->kex_type);
	}

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	/* Verify that the hash matches the MIC we just got. */
	if (GSS_ERROR(ssh_gssapi_checkmic(ctxt, &gssbuf, &msg_tok)))
		packet_disconnect("Hash's MIC didn't verify");

	free(msg_tok.value);

	DH_free(dh);
	free(serverhostkey);
	BN_clear_free(dh_server_pub);

	/* save session id */
	if (ssh->kex->session_id == NULL) {
		ssh->kex->session_id_len = hashlen;
		ssh->kex->session_id = xmalloc(ssh->kex->session_id_len);
		memcpy(ssh->kex->session_id, hash, ssh->kex->session_id_len);
	}

	if (ssh->kex->gss_deleg_creds)
		ssh_gssapi_credentials_updated(ctxt);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	kex_derive_keys_bn(ssh, hash, hashlen, shared_secret);
	BN_clear_free(shared_secret);
	return kex_send_newkeys(ssh);
}

#endif /* GSSAPI */
