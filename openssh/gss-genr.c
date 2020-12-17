/* $OpenBSD: gss-genr.c,v 1.26 2018/07/10 09:13:30 djm Exp $ */

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

#include <sys/types.h>

#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "log.h"
#include "ssh2.h"
#include "cipher.h"
#include "kex.h"
#include "digest.h"

#include "ssh-gss.h"

extern u_char *session_id2;
extern u_int session_id2_len;

typedef struct {
	char *encoded;
	gss_OID oid;
} ssh_gss_kex_mapping;

/*
 * XXX - It would be nice to find a more elegant way of handling the
 * XXX   passing of the key exchange context to the userauth routines
 */

Gssctxt *gss_kex_context = NULL;

static ssh_gss_kex_mapping *gss_enc2oid = NULL;

int 
ssh_gssapi_oid_table_ok(void) {
	return (gss_enc2oid != NULL);
}

/* sshbuf_get for gss_buffer_desc */
int
ssh_gssapi_get_buffer_desc(struct sshbuf *b, gss_buffer_desc *g)
{
	int r;
	u_char *p;
	size_t len;

	if ((r = sshbuf_get_string(b, &p, &len)) != 0)
		return r;
	g->value = p;
	g->length = len;
	return 0;
}

/*
 * Return a list of the gss-group1-sha1 mechanisms supported by this program
 *
 * We test mechanisms to ensure that we can use them, to avoid starting
 * a key exchange with a bad mechanism
 */

char *
ssh_gssapi_client_mechanisms(const char *host, const char *client) {
	gss_OID_set gss_supported;
	OM_uint32 min_status;

	if (GSS_ERROR(gss_indicate_mechs(&min_status, &gss_supported)))
		return NULL;

	return(ssh_gssapi_kex_mechs(gss_supported, ssh_gssapi_check_mechanism,
	    host, client));
}

char *
ssh_gssapi_kex_mechs(gss_OID_set gss_supported, ssh_gssapi_check_fn *check,
    const char *host, const char *client) {
	struct sshbuf *buf;
	size_t i;
	int r, oidpos, enclen;
	char *mechs, *encoded;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	char deroid[2];
	struct ssh_digest_ctx *md;

	if (gss_enc2oid != NULL) {
		for (i = 0; gss_enc2oid[i].encoded != NULL; i++)
			free(gss_enc2oid[i].encoded);
		free(gss_enc2oid);
	}

	gss_enc2oid = xmalloc(sizeof(ssh_gss_kex_mapping) *
	    (gss_supported->count + 1));

	if ((buf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	oidpos = 0;
	for (i = 0; i < gss_supported->count; i++) {
		if (gss_supported->elements[i].length < 128 &&
		    (*check)(NULL, &(gss_supported->elements[i]), host, client)) {

			deroid[0] = SSH_GSS_OIDTYPE;
			deroid[1] = gss_supported->elements[i].length;

			if ((md = ssh_digest_start(SSH_DIGEST_MD5)) == NULL ||
			    ssh_digest_update(md, deroid, 2) != 0 ||
			    ssh_digest_update(md,
			    gss_supported->elements[i].elements,
			    gss_supported->elements[i].length) != 0 ||
			    ssh_digest_final(md, digest, sizeof(digest)) != 0)
				fatal("%s: digest failed", __func__);

			encoded = xmalloc(ssh_digest_bytes(SSH_DIGEST_MD5)
			    * 2);
			enclen = __b64_ntop(digest,
			    ssh_digest_bytes(SSH_DIGEST_MD5), encoded,
			    ssh_digest_bytes(SSH_DIGEST_MD5) * 2);

			if (oidpos != 0) {
				if ((r = sshbuf_put_u8(buf, ',')) != 0)
					fatal("%s: buffer error: %s",
					    __func__, ssh_err(r));
			}

			if ((r = sshbuf_put(buf, KEX_GSS_GEX_SHA1_ID,
			    sizeof(KEX_GSS_GEX_SHA1_ID) - 1)) != 0 ||
			    (r = sshbuf_put(buf, encoded, enclen)) != 0 ||
			    (r = sshbuf_put_u8(buf, ',')) != 0 ||
			    (r = sshbuf_put(buf, KEX_GSS_GRP1_SHA1_ID,
			    sizeof(KEX_GSS_GRP1_SHA1_ID) - 1)) != 0 ||
			    (r = sshbuf_put(buf, encoded, enclen)) != 0 ||
			    (r = sshbuf_put_u8(buf, ',')) != 0 ||
			    (r = sshbuf_put(buf, KEX_GSS_GRP14_SHA1_ID,
			    sizeof(KEX_GSS_GRP14_SHA1_ID) - 1)) != 0 ||
			    (r = sshbuf_put(buf, encoded, enclen)) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));

			gss_enc2oid[oidpos].oid = &(gss_supported->elements[i]);
			gss_enc2oid[oidpos].encoded = encoded;
			oidpos++;
		}
	}
	gss_enc2oid[oidpos].oid = NULL;
	gss_enc2oid[oidpos].encoded = NULL;

	if ((mechs = sshbuf_dup_string(buf)) == NULL)
		fatal("%s: sshbuf_dup_string failed", __func__);

	if (strlen(mechs) == 0) {
		free(mechs);
		mechs = NULL;
	}
	
	return (mechs);
}

gss_OID
ssh_gssapi_id_kex(Gssctxt *ctx, char *name, int kex_type) {
	int i = 0;
	
	switch (kex_type) {
	case KEX_GSS_GRP1_SHA1:
		if (strlen(name) < sizeof(KEX_GSS_GRP1_SHA1_ID))
			return GSS_C_NO_OID;
		name += sizeof(KEX_GSS_GRP1_SHA1_ID) - 1;
		break;
	case KEX_GSS_GRP14_SHA1:
		if (strlen(name) < sizeof(KEX_GSS_GRP14_SHA1_ID))
			return GSS_C_NO_OID;
		name += sizeof(KEX_GSS_GRP14_SHA1_ID) - 1;
		break;
	case KEX_GSS_GEX_SHA1:
		if (strlen(name) < sizeof(KEX_GSS_GEX_SHA1_ID))
			return GSS_C_NO_OID;
		name += sizeof(KEX_GSS_GEX_SHA1_ID) - 1;
		break;
	default:
		return GSS_C_NO_OID;
	}

	while (gss_enc2oid[i].encoded != NULL &&
	    strcmp(name, gss_enc2oid[i].encoded) != 0)
		i++;

	if (gss_enc2oid[i].oid != NULL && ctx != NULL)
		ssh_gssapi_set_oid(ctx, gss_enc2oid[i].oid);

	return gss_enc2oid[i].oid;
}

/* Check that the OID in a data stream matches that in the context */
int
ssh_gssapi_check_oid(Gssctxt *ctx, void *data, size_t len)
{
	return (ctx != NULL && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
void
ssh_gssapi_set_oid_data(Gssctxt *ctx, void *data, size_t len)
{
	if (ctx->oid != GSS_C_NO_OID) {
		free(ctx->oid->elements);
		free(ctx->oid);
	}
	ctx->oid = xcalloc(1, sizeof(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
void
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
void
ssh_gssapi_error(Gssctxt *ctxt)
{
	char *s;

	s = ssh_gssapi_last_error(ctxt, NULL, NULL);
	debug("%s", s);
	free(s);
}

char *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	struct sshbuf *b;
	char *ret;
	int r;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if (major_status != NULL)
		*major_status = ctxt->major;
	if (minor_status != NULL)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	do {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &msg);

		if ((r = sshbuf_put(b, msg.value, msg.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));

		gss_release_buffer(&lmin, &msg);
	} while (ctx != 0);

	/* The mechanism specific error */
	do {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &msg);

		if ((r = sshbuf_put(b, msg.value, msg.length)) != 0 ||
		    (r = sshbuf_put_u8(b, '\n')) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));

		gss_release_buffer(&lmin, &msg);
	} while (ctx != 0);

	if ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ret = xstrdup((const char *)sshbuf_ptr(b));
	sshbuf_free(b);
	return (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
void
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, sizeof (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
void
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	if ((*ctx) == NULL)
		return;
	if ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	if ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	if ((*ctx)->oid != GSS_C_NO_OID) {
		free((*ctx)->oid->elements);
		free((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	if ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	if ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	if ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	free(*ctx);
	*ctx = NULL;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, int deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	int deleg_flag = 0;

	if (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    ctx->client_creds, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, NULL, recv_tok, NULL, send_tok, flags, NULL);

	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	return (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, const char *host)
{
	gss_buffer_desc gssbuf;
	char *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.value = val;
	gssbuf.length = strlen(gssbuf.value);

	if ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	free(gssbuf.value);
	return (ctx->major);
}

OM_uint32
ssh_gssapi_client_identity(Gssctxt *ctx, const char *name)
{
	gss_buffer_desc gssbuf;
	gss_name_t gssname;
	OM_uint32 status;
	gss_OID_set oidset;

	gssbuf.value = (void *) name;
	gssbuf.length = strlen(gssbuf.value);

	gss_create_empty_oid_set(&status, &oidset);
	gss_add_oid_set_member(&status, ctx->oid, &oidset);

	ctx->major = gss_import_name(&ctx->minor, &gssbuf,
	    GSS_C_NT_USER_NAME, &gssname);

	if (!ctx->major)
		ctx->major = gss_acquire_cred(&ctx->minor, 
		    gssname, 0, oidset, GSS_C_INITIATE, 
		    &ctx->client_creds, NULL, NULL);

	gss_release_name(&status, &gssname);
	gss_release_oid_set(&status, &oidset);

	if (ctx->major)
		ssh_gssapi_error(ctx);

	return(ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	if (ctx == NULL) 
		return -1;

	if ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	return (ctx->major);
}

/* Priviledged when used by server */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	if (ctx == NULL)
		return -1;

	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, NULL);

	return (ctx->major);
}

void
ssh_gssapi_buildmic(struct sshbuf *b, const char *user, const char *service,
    const char *context)
{
	int r;

	sshbuf_reset(b);
	if ((r = sshbuf_put_string(b, session_id2, session_id2_len)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

int
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, const char *host, 
    const char *client)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (void *)"\x2B\x06\x01\x05\x05\x02"};
	Gssctxt *intctx = NULL;

	if (ctx == NULL)
		ctx = &intctx;

	/* RFC 4462 says we MUST NOT do SPNEGO */
	if (oid->length == spnego_oid.length && 
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		return 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);

	if (!GSS_ERROR(major) && client)
		major = ssh_gssapi_client_identity(*ctx, client);

	if (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token, 
		    NULL);
		gss_release_buffer(&minor, &token);
		if ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	if (GSS_ERROR(major) || intctx != NULL) 
		ssh_gssapi_delete_ctx(ctx);

	return (!GSS_ERROR(major));
}

int
ssh_gssapi_credentials_updated(Gssctxt *ctxt) {
	static gss_name_t saved_name = GSS_C_NO_NAME;
	static OM_uint32 saved_lifetime = 0;
	static gss_OID saved_mech = GSS_C_NO_OID;
	static gss_name_t name;
	static OM_uint32 last_call = 0;
	OM_uint32 lifetime, now, major, minor;
	int equal;
	
	now = time(NULL);

	if (ctxt) {
		debug("Rekey has happened - updating saved versions");

		if (saved_name != GSS_C_NO_NAME)
			gss_release_name(&minor, &saved_name);

		major = gss_inquire_cred(&minor, GSS_C_NO_CREDENTIAL,
		    &saved_name, &saved_lifetime, NULL, NULL);

		if (!GSS_ERROR(major)) {
			saved_mech = ctxt->oid;
		        saved_lifetime+= now;
		} else {
			/* Handle the error */
		}
		return 0;
	}

	if (now - last_call < 10)
		return 0;

	last_call = now;

	if (saved_mech == GSS_C_NO_OID)
		return 0;
	
	major = gss_inquire_cred(&minor, GSS_C_NO_CREDENTIAL, 
	    &name, &lifetime, NULL, NULL);
	if (major == GSS_S_CREDENTIALS_EXPIRED)
		return 0;
	else if (GSS_ERROR(major))
		return 0;

	major = gss_compare_name(&minor, saved_name, name, &equal);
	gss_release_name(&minor, &name);
	if (GSS_ERROR(major))
		return 0;

	if (equal && (saved_lifetime < lifetime + now - 10))
		return 1;

	return 0;
}

#endif /* GSSAPI */
