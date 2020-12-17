/* 	$OpenBSD: test_kex.c,v 1.2 2015/07/10 06:23:25 markus Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "ssh_api.h"
#include "sshbuf.h"
#include "packet.h"
#include "myproposal.h"

struct ssh *active_state = NULL; /* XXX - needed for linking */

void kex_tests(void);
static int do_debug = 0;

static int
do_send_and_receive(struct ssh *from, struct ssh *to)
{
	u_char type;
	size_t len;
	const u_char *buf;
	int r;

	for (;;) {
		if ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			return r;
		}
		if (type != 0)
			return 0;
		buf = ssh_output_ptr(from, &len);
		if (do_debug)
			printf("%zu", len);
		if (len == 0)
			return 0;
		if ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_input_append(to, buf, len)) != 0)
			return r;
	}
}

static void
run_kex(struct ssh *client, struct ssh *server)
{
	int r = 0;

	while (!server->kex->done || !client->kex->done) {
		if (do_debug)
			printf(" S:");
		if ((r = do_send_and_receive(server, client)))
			break;
		if (do_debug)
			printf(" C:");
		if ((r = do_send_and_receive(client, server)))
			break;
	}
	if (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

static void
do_kex_with_key(char *kex, int keytype, int bits)
{
	struct ssh *client = NULL, *server = NULL, *server2 = NULL;
	struct sshkey *private, *public;
	struct sshbuf *state;
	struct kex_params kex_params;
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	char *keyname = NULL;

	TEST_START("sshkey_generate");
	ASSERT_INT_EQ(sshkey_generate(keytype, bits, &private), 0);
	TEST_DONE();

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(private, &public), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, sizeof(myproposal));
	if (kex != NULL)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	keyname = strdup(sshkey_ssh_name(private));
	ASSERT_PTR_NE(keyname, NULL);
	kex_params.proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, NULL);
	ASSERT_PTR_NE(server, NULL);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, private), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, public), 0);
	TEST_DONE();

	TEST_START("kex");
	run_kex(client, server);
	TEST_DONE();

	TEST_START("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server);
	TEST_DONE();

	TEST_START("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	run_kex(client, server);
	TEST_DONE();

	TEST_START("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, NULL);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = NULL;
	ASSERT_INT_EQ(ssh_init(&server2, 1, NULL), 0);
	ASSERT_PTR_NE(server2, NULL);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, private), 0);
	kex_free(server2->kex);	/* XXX or should ssh_packet_set_state()? */
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, NULL);
	/* XXX we need to set the callbacks */
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kexdh_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kexdh_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
#ifdef OPENSSL_HAS_ECC
	server2->kex->kex[KEX_ECDH_SHA2] = kexecdh_server;
	server2->kex->kex[KEX_HY_ECDH_OQS] = get_hybrid_ecdh_oqs_server_cb();
#endif
	server2->kex->kex[KEX_PQ_OQS] = get_pq_oqs_server_cb();
	server2->kex->kex[KEX_C25519_SHA256] = kexc25519_server;
	server2->kex->load_host_public_key = server->kex->load_host_public_key;
	server2->kex->load_host_private_key = server->kex->load_host_private_key;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(private);
	sshkey_free(public);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	free(keyname);
	TEST_DONE();
}

static void
do_kex(char *kex)
{
	do_kex_with_key(kex, KEY_RSA, 2048);
	do_kex_with_key(kex, KEY_DSA, 1024);
#ifdef OPENSSL_HAS_ECC
	do_kex_with_key(kex, KEY_ECDSA, 256);
#endif
	do_kex_with_key(kex, KEY_ED25519, 256);
}

void
kex_tests(void)
{
	do_kex("curve25519-sha256@libssh.org");
#ifdef OPENSSL_HAS_ECC
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
#if defined(WITH_OQS) && defined(WITH_HYBRID_KEX)
///// OQS_TEMPLATE_FRAGMENT_DO_HYBRID_KEXS_START
#ifdef HAVE_BIKE
	do_kex(KEX_ECDH_NISTP384_BIKE1_L1_CPA_SHA384);
	do_kex(KEX_ECDH_NISTP384_BIKE1_L3_CPA_SHA384);
	do_kex(KEX_ECDH_NISTP384_BIKE1_L1_FO_SHA384);
	do_kex(KEX_ECDH_NISTP384_BIKE1_L3_FO_SHA384);
#endif /* HAVE_BIKE */
#ifdef HAVE_CLASSIC_MCELIECE
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_348864_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_348864F_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_460896F_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6688128_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6688128F_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6960119_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_6960119F_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_8192128_SHA384);
	do_kex(KEX_ECDH_NISTP384_CLASSIC_MCELIECE_8192128F_SHA384);
#endif /* HAVE_CLASSIC_MCELIECE */
#ifdef HAVE_FRODO
	do_kex(KEX_ECDH_NISTP384_FRODO_640_AES_SHA384);
	do_kex(KEX_ECDH_NISTP384_FRODO_640_SHAKE_SHA384);
	do_kex(KEX_ECDH_NISTP384_FRODO_976_AES_SHA384);
	do_kex(KEX_ECDH_NISTP384_FRODO_976_SHAKE_SHA384);
	do_kex(KEX_ECDH_NISTP384_FRODO_1344_AES_SHA384);
	do_kex(KEX_ECDH_NISTP384_FRODO_1344_SHAKE_SHA384);
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
	do_kex(KEX_ECDH_NISTP384_KYBER_512_SHA384);
	do_kex(KEX_ECDH_NISTP384_KYBER_768_SHA384);
	do_kex(KEX_ECDH_NISTP384_KYBER_1024_SHA384);
	do_kex(KEX_ECDH_NISTP384_KYBER_512_90S_SHA384);
	do_kex(KEX_ECDH_NISTP384_KYBER_768_90S_SHA384);
	do_kex(KEX_ECDH_NISTP384_KYBER_1024_90S_SHA384);
#endif /* HAVE_KYBER */
#ifdef HAVE_NEWHOPE
	do_kex(KEX_ECDH_NISTP384_NEWHOPE_512_SHA384);
	do_kex(KEX_ECDH_NISTP384_NEWHOPE_1024_SHA384);
#endif /* HAVE_NEWHOPE */
#ifdef HAVE_NTRU
	do_kex(KEX_ECDH_NISTP384_NTRU_HPS_2048_509_SHA384);
	do_kex(KEX_ECDH_NISTP384_NTRU_HPS_2048_677_SHA384);
	do_kex(KEX_ECDH_NISTP384_NTRU_HRSS_701_SHA384);
	do_kex(KEX_ECDH_NISTP384_NTRU_HPS_4096_821_SHA384);
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
	do_kex(KEX_ECDH_NISTP384_SABER_LIGHTSABER_SHA384);
	do_kex(KEX_ECDH_NISTP384_SABER_SABER_SHA384);
	do_kex(KEX_ECDH_NISTP384_SABER_FIRESABER_SHA384);
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
	do_kex(KEX_ECDH_NISTP384_SIDH_p434_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_p503_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_p610_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_p751_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_P434_COMPRESSED_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_P503_COMPRESSED_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_P610_COMPRESSED_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIDH_P751_COMPRESSED_SHA384);
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
	do_kex(KEX_ECDH_NISTP384_SIKE_P434_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P503_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P610_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P751_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P434_COMPRESSED_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P503_COMPRESSED_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P610_COMPRESSED_SHA384);
	do_kex(KEX_ECDH_NISTP384_SIKE_P751_COMPRESSED_SHA384);
#endif /* HAVE_SIKE */
#ifdef HAVE_THREEBEARS
	do_kex(KEX_ECDH_NISTP384_BABYBEAR_SHA384);
	do_kex(KEX_ECDH_NISTP384_BABYBEAR_EPHEM_SHA384);
	do_kex(KEX_ECDH_NISTP384_MAMABEAR_SHA384);
	do_kex(KEX_ECDH_NISTP384_MAMABEAR_EPHEM_SHA384);
	do_kex(KEX_ECDH_NISTP384_PAPABEAR_SHA384);
	do_kex(KEX_ECDH_NISTP384_PAPABEAR_EPHEM_SHA384);
#endif /* HAVE_THREEBEARS */
#ifdef HAVE_HQC
	do_kex(KEX_ECDH_NISTP384_HQC_128_1_CCA2_SHA384);
	do_kex(KEX_ECDH_NISTP384_HQC_192_1_CCA2_SHA384);
	do_kex(KEX_ECDH_NISTP384_HQC_192_2_CCA2_SHA384);
	do_kex(KEX_ECDH_NISTP384_HQC_256_1_CCA2_SHA384);
	do_kex(KEX_ECDH_NISTP384_HQC_256_2_CCA2_SHA384);
	do_kex(KEX_ECDH_NISTP384_HQC_256_3_CCA2_SHA384);
#endif /* HAVE_HQC */
///// OQS_TEMPLATE_FRAGMENT_DO_HYBRID_KEXS_END
#endif /* defined(WITH_OQS) && defined(WITH_HYBRID_KEX) */
#endif /* OPENSSL_HAS_ECC */
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
#if defined(WITH_OQS) && defined(WITH_OQ_KEX)
///// OQS_TEMPLATE_FRAGMENT_DO_PQ_KEXS_START
#ifdef HAVE_BIKE
	do_kex(KEX_BIKE1_L1_CPA_SHA384);
	do_kex(KEX_BIKE1_L3_CPA_SHA384);
	do_kex(KEX_BIKE1_L1_FO_SHA384);
	do_kex(KEX_BIKE1_L3_FO_SHA384);
#endif /* HAVE_BIKE */
#ifdef HAVE_CLASSIC_MCELIECE
	do_kex(KEX_CLASSIC_MCELIECE_348864_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_348864F_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_460896_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_460896F_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_6688128_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_6688128F_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_6960119_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_6960119F_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_8192128_SHA384);
	do_kex(KEX_CLASSIC_MCELIECE_8192128F_SHA384);
#endif /* HAVE_CLASSIC_MCELIECE */
#ifdef HAVE_FRODO
	do_kex(KEX_FRODO_640_AES_SHA384);
	do_kex(KEX_FRODO_640_SHAKE_SHA384);
	do_kex(KEX_FRODO_976_AES_SHA384);
	do_kex(KEX_FRODO_976_SHAKE_SHA384);
	do_kex(KEX_FRODO_1344_AES_SHA384);
	do_kex(KEX_FRODO_1344_SHAKE_SHA384);
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
	do_kex(KEX_KYBER_512_SHA384);
	do_kex(KEX_KYBER_768_SHA384);
	do_kex(KEX_KYBER_1024_SHA384);
	do_kex(KEX_KYBER_512_90S_SHA384);
	do_kex(KEX_KYBER_768_90S_SHA384);
	do_kex(KEX_KYBER_1024_90S_SHA384);
#endif /* HAVE_KYBER */
#ifdef HAVE_NEWHOPE
	do_kex(KEX_NEWHOPE_512_SHA384);
	do_kex(KEX_NEWHOPE_1024_SHA384);
#endif /* HAVE_NEWHOPE */
#ifdef HAVE_NTRU
	do_kex(KEX_NTRU_HPS_2048_509_SHA384);
	do_kex(KEX_NTRU_HPS_2048_677_SHA384);
	do_kex(KEX_NTRU_HRSS_701_SHA384);
	do_kex(KEX_NTRU_HPS_4096_821_SHA384);
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
	do_kex(KEX_SABER_LIGHTSABER_SHA384);
	do_kex(KEX_SABER_SABER_SHA384);
	do_kex(KEX_SABER_FIRESABER_SHA384);
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
	do_kex(KEX_SIDH_p434_SHA384);
	do_kex(KEX_SIDH_p503_SHA384);
	do_kex(KEX_SIDH_p610_SHA384);
	do_kex(KEX_SIDH_p751_SHA384);
	do_kex(KEX_SIDH_P434_COMPRESSED_SHA384);
	do_kex(KEX_SIDH_P503_COMPRESSED_SHA384);
	do_kex(KEX_SIDH_P610_COMPRESSED_SHA384);
	do_kex(KEX_SIDH_P751_COMPRESSED_SHA384);
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
	do_kex(KEX_SIKE_P434_SHA384);
	do_kex(KEX_SIKE_P503_SHA384);
	do_kex(KEX_SIKE_P610_SHA384);
	do_kex(KEX_SIKE_P751_SHA384);
	do_kex(KEX_SIKE_P434_COMPRESSED_SHA384);
	do_kex(KEX_SIKE_P503_COMPRESSED_SHA384);
	do_kex(KEX_SIKE_P610_COMPRESSED_SHA384);
	do_kex(KEX_SIKE_P751_COMPRESSED_SHA384);
#endif /* HAVE_SIKE */
#ifdef HAVE_THREEBEARS
	do_kex(KEX_BABYBEAR_SHA384);
	do_kex(KEX_BABYBEAR_EPHEM_SHA384);
	do_kex(KEX_MAMABEAR_SHA384);
	do_kex(KEX_MAMABEAR_EPHEM_SHA384);
	do_kex(KEX_PAPABEAR_SHA384);
	do_kex(KEX_PAPABEAR_EPHEM_SHA384);
#endif /* HAVE_THREEBEARS */
#ifdef HAVE_HQC
	do_kex(KEX_HQC_128_1_CCA2_SHA384);
	do_kex(KEX_HQC_192_1_CCA2_SHA384);
	do_kex(KEX_HQC_192_2_CCA2_SHA384);
	do_kex(KEX_HQC_256_1_CCA2_SHA384);
	do_kex(KEX_HQC_256_2_CCA2_SHA384);
	do_kex(KEX_HQC_256_3_CCA2_SHA384);
#endif /* HAVE_HQC */
///// OQS_TEMPLATE_FRAGMENT_DO_PQ_KEXS_END
#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */
}
