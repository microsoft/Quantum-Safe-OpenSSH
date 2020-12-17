/* $OpenBSD: pathnames.h,v 1.28 2018/02/23 15:58:37 markus Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#define ETCDIR				"/etc"

#ifndef SSHDIR
#define SSHDIR				ETCDIR "/ssh"
#endif

#ifndef _PATH_SSH_PIDDIR
#define _PATH_SSH_PIDDIR		"/var/run"
#endif

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#define _PATH_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#define _PATH_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#define _PATH_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#define _PATH_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#define _PATH_HOST_DSA_KEY_FILE		SSHDIR "/ssh_host_dsa_key"
#define _PATH_HOST_ECDSA_KEY_FILE	SSHDIR "/ssh_host_ecdsa_key"
#define _PATH_HOST_ED25519_KEY_FILE	SSHDIR "/ssh_host_ed25519_key"
#define _PATH_HOST_XMSS_KEY_FILE	SSHDIR "/ssh_host_xmss_key"
#define _PATH_HOST_RSA_KEY_FILE		SSHDIR "/ssh_host_rsa_key"
///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_KEY_FILES_START
#define _PATH_HOST_DILITHIUM_2_KEY_FILE SSHDIR "/ssh_host_dilithium2_key"
#define _PATH_HOST_FALCON_512_KEY_FILE SSHDIR "/ssh_host_falcon512_key"
#define _PATH_HOST_MQDSS_31_48_KEY_FILE SSHDIR "/ssh_host_mqdss3148_key"
#define _PATH_HOST_PICNIC_L1FS_KEY_FILE SSHDIR "/ssh_host_picnicl1fs_key"
#define _PATH_HOST_PICNIC3_L1_KEY_FILE SSHDIR "/ssh_host_picnic3l1_key"
#define _PATH_HOST_QTESLA_P_I_KEY_FILE SSHDIR "/ssh_host_qteslapi_key"
#define _PATH_HOST_RAINBOW_IA_CLASSIC_KEY_FILE SSHDIR "/ssh_host_rainbowiaclassic_key"
#define _PATH_HOST_RAINBOW_IIIC_CLASSIC_KEY_FILE SSHDIR "/ssh_host_rainbowiiicclassic_key"
#define _PATH_HOST_RAINBOW_VC_CLASSIC_KEY_FILE SSHDIR "/ssh_host_rainbowvcclassic_key"
#define _PATH_HOST_SPHINCS_HARAKA_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_sphincsharaka128frobust_key"
#define _PATH_HOST_SPHINCS_SHA256_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_sphincssha256128frobust_key"
#define _PATH_HOST_SPHINCS_SHAKE256_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_sphincsshake256128frobust_key"
#define _PATH_HOST_RSA3072_DILITHIUM_2_KEY_FILE SSHDIR "/ssh_host_rsa3072_dilithium2_key"
#define _PATH_HOST_P256_DILITHIUM_2_KEY_FILE SSHDIR "/ssh_host_p256_dilithium2_key"
#define _PATH_HOST_RSA3072_FALCON_512_KEY_FILE SSHDIR "/ssh_host_rsa3072_falcon512_key"
#define _PATH_HOST_P256_FALCON_512_KEY_FILE SSHDIR "/ssh_host_p256_falcon512_key"
#define _PATH_HOST_RSA3072_MQDSS_31_48_KEY_FILE SSHDIR "/ssh_host_rsa3072_mqdss3148_key"
#define _PATH_HOST_P256_MQDSS_31_48_KEY_FILE SSHDIR "/ssh_host_p256_mqdss3148_key"
#define _PATH_HOST_RSA3072_PICNIC_L1FS_KEY_FILE SSHDIR "/ssh_host_rsa3072_picnicl1fs_key"
#define _PATH_HOST_P256_PICNIC_L1FS_KEY_FILE SSHDIR "/ssh_host_p256_picnicl1fs_key"
#define _PATH_HOST_RSA3072_PICNIC3_L1_KEY_FILE SSHDIR "/ssh_host_rsa3072_picnic3l1_key"
#define _PATH_HOST_P256_PICNIC3_L1_KEY_FILE SSHDIR "/ssh_host_p256_picnic3l1_key"
#define _PATH_HOST_RSA3072_QTESLA_P_I_KEY_FILE SSHDIR "/ssh_host_rsa3072_qteslapi_key"
#define _PATH_HOST_P256_QTESLA_P_I_KEY_FILE SSHDIR "/ssh_host_p256_qteslapi_key"
#define _PATH_HOST_RSA3072_RAINBOW_IA_CLASSIC_KEY_FILE SSHDIR "/ssh_host_rsa3072_rainbowiaclassic_key"
#define _PATH_HOST_P256_RAINBOW_IA_CLASSIC_KEY_FILE SSHDIR "/ssh_host_p256_rainbowiaclassic_key"
#define _PATH_HOST_P384_RAINBOW_IIIC_CLASSIC_KEY_FILE SSHDIR "/ssh_host_p384_rainbowiiicclassic_key"
#define _PATH_HOST_P521_RAINBOW_VC_CLASSIC_KEY_FILE SSHDIR "/ssh_host_p521_rainbowvcclassic_key"
#define _PATH_HOST_RSA3072_SPHINCS_HARAKA_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_rsa3072_sphincsharaka128frobust_key"
#define _PATH_HOST_P256_SPHINCS_HARAKA_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_p256_sphincsharaka128frobust_key"
#define _PATH_HOST_RSA3072_SPHINCS_SHA256_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_rsa3072_sphincssha256128frobust_key"
#define _PATH_HOST_P256_SPHINCS_SHA256_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_p256_sphincssha256128frobust_key"
#define _PATH_HOST_RSA3072_SPHINCS_SHAKE256_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_rsa3072_sphincsshake256128frobust_key"
#define _PATH_HOST_P256_SPHINCS_SHAKE256_128F_ROBUST_KEY_FILE SSHDIR "/ssh_host_p256_sphincsshake256128frobust_key"
///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_KEY_FILES_END
#define _PATH_DH_MODULI			SSHDIR "/moduli"

#ifndef _PATH_SSH_PROGRAM
#define _PATH_SSH_PROGRAM		"/usr/bin/ssh"
#endif

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#define _PATH_SSH_DAEMON_PID_FILE	_PATH_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#define _PATH_SSH_USER_DIR		".ssh"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#define _PATH_SSH_USER_HOSTFILE		"~/" _PATH_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#define _PATH_SSH_USER_HOSTFILE2	"~/" _PATH_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#define _PATH_SSH_CLIENT_ID_DSA		_PATH_SSH_USER_DIR "/id_dsa"
#define _PATH_SSH_CLIENT_ID_ECDSA	_PATH_SSH_USER_DIR "/id_ecdsa"
#define _PATH_SSH_CLIENT_ID_RSA		_PATH_SSH_USER_DIR "/id_rsa"
#define _PATH_SSH_CLIENT_ID_ED25519	_PATH_SSH_USER_DIR "/id_ed25519"
#define _PATH_SSH_CLIENT_ID_XMSS	_PATH_SSH_USER_DIR "/id_xmss"
///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_ID_FILES_START
#define _PATH_SSH_CLIENT_ID_DILITHIUM_2 _PATH_SSH_USER_DIR "/id_dilithium2"
#define _PATH_SSH_CLIENT_ID_FALCON_512 _PATH_SSH_USER_DIR "/id_falcon512"
#define _PATH_SSH_CLIENT_ID_MQDSS_31_48 _PATH_SSH_USER_DIR "/id_mqdss3148"
#define _PATH_SSH_CLIENT_ID_PICNIC_L1FS _PATH_SSH_USER_DIR "/id_picnicl1fs"
#define _PATH_SSH_CLIENT_ID_PICNIC3_L1 _PATH_SSH_USER_DIR "/id_picnic3l1"
#define _PATH_SSH_CLIENT_ID_QTESLA_P_I _PATH_SSH_USER_DIR "/id_qteslapi"
#define _PATH_SSH_CLIENT_ID_RAINBOW_IA_CLASSIC _PATH_SSH_USER_DIR "/id_rainbowiaclassic"
#define _PATH_SSH_CLIENT_ID_RAINBOW_IIIC_CLASSIC _PATH_SSH_USER_DIR "/id_rainbowiiicclassic"
#define _PATH_SSH_CLIENT_ID_RAINBOW_VC_CLASSIC _PATH_SSH_USER_DIR "/id_rainbowvcclassic"
#define _PATH_SSH_CLIENT_ID_SPHINCS_HARAKA_128F_ROBUST _PATH_SSH_USER_DIR "/id_sphincsharaka128frobust"
#define _PATH_SSH_CLIENT_ID_SPHINCS_SHA256_128F_ROBUST _PATH_SSH_USER_DIR "/id_sphincssha256128frobust"
#define _PATH_SSH_CLIENT_ID_SPHINCS_SHAKE256_128F_ROBUST _PATH_SSH_USER_DIR "/id_sphincsshake256128frobust"
#define _PATH_SSH_CLIENT_ID_RSA3072_DILITHIUM_2 _PATH_SSH_USER_DIR "/id_rsa3072_dilithium2"
#define _PATH_SSH_CLIENT_ID_P256_DILITHIUM_2 _PATH_SSH_USER_DIR "/id_p256_dilithium2"
#define _PATH_SSH_CLIENT_ID_RSA3072_FALCON_512 _PATH_SSH_USER_DIR "/id_rsa3072_falcon512"
#define _PATH_SSH_CLIENT_ID_P256_FALCON_512 _PATH_SSH_USER_DIR "/id_p256_falcon512"
#define _PATH_SSH_CLIENT_ID_RSA3072_MQDSS_31_48 _PATH_SSH_USER_DIR "/id_rsa3072_mqdss3148"
#define _PATH_SSH_CLIENT_ID_P256_MQDSS_31_48 _PATH_SSH_USER_DIR "/id_p256_mqdss3148"
#define _PATH_SSH_CLIENT_ID_RSA3072_PICNIC_L1FS _PATH_SSH_USER_DIR "/id_rsa3072_picnicl1fs"
#define _PATH_SSH_CLIENT_ID_P256_PICNIC_L1FS _PATH_SSH_USER_DIR "/id_p256_picnicl1fs"
#define _PATH_SSH_CLIENT_ID_RSA3072_PICNIC3_L1 _PATH_SSH_USER_DIR "/id_rsa3072_picnic3l1"
#define _PATH_SSH_CLIENT_ID_P256_PICNIC3_L1 _PATH_SSH_USER_DIR "/id_p256_picnic3l1"
#define _PATH_SSH_CLIENT_ID_RSA3072_QTESLA_P_I _PATH_SSH_USER_DIR "/id_rsa3072_qteslapi"
#define _PATH_SSH_CLIENT_ID_P256_QTESLA_P_I _PATH_SSH_USER_DIR "/id_p256_qteslapi"
#define _PATH_SSH_CLIENT_ID_RSA3072_RAINBOW_IA_CLASSIC _PATH_SSH_USER_DIR "/id_rsa3072_rainbowiaclassic"
#define _PATH_SSH_CLIENT_ID_P256_RAINBOW_IA_CLASSIC _PATH_SSH_USER_DIR "/id_p256_rainbowiaclassic"
#define _PATH_SSH_CLIENT_ID_P384_RAINBOW_IIIC_CLASSIC _PATH_SSH_USER_DIR "/id_p384_rainbowiiicclassic"
#define _PATH_SSH_CLIENT_ID_P521_RAINBOW_VC_CLASSIC _PATH_SSH_USER_DIR "/id_p521_rainbowvcclassic"
#define _PATH_SSH_CLIENT_ID_RSA3072_SPHINCS_HARAKA_128F_ROBUST _PATH_SSH_USER_DIR "/id_rsa3072_sphincsharaka128frobust"
#define _PATH_SSH_CLIENT_ID_P256_SPHINCS_HARAKA_128F_ROBUST _PATH_SSH_USER_DIR "/id_p256_sphincsharaka128frobust"
#define _PATH_SSH_CLIENT_ID_RSA3072_SPHINCS_SHA256_128F_ROBUST _PATH_SSH_USER_DIR "/id_rsa3072_sphincssha256128frobust"
#define _PATH_SSH_CLIENT_ID_P256_SPHINCS_SHA256_128F_ROBUST _PATH_SSH_USER_DIR "/id_p256_sphincssha256128frobust"
#define _PATH_SSH_CLIENT_ID_RSA3072_SPHINCS_SHAKE256_128F_ROBUST _PATH_SSH_USER_DIR "/id_rsa3072_sphincsshake256128frobust"
#define _PATH_SSH_CLIENT_ID_P256_SPHINCS_SHAKE256_128F_ROBUST _PATH_SSH_USER_DIR "/id_p256_sphincsshake256128frobust"
///// OQS_TEMPLATE_FRAGMENT_DEFINE_OQS_ID_FILES_END

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#define _PATH_SSH_USER_CONFFILE		_PATH_SSH_USER_DIR "/config"

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#define _PATH_SSH_USER_PERMITTED_KEYS	_PATH_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#define _PATH_SSH_USER_PERMITTED_KEYS2	_PATH_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#define _PATH_SSH_USER_RC		_PATH_SSH_USER_DIR "/rc"
#define _PATH_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#define _PATH_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#define _PATH_RHOSTS_EQUIV		"/etc/hosts.equiv"

/*
 * Default location of askpass
 */
#ifndef _PATH_SSH_ASKPASS_DEFAULT
#define _PATH_SSH_ASKPASS_DEFAULT	"/usr/X11R6/bin/ssh-askpass"
#endif

/* Location of ssh-keysign for hostbased authentication */
#ifndef _PATH_SSH_KEY_SIGN
#define _PATH_SSH_KEY_SIGN		"/usr/libexec/ssh-keysign"
#endif

/* Location of ssh-pkcs11-helper to support keys in tokens */
#ifndef _PATH_SSH_PKCS11_HELPER
#define _PATH_SSH_PKCS11_HELPER		"/usr/libexec/ssh-pkcs11-helper"
#endif

/* xauth for X11 forwarding */
#ifndef _PATH_XAUTH
#define _PATH_XAUTH			"/usr/X11R6/bin/xauth"
#endif

/* UNIX domain socket for X11 server; displaynum will replace %u */
#ifndef _PATH_UNIX_X
#define _PATH_UNIX_X "/tmp/.X11-unix/X%u"
#endif

/* for scp */
#ifndef _PATH_CP
#define _PATH_CP			"cp"
#endif

/* for sftp */
#ifndef _PATH_SFTP_SERVER
#define _PATH_SFTP_SERVER		"/usr/libexec/sftp-server"
#endif

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#ifndef _PATH_PRIVSEP_CHROOT_DIR
#define _PATH_PRIVSEP_CHROOT_DIR	"/var/empty"
#endif

/* for passwd change */
#ifndef _PATH_PASSWD_PROG
#define _PATH_PASSWD_PROG             "/usr/bin/passwd"
#endif

#ifndef _PATH_LS
#define _PATH_LS			"ls"
#endif

/* Askpass program define */
#ifndef ASKPASS_PROGRAM
#define ASKPASS_PROGRAM         "/usr/lib/ssh/ssh-askpass"
#endif /* ASKPASS_PROGRAM */
