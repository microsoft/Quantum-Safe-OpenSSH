#ifndef SSH_OQS_H
#define SSH_OQS_H

#include "sshkey.h"

const char* get_oqs_alg_name(int);
int sshkey_oqs_generate_private_key(struct sshkey *, int);
int ssh_oqs_sign(const struct sshkey *, u_char **, size_t *, const u_char *, size_t, u_int);
int ssh_oqs_verify(const struct sshkey *, const u_char *, size_t, const u_char *, size_t, u_int);

#endif /* SSH_OQS_H */
