#include <stdint.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test_vectors.h"

struct afalg_ctx_st {
  struct sockaddr_alg sa;
  int sfd, bfd;
};
typedef struct afalg_ctx_st afalg_ctx;

static void PrintHex(FILE *stream, const char *text, size_t text_len)
{
  for(int i=0; i < text_len; i++)
    fprintf(stream, " %02hhx", *(text++));
}

static int CipherInit(afalg_ctx *ctx, const char *alg_name, const char *key,
		      size_t keylen, const char *iv, size_t ivlen, int enc)
{
  struct sockaddr_alg sa;
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  struct af_alg_iv *aiv;
  struct iovec iov;
  int op = enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
  size_t set_op_len = sizeof op;
  size_t set_iv_len = offsetof(struct af_alg_iv, iv) + ivlen;
  char buf[CMSG_SPACE(set_op_len) + CMSG_SPACE(set_iv_len)];

  memset(&sa, 0, sizeof ctx->sa);
  sa.salg_family = AF_ALG;
  strcpy(sa.salg_type, "skcipher");
  strncpy(sa.salg_name, alg_name, sizeof sa.salg_name);
  if (( ctx->bfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) < 0) {
    perror("Failed to open socket");
    goto err;
  }

  if (bind(ctx->bfd, (struct sockaddr *)&sa, sizeof sa) < 0) {
    perror("Failed to bind socket");
    goto err;
  }
  if (setsockopt(ctx->bfd, SOL_ALG, ALG_SET_KEY, key, keylen) < 0) {
    perror("Failed to set key");
  }
  if ((ctx->sfd = accept(ctx->bfd, NULL, 0)) < 0) {
    perror("Socket accept failed");
    goto err;
  }
  memset(&buf, 0, sizeof buf);
  msg.msg_control = buf;
  /* set op */
  msg.msg_controllen = CMSG_SPACE(set_op_len);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_ALG;
  cmsg->cmsg_type = ALG_SET_OP;
  cmsg->cmsg_len = CMSG_LEN(set_op_len);
  memcpy(CMSG_DATA(cmsg), &op, sizeof op);
  /* set IV */
  msg.msg_controllen += CMSG_SPACE(set_iv_len);
  cmsg = CMSG_NXTHDR(&msg, cmsg);
  cmsg->cmsg_level = SOL_ALG;
  cmsg->cmsg_type = ALG_SET_IV;
  cmsg->cmsg_len = CMSG_LEN(set_iv_len);
  aiv = (void *)CMSG_DATA(cmsg);
  aiv->ivlen = ivlen;
  memcpy(aiv->iv, iv, ivlen);

  iov.iov_base = NULL;
  iov.iov_len = 0;
  if (sendmsg(ctx->sfd, &msg, 0) < 0) {
    fprintf(stderr, "sendmsg: Failed to set op=%d, ivlen=%zd, iv=", op, ivlen);
    PrintHex(stderr, iv, ivlen);
    perror(": ");
    goto err;
  }
  return 1;
err:
  if (ctx->bfd >= 0)
    close(ctx->bfd);
  if (ctx->sfd >= 0)
    close(ctx->sfd);
  ctx->bfd = ctx->sfd = -1;
  return 0;
}

static int CipherUpdate(afalg_ctx *ctx, char *out, size_t *outl,
			const char* in, size_t inl)
{
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  struct iovec iov;
  ssize_t nbytes;
  int ret = 1;

  iov.iov_base = (void *)in;
  iov.iov_len = inl;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if ((nbytes = send(ctx->sfd, in, inl, MSG_MORE)) != (ssize_t) inl) {
    fprintf(stderr, "CipherUpdate: sent %zd bytes != inl %zd\n", nbytes, inl);
    if (nbytes <= 0)
      return 0;
    ret = 0;
  }
  if ((nbytes = read(ctx->sfd, out, (size_t) nbytes)) != (ssize_t) inl) {
    fprintf(stderr, "CipherUpdate: read %zd bytes != inl %zd\n", nbytes, inl);
    if (nbytes < 0)
      return 0;
    ret = 0;
  }
  if (outl != NULL)
    *outl = (size_t) nbytes;
  return ret;
}

static int CipherFinal(afalg_ctx *ctx)
{
   close(ctx->sfd);
   close(ctx->bfd);
   ctx->bfd = ctx->sfd = -1;
   return 1;
}

static int run_test(const char *cipher, const char *key, size_t keylen,
		    const char* iv, size_t ivlen, const char *text,
		    size_t len, int enc, const char *expected, size_t roundlen)
{
  afalg_ctx ctx;
  char text_out[1024];
  size_t outl;
  int ret = 0;

  if (!CipherInit(&ctx, cipher, key, keylen, iv, ivlen, enc)) {
    fprintf(stderr, "Error in CipherInit\n");
    return -1;
  }

  for (size_t i = 0; i < len; i += roundlen) {
    if (i + roundlen > len)
       roundlen = len - i;
    printf("InText:");
    PrintHex(stdout, text + i, roundlen);
    printf("\n");
    if(!CipherUpdate(&ctx, text_out, &outl, text + i, roundlen)) {
      fprintf(stderr, "Error in CipherUpdate\n");
      if (outl < 1)
	return -1;
    }
    printf("Output:");
    PrintHex(stdout, text_out, outl);
    if (memcmp(text_out, expected + i, roundlen)) {
      printf(": FAILED!\n");
      printf("Expect:");
      PrintHex(stdout, expected + i, roundlen);
      printf(": FAILED!\n");
      ret = 1;
    } else {
      printf(": PASS\n");
    }
  }
  if (!CipherFinal(&ctx)) {
    fprintf(stderr, "Error in CipherFinal_ex\n");
    return -1;
  }
  return ret;
}

int main(int argc, char **argv)
{
  int ret = 0;

#ifdef FAIL_TEST
  vectors[FAIL_TEST].ciphertext[vectors[FAIL_TEST].textlen - 2]++;
#endif
  for (int t = 0; vectors[t].alg; t++) {
    printf("%s:\n"
	   "Key   :", vectors[t].desc);
    PrintHex(stdout, vectors[t].key, vectors[t].klen);
    printf("\nIV    :");
    PrintHex(stdout, vectors[t].iv, vectors[t].ivlen);
    printf("\n\n");
    for (int n = ((vectors[t].len + vectors[t].blocklen - 1) /
		  vectors[t].blocklen) * vectors[t].blocklen;
	 n > 0;
	 n -= vectors[t].blocklen) {
      if (n < vectors[t].len) {
        /* rfc3863-mode ciphers are not updating IV on their own,
	 * so they can't do the operation using partial updates */
#ifndef AFALG_RFC3686_UPDATE_TEST
        if (!strncmp(vectors[t].alg, "rfc3686(", 8))
	  break;
#endif
	printf("Running using %d-byte updates\n", n);
      } else {
	printf("Running in one-shot\n");
      }
      printf("Encryption:\n");
      ret |= run_test(vectors[t].alg, vectors[t].key, vectors[t].klen,
		      vectors[t].iv, vectors[t].ivlen, vectors[t].ptext,
		      vectors[t].len, 1, vectors[t].ctext, n);
      printf("Decryption:\n");
      ret |= run_test(vectors[t].alg, vectors[t].key, vectors[t].klen,
		      vectors[t].iv, vectors[t].ivlen, vectors[t].ctext,
		      vectors[t].len, 0, vectors[t].ptext, n);
      printf("\n");
    }
  }
  if (ret)
    printf("There were failed tests.  Check output!\n");
  else
    printf("Success! All tests passed!\n");
  return ret;
}

