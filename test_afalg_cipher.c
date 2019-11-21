#include <errno.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/cryptouser.h>
#include <linux/if_alg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test_vectors.h"

struct afalg_ctx_st {
  int sfd, bfd, enc;
  size_t tlen;
};
typedef struct afalg_ctx_st afalg_ctx;

static void PrintHex(FILE *stream, const char *text, size_t text_len)
{
  for(int i=0; i < text_len; i++)
    fprintf(stream, " %02hhx", *(text++));
}

static int CipherInit(afalg_ctx *ctx, const char *alg_name, const char *key,
		      size_t keylen, const char *iv, size_t ivlen, size_t tlen,
		      unsigned int aadlen, int enc)
{
  struct sockaddr_alg sa = { 0 };
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  struct af_alg_iv *aiv;
  struct iovec iov;
  int op = enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
  size_t set_op_len = sizeof op;
  size_t set_iv_len = offsetof(struct af_alg_iv, iv) + ivlen;
  char buf[CMSG_SPACE(set_op_len) + CMSG_SPACE(set_iv_len)
	   + CMSG_SPACE(sizeof aadlen)];

  sa.salg_family = AF_ALG;
  strcpy(sa.salg_type, tlen == 0 ? "skcipher" : "aead");
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
    goto err;
  }
  if (tlen > 0 && setsockopt(ctx->bfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL,
			     tlen) < 0) {
    perror("Failed to set authentication tag length");
    goto err;
  }
  if ((ctx->sfd = accept(ctx->bfd, NULL, 0)) < 0) {
    perror("Socket accept failed");
    goto err;
  }
  ctx->tlen = tlen;
  ctx->enc = enc;
  memset(&buf, 0, sizeof buf);
  msg.msg_control = buf;
  /* set op */
  msg.msg_controllen = CMSG_SPACE(set_op_len)
		       + (ivlen > 0 ? CMSG_SPACE(set_iv_len) : 0)
		       + (aadlen > 0 ? CMSG_SPACE(sizeof aadlen) : 0);
  cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL)
    goto err;
  cmsg->cmsg_level = SOL_ALG;
  cmsg->cmsg_type = ALG_SET_OP;
  cmsg->cmsg_len = CMSG_LEN(set_op_len);
  *(CMSG_DATA(cmsg)) = op;
  /* set IV */
  if (ivlen > 0) {
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL)
      goto err;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(set_iv_len);
    aiv = (void *)CMSG_DATA(cmsg);
    aiv->ivlen = ivlen;
    memcpy(aiv->iv, iv, ivlen);
  }
  if (aadlen > 0) {
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL)
      goto err;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof aadlen);
    *(CMSG_DATA(cmsg)) = aadlen;
  }
  iov.iov_base = NULL;
  iov.iov_len = 0;
  if (sendmsg(ctx->sfd, &msg, MSG_MORE) < 0) {
    fprintf(stderr, "%s: Failed to set op=%d, ivlen=%zd, iv=",
	    __func__, op, ivlen);
    PrintHex(stderr, iv, ivlen);
    perror(": sendmsg: ");
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
			const char* in, size_t inl, const char *aad,
			size_t aadlen, char *tag, int more)
{
  struct msghdr msg = { 0 };
  struct cmsghdr *cmsg;
  struct iovec iov[3];
  ssize_t nbytes, expected;
  int ret = 1;
  unsigned int i = 0;
  void *out_aad = NULL;

  if (aadlen > 0 && (out_aad = malloc(aadlen)) == NULL) {
    ret = 0;
    goto end;
  }
  msg.msg_iov = iov;
  expected = 0;
  if (aadlen > 0) {
    iov[i].iov_base = (void *)aad;
    iov[i++].iov_len = aadlen;
    expected += aadlen;
  }
  if (inl > 0) {
    iov[i].iov_base = (void *)in;
    iov[i++].iov_len = inl;
    expected += inl;
  }
  if (ctx->tlen > 0 && !ctx->enc && !more) {
    iov[i].iov_base = (void *)tag;
    iov[i++].iov_len = ctx->tlen;
    expected += ctx->tlen;
  }
  msg.msg_iovlen = i;
  if ((nbytes = sendmsg(ctx->sfd, &msg, more ? MSG_MORE : 0)) 
      != expected) {
    ret = 0;
    if (nbytes < 0) {
      perror(__func__);
      goto end;
    }
    fprintf(stderr, "%s: sendmsg: sent %zd bytes != %zd\n", __func__, nbytes, expected);
  }
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  i = 0;
  expected = 0;
  if (aadlen > 0) {
    iov[i].iov_base = out_aad;
    iov[i++].iov_len = aadlen;
    expected += aadlen;
  }
  if (inl > 0) {
    iov[i].iov_base = (void *)out;
    iov[i++].iov_len = inl;
    expected += inl;
  }
  if (ctx->tlen > 0 && ctx->enc && !more) {
    iov[i].iov_base = tag;
    iov[i++].iov_len = ctx->tlen;
    expected += ctx->tlen;
  }
  msg.msg_iovlen = i;
  nbytes = 0;
  if (expected == 0) {
    // authentication only
    iov[0].iov_base = &i;
    iov[0].iov_len = 1;
    msg.msg_iovlen = 1;
  }
  if ((nbytes = recvmsg(ctx->sfd, &msg, 0)) != expected) {
    ret = 0;
    if (nbytes < 0) {
      if (errno == EBADMSG && !ctx->enc) {
	printf("Tag   : Authentication Failed.\n");
      } else {
        fprintf(stderr, "%s: ", __func__);
        perror("recvmsg");
      }
      goto end;
    }
    fprintf(stderr, "recvmsg: received %zd bytes != %zd\n", nbytes, expected);
  }
  if (nbytes > aadlen)
    nbytes -= aadlen;
  else if (nbytes > 0)
    nbytes = 0;
  if (outl != NULL)
    *outl = (size_t) nbytes;

end:
  free(out_aad);
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
		    size_t len, int enc, const char *expected, const char *aad,
		    size_t aadlen, const char *tag, size_t tlen,
		    size_t roundlen)
{
  afalg_ctx ctx;
  char text_out[1024], tag_out[64];
  size_t i = 0, outl = 0, out_tlen;
  int ret = 0;
  int more;

  if (!CipherInit(&ctx, cipher, key, keylen, iv, ivlen, tlen, aadlen, enc)) {
    fprintf(stderr, "Error in CipherInit.  TEST FAILED!\n");
    return -1;
  }

  do {
    more = (i + roundlen < len);
    if (!more)
       roundlen = len - i;
    printf("InText:");
    PrintHex(stdout, text + i, roundlen);
    if (more)
      printf(" ...");
    printf("\n");
    if (!enc && tlen > 0) {
      printf("Tag   :");
      PrintHex(stdout, tag, tlen);
      printf("\n");
    }
    if(!CipherUpdate(&ctx, text_out, &outl, text + i, roundlen,
		     aad, aadlen, enc ? tag_out : (char *) tag,
		     more)) {
      ret = 1;
      if (outl < 0) {
	fprintf(stderr, "Error in CipherUpdate: %s\n", strerror(-outl));
	outl = 0;
      }
    }
    if (tlen > 0 && enc) {
      if (outl > tlen) {
	outl -= tlen;
	out_tlen = tlen;
      } else {
	out_tlen = outl;
	outl = 0;
      }
    }
    printf("Output:");
    PrintHex(stdout, text_out, outl);
    if (memcmp(text_out, expected + i, roundlen)) {
      printf(": FAILED!\n");
      printf("Expect:");
      PrintHex(stdout, expected + i, roundlen);
      printf(": FAILED!\n");
      ret = 1;
    }
    if (enc && tlen > 0) {
      printf("\nTag   :");
      PrintHex(stdout, tag_out, out_tlen);
      if (tlen > 0 && enc && (out_tlen != tlen || memcmp(tag_out, tag, tlen))) {
        printf(": FAILED!\n");
        printf("Expect:");
        PrintHex(stdout, tag, tlen);
        printf(": FAILED!\n");
        ret = 1;
      }
    }
    if (ret == 0)
      printf(": PASS\n");
    i += roundlen;
  } while (i < len);
  if (!CipherFinal(&ctx)) {
    fprintf(stderr, "Error in CipherFinal_ex\n");
    return -1;
  }
  return ret;
}

int main(int argc, char **argv)
{
  int vres;
  unsigned int vfails = 0, vpasses = 0, tfails = 0, tpasses = 0;

  setbuf(stdout, NULL);
  for (int t = 0; vectors[t].alg; t++) {
    if (argc > 1 && strncmp(argv[1], vectors[t].alg, CRYPTO_MAX_NAME))
      continue;
    printf("%s:\n"
	   "Key   :", vectors[t].desc);
    PrintHex(stdout, vectors[t].key, vectors[t].klen);
    printf("\nIV    :");
    PrintHex(stdout, vectors[t].iv, vectors[t].ivlen);
    if (vectors[t].aadlen > 0) {
      printf("\nAAD   :");
      PrintHex(stdout, vectors[t].aad, vectors[t].aadlen);
    }
    printf("\n\n");
    vres = 0;
    for (int n = ((vectors[t].len + vectors[t].blocklen - 1) /
		  vectors[t].blocklen) * vectors[t].blocklen;
	 n + vectors[t].tlen > 0;
	 n -= vectors[t].blocklen) {
      if (n < vectors[t].len) {
        /* rfc3863-mode ciphers are not updating IV on their own,
	 * so they can't do the operation using partial updates */
#ifndef AFALG_RFC3686_UPDATE_TEST
        if (!strncmp(vectors[t].alg, "rfc3686(", 8))
	  break;
#endif
	if (vectors[t].tlen > 0)
	  break;
	printf("Running using %d-bytes updates\n", n);
      } else {
	printf("Running in one-shot\n");
      }
      printf("Encryption:\n");
      if (run_test(vectors[t].alg, vectors[t].key, vectors[t].klen,
		   vectors[t].iv, vectors[t].ivlen, vectors[t].ptext,
		   vectors[t].len, 1, vectors[t].ctext,
		   vectors[t].aad, vectors[t].aadlen,
		   vectors[t].tag, vectors[t].tlen, n) != 0) {
	tfails++;
	vres = 1;
      } else {
        tpasses++;
      }
      printf("Decryption:\n");
      if (run_test(vectors[t].alg, vectors[t].key, vectors[t].klen,
		   vectors[t].iv, vectors[t].ivlen, vectors[t].ctext,
		   vectors[t].len, 0, vectors[t].ptext,
		   vectors[t].aad, vectors[t].aadlen,
		   vectors[t].tag, vectors[t].tlen, n) != 0) {
	tfails++;
	vres = 1;
      } else {
	tpasses++;
      }
      printf("\n");
    }
    if (vres)
      vfails++;
    else
      vpasses++;
  }
  printf("%3d Tests Vectors Performed: PASS: %3d; FAIL: %3d\n"
	 "%3d Total Test Runs        : PASS: %3d; FAIL: %3d\n",
	 vpasses + vfails, vpasses, vfails, tpasses + tfails, tpasses, tfails);
  if (vfails > 0) {
    printf("There were failed tests.  Check output!\n");
  } else if (vpasses > 0) {
    printf("Success! All tests passed!\n");
  } else {
    printf("No tests performed!\n");
    return -1;
  }
  return vfails;
}

