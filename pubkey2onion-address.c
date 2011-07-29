/*
 * An implementation of convertion from OpenSSL to OpenSSH public key format
 *
 * Copyright (c) 2008 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * 
 */

#include <memory.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdint.h>

static const char BASE32_CHARS[] = "abcdefghijklmnopqrstuvwxyz234567";

static void
base32_encode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  unsigned int i, bit, v, u;
  size_t nbits = srclen * 8;

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((uint8_t)src[bit/8]) << 8;
    if (bit+5<nbits) v += (uint8_t)src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
}

int main(int argc, char**  argv)
{
   EVP_PKEY* const pPubKey = PEM_read_PUBKEY(stdin, NULL, NULL, NULL);
   if (!pPubKey)
       return -1;

   if (EVP_PKEY_type(pPubKey->type) != EVP_PKEY_RSA)
       return -1;

   RSA* const pRsa = EVP_PKEY_get1_RSA(pPubKey);
   if (!pRsa)
       return -1;

   const int len = i2d_RSAPublicKey(pRsa, NULL);
   if (len < 0)
       return -1;
   unsigned char *buf, *bufp;
   buf = bufp = malloc(len+1);
   if (len != i2d_RSAPublicKey(pRsa, &bufp))
       return -1;
   unsigned char digest[20];
   if (SHA1((const unsigned char*)buf, len, digest) < 0)
       return -1;
   char onion[23];
   base32_encode(onion, 17, digest, 10);
   strcpy(onion + 16, ".onion");
   puts(onion);

   return 0;
}
