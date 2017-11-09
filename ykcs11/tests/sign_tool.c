/*
 * Copyright (c) 2015-2016 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <ykcs11.h>
#include <ykcs11-version.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include <cJSON.h>

#define CONFIG_FILENAME "config.json"
#define MAX_BUF_SIZE 128
#define PIN_LENGTH 6

//key is store in slot 9c(ID 2)
#define OBJECT_ID 2
#define RSA_2048_SIG_SIZE 256



void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, int space) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(output, "%02x%s", buf[i], space == 1 ? " " : "");
  }
  fprintf(output, "\n");
}

static CK_FUNCTION_LIST_PTR funcs;

#define asrt(c, e, m) _asrt(__LINE__, c, e, m);
static void _asrt(int line, CK_ULONG check, CK_ULONG expected, CK_CHAR_PTR msg) {

  if (check == expected)
    return;

  fprintf(stderr, "<%s>:%d check failed with value %lu (0x%lx), expected %lu (0x%lx)\n",
          msg, line, check, check, expected, expected);

  exit(EXIT_FAILURE);

}

static void get_functions(CK_FUNCTION_LIST_PTR_PTR funcs) {

  if (C_GetFunctionList(funcs) != CKR_OK) {
    fprintf(stderr, "Get function list failed\n");
    exit(EXIT_FAILURE);
  }

}

static void test_lib_info() {

  const CK_CHAR_PTR MANUFACTURER_ID    = "Yubico (www.yubico.com)";
  const CK_CHAR_PTR YKCS11_DESCRIPTION = "PKCS#11 PIV Library (SP-800-73)";
  const CK_ULONG CRYPTOKI_VERSION_MAJ  = 2;
  const CK_ULONG CRYPTOKI_VERSION_MIN  = 40;


  CK_INFO info;

  asrt(funcs->C_GetInfo(&info), CKR_OK, "GET_INFO");

  asrt(strcmp(info.manufacturerID, MANUFACTURER_ID), 0, "MANUFACTURER");

  asrt(info.cryptokiVersion.major, CRYPTOKI_VERSION_MAJ, "CK_MAJ");
  asrt(info.cryptokiVersion.minor, CRYPTOKI_VERSION_MIN, "CK_MIN");

  asrt(info.libraryVersion.major, YKCS11_VERSION_MAJOR, "LIB_MAJ");
  asrt(info.libraryVersion.minor, ((YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH ), "LIB_MIN");

  asrt(strcmp(info.libraryDescription, YKCS11_DESCRIPTION), 0, "LIB_DESC");
}

static int find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret,
		const unsigned char *id, size_t id_len, int obj_index)
{
	CK_ATTRIBUTE attrs[2];
	unsigned int nattrs = 0;
	CK_ULONG count;
	CK_RV rv;
	int i;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;
	if (id) {
		attrs[nattrs].type = CKA_ID;
		attrs[nattrs].pValue = (void *) id;
		attrs[nattrs].ulValueLen = id_len;
		nattrs++;
	}

	rv = funcs->C_FindObjectsInit(sess, attrs, nattrs);
	if (rv != CKR_OK)
		printf("C_FindObjectsInit, %d", rv);

	for (i = 0; i < obj_index; i++) {
		rv = funcs->C_FindObjects(sess, ret, 1, &count);
		if (rv != CKR_OK)
			printf("C_FindObjects", rv);
		if (count == 0)
			goto done;
	}
	rv = funcs->C_FindObjects(sess, ret, 1, &count);
	if (rv != CKR_OK)
		printf("C_FindObjects, %d", rv);

done:	if (count == 0)
		*ret = CK_INVALID_HANDLE;
	funcs->C_FindObjectsFinal(sess);

	return count;
}


static int sign_data(CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key, unsigned char *inbuf, unsigned int inlen,
		unsigned char *outbuf, size_t *poutlen)
{
	CK_MECHANISM	mech;
	CK_RV		rv;

	if(!session || !key || !inbuf || !inlen || !outbuf || !poutlen || !*poutlen) {
		printf("Input parameters error!\n");
		return -1;
	}

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = CKM_RSA_PKCS_PSS;

	rv = CKR_CANCEL;

	rv = funcs->C_SignInit(session, &mech, key);
	if (rv != CKR_OK){
		printf("C_SignInit: %d", rv);
		return -1;
	}
	rv =  funcs->C_Sign(session, inbuf, inlen, outbuf, poutlen);
	if (rv != CKR_OK)   {
		printf("C_Sign failed\n");
		return -2;
	}
	return 0;
}

static int sign_code(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
	const char *input_string, const char *input_filename, const char *output_filename, char *base64_output)
{
	int result = -1;
	unsigned char input_buf[MAX_BUF_SIZE + 1];
	size_t input_len = 0;
	int cnt;
	FILE *f;
	
	SHA256_CTX sha256;
	unsigned char sha256_buf[SHA256_DIGEST_LENGTH];
	unsigned char outbuf[RSA_2048_SIG_SIZE];
	unsigned int outlen = sizeof(outlen);
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	
	if (!session || !base64_output) {
		printf("input not correct\n");
		goto done;
	}
    if (input_string) {
		if (strlen(input_string) > MAX_BUF_SIZE) {
			result = -1;
			goto done;
		}
		strcpy(input_buf, input_string);
		input_len = strlen(input_string);
    } else if (input_filename) {
		if(!(f = fopen(input_filename, "rb"))){
			printf("open input file error\n");
			return -1;
			goto done;
		}
		input_len = fread(input_buf, 1, sizeof(input_buf), f);
		fclose(f);
    }	
    SHA256_Init(&sha256);
	SHA256_Update(&sha256, input_buf, input_len);
	SHA256_Final(sha256_buf, &sha256);
	if((result = sign_data(session, object, sha256_buf, sizeof(sha256_buf), outbuf, &outlen))) {
		printf("RSA2048-PSS failed\n");
		goto done;
	}

	if (output_filename) {	
		if((f = fopen(output_filename, "wb")) < 0){
			printf("failed to open output file\n");
			return -1;
		}
		printf("Writing RSA signature\n");
		if((cnt = fwrite(outbuf, 1, sizeof(outbuf), f)) != sizeof(outbuf)) {
			printf("Failed to write output file\n");
			return -1;
		}
		fclose(f);
	}
	
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, outbuf, RSA_2048_SIG_SIZE);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);

	memcpy(base64_output, bufferPtr->data, bufferPtr->length);
	base64_output[bufferPtr->length] = '\0';
	
	BIO_set_close(bio, BIO_CLOSE);
	BIO_free_all(bio);
	result = 0;
done:
	return result;	
}


static void Usage(const char *appname)
{
	printf("Usage: %s [OPTIONS]\n", appname);
	printf("Options:\n");
	printf("\t -i \t\t Input file\n");
	printf("\t -s \t\t Input string from command line\n");
	printf("\t -o \t\t Output file\n");
	printf("\t -b \t\t Base64 encoded output to stdout\n");
}

int main(int argc, char *argv[]) {
  int result = -1;
  int opt;
  extern char *optarg;

  char *input_filename= NULL;
  char *input_string = NULL;
  char *output_filename = NULL;
  unsigned char is_base64_output = 0;
  char base64_output[RSA_2048_SIG_SIZE *2];

  FILE *f;
  char json_string[MAX_BUF_SIZE];

  char pin[PIN_LENGTH + 1];
  
  if (!(f = fopen(CONFIG_FILENAME, "r"))){
	  printf("open config file error\n");
	  result = -1;
	  goto done;
  }
  if (!fread(json_string, 1, sizeof(json_string), f)) {
  	printf("read config file error\n");
	result = -1;
	goto done;
  }

  cJSON * root = cJSON_Parse(json_string);
  cJSON * json_pin =  cJSON_GetObjectItemCaseSensitive(root, "pin");
  if (!cJSON_IsString(json_pin)) {
  	result = -1;
	printf("read config file fail\n");
	return;
  }

  if (strlen(json_pin->valuestring ) > PIN_LENGTH) {
  	printf("PIN length not correct\n");
	result = -1;
	goto done;
  }
  strcpy(pin, json_pin->valuestring);

  while((opt = getopt(argc, argv, "i:s:o:bh")) != -1) {
  	switch(opt) {
		case 'i':
			input_filename = optarg;
			break;
		case 's':
			input_string = optarg;
			break;
		case 'o':
			output_filename = optarg;
			break;
		case 'b':
			is_base64_output = 1;
			break;
		case 'h':
			Usage(argv[0]);
			result = 0;
			goto done;
		default:
			printf("unkown option %c\n", opt);
			Usage(argv[0]);
			result = -1;
			goto done;
  	}
  }

  if (input_filename && input_string) {
  	printf("cant have -i and -s together\n");
	result = -1;
	goto done;
  }
  
  get_functions(&funcs);
  test_lib_info();

  CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
  CK_BYTE object_id[1] = {OBJECT_ID};
  size_t object_id_len = 1;

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_USER, pin, 6), CKR_OK, "Login USER");
  if (!find_object(session, CKO_PRIVATE_KEY, &object,
			  object_id,
			  object_id_len, 0)) {
	  printf("Private key %d not found\n", object_id[0]);
	  result = -1;
	  goto done;
  }

  result = sign_code(session, object, input_string, input_filename, output_filename, base64_output);
  if (!result && is_base64_output)
  		printf("%s\n",base64_output);
  
  if(session != CK_INVALID_HANDLE) {
	  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");  
	  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  }
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

done:
	return result;
}
