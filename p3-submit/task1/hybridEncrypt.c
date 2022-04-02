#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <unistd.h>

int encrypt(unsigned char *key, unsigned char *ciphertext, unsigned char* plaintext, 
 int plaintext_len, unsigned char *iv, unsigned char *tag){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

    /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())){
    return -2;
  }

    /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){ 
    return -2;
  }


    /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){ 
    return -2;
  }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
    return -2;
  }
  ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
    return -2;
  }
  ciphertext_len += len;

    /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
    return -2;
  }

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *key, unsigned char* plaintext, unsigned char *ciphertext,
 int ciphertext_len, unsigned char *iv, unsigned char *tag){

  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;


      /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return -2;


      /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    return -2;


      /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    return -2;

      /*
       * Provide the message to be decrypted, and obtain the plaintext output.
       * EVP_DecryptUpdate can be called multiple times if necessary
       */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
      return -2;
  plaintext_len = len;

      /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    return -2;

      /*
       * Finalise the decryption. A positive return value indicates success,
       * anything else is a failure - the plaintext is not trustworthy.
       */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

      /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0) {
          /* Success */
    plaintext_len += len;
    return plaintext_len;

  } else {
          /* Verify failed */
    return -1;
  }
}

int main(int argc, char **argv)
{
  // file pointer
  FILE *f_input, *f_enc, *f_dec, *fp;

  //if there are not exactly 3 parameter --> error 
  if (argc != 4) {
    return 2;
  } 


  // encrypt mode 
  if (strncmp(argv[1],"e",1) == 0){ 


	  //generate random key and random iv for secure
	  unsigned char key[16];
	  unsigned char iv[12];
	  if (!RAND_bytes (key,sizeof(key)-1) || !RAND_bytes (iv,sizeof(iv)-1)){
	    return 2;
	  }


	  // read file plaintext and change it into char array 
	  unsigned char *buffer = NULL;
	  size_t size = 0;
	  f_input = fopen(argv[3], "rb");
	  if (!f_input) {
	    /* Unable to open file for reading */
	    //printf("can't open input");
	    return 2;
	  }
	  fseek(f_input, 0, SEEK_END); /* Go to end of file */
	  size = ftell(f_input); /* How many bytes did we pass ? */

	    /* Set position of stream to the beginning */
	  rewind(f_input);

	    /* Allocate the buffer (no need to initialize it with calloc) */
	  buffer = malloc((size + 1) * sizeof(*buffer)); /* size + 1 byte for the \0 */

	    /* Read the file into the buffer */
	  fread(buffer, size, 1, f_input); /* Read 1 chunk of size bytes from fp into buffer */

	    /* NULL-terminate the buffer */
	  buffer[size] = '\0';

	  fclose(f_input);

	    /* Print it ! */
	  //printf("plaintext length: %ld, and text:%s\n", strlen(buffer), buffer);



	  //encrypt the file 
	  unsigned char *ciphertext;
	  ciphertext = malloc(strlen(buffer));

	  //set tag --> 16 bytes in gcm modes. 
	  unsigned char tag[16]; 

	  int ciphertext_len = encrypt(key, ciphertext, buffer, strlen(buffer), iv, tag); 

	  // we going return -2 if any encrypt step in the encrypt function is wrong --> return 2 in that case
	  if (ciphertext_len < 0){
	  	return 2;
	  }
	  

	  //encrypt the msg
	  unsigned char *p;
	  p = malloc(ciphertext_len);
	  int a = decrypt(key, p, ciphertext, ciphertext_len,iv, tag);
	    /* Create and initialise the context */

	    // encrypt the key

	  EVP_PKEY *prsa;
	  fp = fopen(argv[2],"rb");
	  if (!fp) {
	        /* Unable to open file for reading */
	    //printf("can't open pem input");
	    return 2;
	  }
	  prsa = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	  if (prsa == NULL){
	    //printf("read public file error");
	    return 2;
	  }
	  fclose(fp);

	  RSA *rsa = EVP_PKEY_get1_RSA(prsa);
	  if (rsa == NULL){
	    //printf("change wrong");
	    return 2;
	  }

	  int cipher_len;
	  unsigned char *pkey = malloc(256);
	  if((cipher_len = RSA_public_encrypt(16, key, pkey, rsa, RSA_PKCS1_OAEP_PADDING)) == -1){
	    //printf("rsa encrypt wrong");
	    return 2;
	  }
	  //printf("encrypt length:%d\n", cipher_len);
	  // for(int i = 0; i < cipher_len; i++)
	  //   printf("%x", pkey[i]);
	  // printf("\n");


	  // for(int i = 0; i < 16; i++)
	  //   printf("%x", key[i]);
	  // printf("\n");
	  // for(int i = 0; i < sizeof(iv); i++)
	  //   printf("%x", iv[i]);
	  // printf("\n");
	  // for(int i = 0; i < sizeof(tag); i++)
	  //   printf("%x", tag[i]);
	  // printf("\n");
	  // for(int i = 0; i < ciphertext_len; i++)
	  //   printf("%x", ciphertext[i]);
	  // printf("\n");


	  /* Because the project given tht we are going to use the 2048 RSA key pair to encrypt, so the ckey 
	  length will always be 2048/8 = 256 bytes --> first 256 bytes will be my ckey, and because iv will 
	  always = the block size in the gcm mode which is 12, so we know the next 12 bytes is the iv. And 
	  because we set the tag to by 16 bytes --> we going to have next 16 bytes for our tag, and rest are 
	  cmsg*/
	  unsigned char final[256+12+16+ciphertext_len]; 

	  for(int i=0; i<(256+12+16+ciphertext_len); i++){
	    if (i< 256)
	      final[i] = pkey[i];
	    else if (i<256+12)
	      final[i] = iv[i-256];
	    else if (i<256+12+16)
	      final[i] = tag[i-256-12];
	    else
	      final[i] = ciphertext[i-256-12-16];

	  }
	  final[256+12+16+ciphertext_len] = '\0';
	  

	  // write the result into ciphertext.
	  if ((f_enc = fopen("ciphertext.bin", "wb")) == NULL) {
	    //printf("can't open write file");
	    return 2;
	  }

	  fwrite(final, 1, 256+12+16+ciphertext_len, f_enc);

	  fclose(f_enc);

	  fflush(stdout);
	  fwrite(final, 1, 256+12+16+ciphertext_len, stdout);
	  
	  return 0;

// decrypt the file 
  }else if (strncmp(argv[1],"d",1) == 0){


    // read Private key 
    EVP_PKEY *prsa;

    fp = fopen(argv[2],"rb");
    if (!fp) {
        /* Unable to open file for reading */
      //printf("can't open pem input");
      return 2;
    }

    prsa = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (prsa == NULL){
      //printf("read private file error");
      return 2;
    }

    //change it to RSA key format
    RSA *rsa = EVP_PKEY_get1_RSA(prsa);
    if (rsa == NULL){
      //printf("change wrong");
      return 2;
    }

    

    // Read the ciphertext File 
    unsigned char *buffer = NULL;
    size_t size = 0;
    f_input = fopen(argv[3], "rb");
    if (!f_input) {
        /* Unable to open file for reading */
        //printf("can't open input");
        return 2;
    }
    fseek(f_input, 0, SEEK_END); /* Go to end of file */
    size = ftell(f_input); /* How many bytes did we pass ? */

    /* Set position of stream to the beginning */
    rewind(f_input);

    /* Allocate the buffer (no need to initialize it with calloc) */
    buffer = malloc((size + 1) * sizeof(*buffer)); /* size + 1 byte for the \0 */

    /* Read the file into the buffer */
    fread(buffer, size, 1, f_input); /* Read 1 chunk of size bytes from fp into buffer */

    /* NULL-terminate the buffer */
    buffer[size] = '\0';

    /* Print it ! */
    //printf("%ld\n", size);
    // for(int i = 0; i < size; i++)
    //   printf("%x", buffer[i]);
    // printf("\n");


    //because we know that we are using RSA 2048 key pair --> the ckey will always be 256 bytes (2048/8)
    // same, because we know in gcm mode the iv will be 12 bytes and the tag will be 16 bytes --> set it 
    unsigned char ckey[256], iv[12], tag[16];
    unsigned char *ciphertext;
    ciphertext = malloc(size-256-12-16);


     /* Because the project given tht we are going to use the 2048 RSA key pair to encrypt, so the ckey 
	  length will always be 2048/8 = 256 bytes --> first 256 bytes will be my ckey, and because iv will 
	  always = the block size in the gcm mode which is 12, so we know the next 12 bytes is the iv. And 
	  because we set the tag to by 16 bytes --> we going to have next 16 bytes for our tag, and rest are 
	  cmsg*/

    for(int i=0; i<size; i++){
      if (i< 256)
        ckey[i] = buffer[i];
      else if (i<256+12)
        iv[i-256]= buffer[i];
      else if (i<256+12+16)
        tag[i-256-12]= buffer[i];
      else
        ciphertext[i-256-12-16] = buffer[i];

    }

    // for(int i = 0; i < size; i++)
    //   printf("%x", buffer[i]);
    // printf("\n");

    // decrypt the ckey
    int key_len;
    unsigned char *key = malloc(256);
    if((key_len = RSA_private_decrypt(256, ckey, key, rsa, RSA_PKCS1_OAEP_PADDING)) == -1){
      //printf("rsa encrypt wrong");
      return 2;
    }
    //printf("encrypt length:%d\n", key_len);
    // for(int i = 0; i < key_len; i++)
    //   //printf("%x", key[i]);
    // printf("\n");

    
    //decrypt the msg
    unsigned char *p;
    p = malloc(size-256-12-16);
    int a = decrypt(key, p, ciphertext, size-256-12-16,iv, tag);

    //deal with error 
    if (a<0){

    	//if verify failed --> return 1;
    	if (a == -1)
    		return 1;

    	//otherwise it is other error --> return 2;
    	else 
    		return 2;
    }


    if ((f_dec = fopen("plaintext.txt", "w")) == NULL) {
      //printf("can't open write file");
      return 2;
    }

    fwrite(p, 1, a, f_dec);

    fclose(f_dec);

    fflush(stdout);
	fwrite(p, 1, a, stdout);


  
    return 0;
  // neither e or d mode --> error 
  } else {

  	// if it is neither encrypt mode nor decrypt mode, return 2
    //printf("Not correct");
    return 2;
  }
}

