#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>


int main(int argc, char **argv)
{
  // file pointer
    FILE *f_nacl, *f_msg, *fp;

    //if there are not exactly 4 parameter --> error 
    if (argc != 5) {
        //printf("need 4 parameter");
        return 1;
    }

    const EVP_MD *mode = EVP_get_digestbyname(argv[1]);

    int times = atoi(argv[2]); //use c function convert str to int
    //printf("times: %d\n", times);

    unsigned char *nacl;
    size_t size = 0;
    f_nacl = fopen(argv[3], "rb");
    if (!f_nacl) {
        /* Unable to open file for reading */
        //printf("can't open input");
        return 1;
    }
    fseek(f_nacl, 0, SEEK_END); /* Go to end of file */
    size = ftell(f_nacl); /* How many bytes did we pass ? */

    /* Set position of stream to the beginning */
    rewind(f_nacl);

    /* Allocate the nacl (no need to initialize it with calloc) */
    nacl = malloc((size) * sizeof(*nacl)); /* size + 1 byte for the \0 */

    /* Read the file into the nacl */
    fread(nacl, size, 1, f_nacl); /* Read 1 chunk of size bytes from fp into buffer */
    fclose(f_nacl);

    /* NULL-terminate the nacl */
    //nacl[size] = '\0';

    /* Print it ! */
    // for (int i=0; i<size; i++){
    //     printf("%02x", nacl[i]);
    // }
    // printf("\n");
    
    // printf("size: %ld\n",size);

    unsigned char *msg;
    size_t msize = 0;
    f_msg = fopen(argv[4], "rb");
    if (!f_msg) {
        /* Unable to open file for reading */
        //printf("can't open input");
        return 1;
    }
    fseek(f_msg, 0, SEEK_END); /* Go to end of file */
    msize = ftell(f_msg); /* How many bytes did we pass ? */
    //printf("size: %ld\n",msize);

    /* Set position of stream to the beginning */
    rewind(f_msg);

    /* Allocate the nacl (no need to initialize it with calloc) */
    msg = malloc((msize) * sizeof(*msg)); /* size + 1 byte for the \0 */

    /* Read the file into the nacl */
    fread(msg, msize, 1, f_msg); /* Read 1 chunk of size bytes from fp into buffer */

    /* NULL-terminate the nacl */
    //msg[msize] = '\0';

    /* Print it ! */
    // for (int i=0; i<msize; i++){
    //     printf("%02x", msg[i]);
    // }
    // printf("\n");
    // printf("msize: %ld\n",msize);
    fclose(f_msg);

    unsigned char *combine;
    combine = malloc(msize+size);
    for (int i=0; i<msize+size; i++){
        if (i<size)
            combine[i]=nacl[i];
        else 
            combine[i]=msg[i-size];
    }

    //combine[msize+size]  = '\0';
    // if(combine[msize+size-1] == '\0'){
    //     printf("yes\n");
    // }else{
    //     printf("NO\n");
    // }

    //  for (int i=0; i<msize+size; i++){
    //     printf("%02x", combine[i]);
    // }
    // printf("\n");


    unsigned char *in = combine;
    unsigned int in_len = msize+size;
    //printf("length: %d\n", in_len);
    unsigned char *out;
    out = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
    unsigned int *out_len;

    if(combine != NULL){
    	for (int i = 0; i< times; i++){
	        EVP_MD_CTX *mdctx;
	        //out = (unsigned char*)malloc(EVP_MAX_MD_SIZE);

	        if((mdctx = EVP_MD_CTX_new()) == NULL){
	            //printf("new ctx error\n");
	            return 1;
	        }

	        if(1 != EVP_DigestInit_ex(mdctx, mode, NULL)){
	            //printf("init error\n");
	            return 1;
	        }

	        // for(int i = 0; i< in_len; i++){
	        // 	printf("%02x", in[i]);
	        // }
	        //printf("\n");

	        if(1 != EVP_DigestUpdate(mdctx, in, in_len)){
	            //printf("update\n");
	            return 1;
	        }

	        if(1 != EVP_DigestFinal_ex(mdctx, out, out_len)){
	            //printf("final error \n");
	            return 1;
	        }

	        EVP_MD_CTX_free(mdctx);
	        //printf("relength: %d\n", *out_len);
	        //printf("out_len: %d\n",*out_len);
	        free(in);
	        in = (unsigned char*)malloc(*out_len);
	        //in = out;
	        in_len = *out_len;
	        
	        memcpy(in,out,*out_len);
	        //free(out);
	        //free(out_len);
    	}
    	for(int i = 0; i< *out_len; i++){
            printf("%02x",out[i]);
        }
        printf("\n");
    } else
        return 1;
    free(out);
    return 0;
}
