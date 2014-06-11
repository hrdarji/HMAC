#include <stdio.h> 
#include <string.h> 
#include <time.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
    


#define BLOCK_SIZE 16
#define FREAD_COUNT 4096
#define KEY_BIT 256
#define IV_SIZE 16
#define RW_SIZE 1
#define SUCC 0
#define FAIL -1

 
AES_KEY aes_ks3;
unsigned char iv[IV_SIZE];
unsigned char key[16];
unsigned char MD5_sender[16];
unsigned char MD5_receiver[16];
FILE *inFile;
FILE *md5sender;
FILE *md5receiver;
time_t rawtime;
struct tm * timeinfo;



 // To encrypt the plain text
int fs_encrypt_aes(char *in_file,char *out_file)
{
    
    int i=0;
    int len=0;
    int padding_len=0;
    char buf[FREAD_COUNT+BLOCK_SIZE];
	
	// To generate the random key using the Random function
    RAND_bytes(key,sizeof (key));
 
    FILE *fp=fopen(in_file,"rb");
    if( fp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,in_file);
        return FAIL;
    }
 
    FILE *wfp=fopen(out_file,"wb");
    if( wfp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,out_file);
        return FAIL;
    }
 
    memset(iv,0,sizeof(iv)); // init iv
	// SET the AES Key to 256 bit
    AES_set_encrypt_key(key ,KEY_BIT ,&aes_ks3);
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT, fp) ){
        if( FREAD_COUNT != len ){
            break;
        }
 
        AES_cbc_encrypt(buf ,buf ,len ,&aes_ks3 ,iv ,AES_ENCRYPT);
        fwrite(buf ,RW_SIZE ,len ,wfp);
    }
 
 
    //
    padding_len=BLOCK_SIZE - len % BLOCK_SIZE;
    //printf("enc padding len:%d\n",padding_len);
    memset(buf+len, padding_len, padding_len);
/**
    for(i=len; i < len+padding_len ;i++){
        buf[i]=padding_len;
    }
**/
    AES_cbc_encrypt(buf ,buf ,len+padding_len ,&aes_ks3, iv,AES_ENCRYPT);
    fwrite(buf ,RW_SIZE ,len+padding_len ,wfp);
 
    fclose(wfp);
    fclose(fp);
 
    return SUCC;
}
 // This function will take the encrypted Text and will decrypt it into the plain text
int fs_decrypt_aes(char *in_file,char *out_file)
{
    char buf[FREAD_COUNT+BLOCK_SIZE];
    int len=0;
    int total_size=0;
    int save_len=0;
    int w_len=0;
 
    FILE *fp=fopen(in_file,"rb");
    if( fp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,in_file);
        return FAIL;
    }
 
    FILE *wfp=fopen(out_file,"wb");
    if( wfp == NULL ){
        fprintf(stderr,"[ERROR] %d can not fopen('%s')\n",__LINE__,out_file);
        return FAIL;
    }
 
    memset(iv,0,sizeof(iv)); // the same iv
    AES_set_decrypt_key(key ,KEY_BIT ,&aes_ks3);
 
    fseek(fp ,0 ,SEEK_END);
    total_size=ftell(fp);
    fseek(fp ,0 ,SEEK_SET);
    //printf("total_size %d\n",total_size);
 
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT ,fp) ){
        if( FREAD_COUNT == 0 ){
            break;
        }
        save_len+=len;
        w_len=len;
 
        AES_cbc_encrypt(buf ,buf ,len ,&aes_ks3 ,iv ,AES_DECRYPT);
        if( save_len == total_size ){ // check last block
            w_len=len - buf[len-1];
            //printf("dec padding size %d\n" ,buf[len-1]);
        }
 
        fwrite(buf ,RW_SIZE ,w_len ,wfp);
	
    }
 
    fclose(wfp);
    fclose(fp);
 
    return SUCC;
}

int main(int argc, char *args[])
{
    
   clock_t start_t, end_t, total_t;
   int i;

   start_t = clock();
 //  printf("Starting of the program, start_t = %ld\n", start_t);



    if( argc != 2 ){
        printf("[Usage] %s fs_src_file\n",args[0]);
        return FAIL;
    }
    
    FILE *fp=fopen(args[1],"a+b");
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "\nsending local time and date: %s \n\n", asctime (timeinfo));
    fprintf(fp, "%s\n", asctime(timeinfo));
    fclose(fp);

 
    if( fs_encrypt_aes(args[1],"fs_in.file") == SUCC){
        fs_decrypt_aes("fs_in.file","fs_out.file");
       // printf("result:[fs_out.file]\n");
    }

    // MD5 generation sender side

    unsigned char c[MD5_DIGEST_LENGTH];
    inFile = fopen ("fs_in.file", "rb");
    int bytes;
    char mdString[33];
    fseek(inFile, 0, SEEK_END); 
    long fsize = ftell(inFile);
    long inputfilelength=0;
    unsigned char digest[16];
    fseek(inFile, 0, SEEK_SET); 
    while (fgetc(inFile) != EOF)
    {
        inputfilelength++;
        //printf("inputfilelength inside loop : %d\n",inputfilelength );
    }
   
    char *data = malloc(inputfilelength + 1);
    
    fseek(inFile, 0, SEEK_SET); 
    //printf("inputfilelength : %d\n",inputfilelength);
    fgets(data, inputfilelength, inFile);
    //printf("\bsender side data: %s\n",data);
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, inputfilelength);
    MD5_Final(digest, &ctx);
    md5sender = fopen ("md5sender.txt", "w");
    for(i = 0; i < 16; i++)
    {
        //printf("%.02x",digest[i]);
        MD5_sender[i]=digest[i];
        fprintf(md5sender, "%.02x", digest[i]);
    }
    fclose(md5sender);
    fclose (inFile);
    
    // MD5 receiver side
    inFile = fopen ("fs_in.file", "r");
    fseek(inFile, 0, SEEK_END); 
    fsize = ftell(inFile);
    inputfilelength=0;
    fseek(inFile, 0, SEEK_SET);
    while (fgetc(inFile) != EOF)
    {
        inputfilelength++;
    }
   
    //char *data = malloc(inputfilelength + 1);
    
    fseek(inFile, 0, SEEK_SET); 
    fgets(data, inputfilelength, inFile);
    //MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, inputfilelength);
    MD5_Final(digest, &ctx);
    md5receiver = fopen ("md5receiver.txt", "w");
    for(i = 0; i < 16; i++)
    {
        //printf("%.02x",digest[i]);
        MD5_receiver[i]=digest[i];
        fprintf(md5receiver, "%.02x", digest[i]);
    }
    fclose(md5receiver);
    fclose (inFile);

    end_t = clock();
   //printf ("%f cpu sec\n", ((double)end_t - (double)start_t)*1000000);
  //  printf("Exiting of the program...\n");
    int flag=0;

    for(i = 0; i < 16; i++)
    {
        
        if(MD5_sender[i]!=MD5_receiver[i])
        {
            flag=1;
        }
        
    }


    // fetch receiver side time from decrypted text :
    FILE *source;
    source = fopen("fs_out.file","r+");
    fseek(source, 0, SEEK_END);
    int filesize = ftell(source); 
    fseek(source, 0, SEEK_SET);

    long a = filesize -25;

    fseek(source,a-1,SEEK_SET); // Set the new position at 10. 
    int j=0;
    unsigned char buffer[25];
    printf("Sender Time Recieved: ");
    if (source != NULL) 
    { 
        for (i = a; i < filesize; i++) 
        { 
           char c = fgetc(source); // Get character 
            buffer[j] = c; 
	    printf("%c",buffer[j]);
            j++;
        }
    }

 // Getting Reciever side Time

  time_t rawtime1;
  struct tm * timeinfo1;
  time ( &rawtime1 );
  timeinfo1 = localtime ( &rawtime1 );
  printf ( "\nCurrent local time and date on reciever side: %s", asctime (timeinfo1) );

 
 long timeend= (int)*asctime(timeinfo1);
 long timestart= (int)*asctime(timeinfo);

if((timeend-timestart)<0)
  {
   printf("Time integrity Failed");
}
 else
  {
    printf("Time integrity Verified");
}

    if(flag==0)
    {
        printf("\n\nMessage integrity verified\n\n\n");
    }

    //int a = 
    //receiver side  time stamp
 
    return 0;
}
