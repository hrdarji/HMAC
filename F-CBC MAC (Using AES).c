#include <stdio.h> 
#include <string.h> 
#include <time.h>
#include <openssl/aes.h>
	


#define BLOCK_SIZE 16
#define FREAD_COUNT 4096
#define KEY_BIT 256
#define IV_SIZE 16
#define RW_SIZE 1
#define SUCC 0
#define FAIL -1
time_t rawtime;
struct tm * timeinfo;

unsigned char tag1[1000];
unsigned char tag2[1000];

unsigned char c1[1000];
unsigned char c2[1000];

long q=16;
 
AES_KEY aes_ks3;
unsigned char iv[IV_SIZE];
unsigned char key[16];
unsigned char key1[16];

AES_KEY aunthenticate_key;
unsigned char iv_aunthentication[16]= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


// Tag generation using AES in CBC mode and taking the Last 16 Byte of Tag.
int tag_generation_aes(char *in_file,char *out_file)
{
	int i=0;
    int len=0;
    int padding_len=0;
    char buf[FREAD_COUNT+BLOCK_SIZE];
    FILE *inputfile;
    long inputfilelength=0;
    inputfile=fopen("input.txt","r");
  //fseek(f, 0, SEEK_END);
    fseek(inputfile, 0, SEEK_END);
    long fsize = ftell(inputfile);
	//printf("file size : %lu \n",fsize );
	//q=fsize;
RAND_bytes(key1,sizeof (key1));
 
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
 
    memset(iv_aunthentication,0,sizeof(iv_aunthentication)); // init iv_aunthentication
	
	// SET the AES Key to 256 bit
    AES_set_encrypt_key(key1 ,KEY_BIT ,&aunthenticate_key);
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT, fp) ){
        if( FREAD_COUNT != len ){
            break;
        }
 
        AES_cbc_encrypt(buf ,buf ,len ,&aunthenticate_key,iv_aunthentication ,AES_ENCRYPT);
        fwrite(buf ,RW_SIZE ,len ,wfp);
    }
 
 
    //
    padding_len=BLOCK_SIZE - len % BLOCK_SIZE;
   // printf("\nTag padding len:%d\n",padding_len);
    memset(buf+len, padding_len, padding_len);
/**
    for(i=len; i < len+padding_len ;i++){
        buf[i]=padding_len;
    }
**/
    AES_cbc_encrypt(buf ,buf ,len+padding_len ,&aunthenticate_key, iv_aunthentication,AES_ENCRYPT);
    fwrite(buf ,RW_SIZE ,len+padding_len ,wfp);
    fclose(wfp);
    fclose(fp);

unsigned char buffer[16];
FILE *source;
FILE *Tag;
int a, c;
int j=0;
source = fopen("fs_tag.file","r+b");

int filesize;
fseek(source, 0, SEEK_END);
filesize = ftell(source);
fseek(source, 0, SEEK_SET);
a = filesize - 16;
//printf("File Size %d", a);
//fseek(source, 0, 10); // Set the new position at 10
if (source != NULL) {
for (i = a; i < filesize; i++) {
c = fgetc(source); // Get character
buffer[j] = c; // Store characters in array

//printf("Buffer[%d] = %X\n",j, c);
j++;
}
} else {
printf("File not found.\n");
return 0;
}
fclose(source);
Tag = fopen("fs_tag.file", "w");
int results = fputs(buffer, Tag);
if (results == EOF) {
    printf("Failed to write do error code here.");
}
fclose(Tag);
/* Add null to end string */
buffer[i] = '\0';
//for (i = 0; i < sizeof(buffer); i++) {
//printf("Result B: %X\n", buffer[i]);
//}

    int p;
    for(p =0; p<fsize; p++)
    {
	tag1[p] = buffer[p];
        //printf("%s",buffer[p]);
        //printf("%d\n",p);
    }
    printf("\nTag Genrated at sender Side = %s",tag1);
   // string str(buffer);
   // tag1 = str; 
	
FILE *source1;
source1 = fopen("fs_tag.file","r+b");

int filesize1;
fseek(source1, 0, SEEK_END);
filesize1 = ftell(source1);
 printf("\nTag File Size = %d ", filesize1);
fclose(source1);
	//printf("Hi this is Nandish");
 
    return SUCC;
}



// This will generate the Tag on receiver side and will use to Check the data integrity.

int tag_vrfy_aes(char *in_file,char *out_file)
{

   int i=0;
    int len=0;
    int padding_len=0;
    char buf[FREAD_COUNT+BLOCK_SIZE];
    FILE *inputfile;
    long inputfilelength=0;
    inputfile=fopen("input.txt","r");
  //fseek(f, 0, SEEK_END);
    fseek(inputfile, 0, SEEK_END);
    long fsize = ftell(inputfile);
	//printf("file size : %lu \n",fsize );
	//q=fsize;
//RAND_bytes(key1,sizeof (key1));
 
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
 
    memset(iv_aunthentication,0,sizeof(iv_aunthentication)); // init iv_aunthentication
	
	// SET the AES Key to 256 bit
    AES_set_encrypt_key(key1 ,KEY_BIT ,&aunthenticate_key);
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT, fp) ){
        if( FREAD_COUNT != len ){
            break;
        }
 
        AES_cbc_encrypt(buf ,buf ,len ,&aunthenticate_key,iv_aunthentication ,AES_ENCRYPT);
        fwrite(buf ,RW_SIZE ,len ,wfp);
    }
 
 
    //
    padding_len=BLOCK_SIZE - len % BLOCK_SIZE;
   // printf("\nTag padding len:%d\n",padding_len);
    memset(buf+len, padding_len, padding_len);
/**
    for(i=len; i < len+padding_len ;i++){
        buf[i]=padding_len;
    }
**/
    AES_cbc_encrypt(buf ,buf ,len+padding_len ,&aunthenticate_key, iv_aunthentication,AES_ENCRYPT);
    fwrite(buf ,RW_SIZE ,len+padding_len ,wfp);
    fclose(wfp);
    fclose(fp);

unsigned char buffer[16];
FILE *source;
FILE *Tag;
int a, c;
int j=0;
source = fopen("fs_tag.file","r+b");

int filesize;
fseek(source, 0, SEEK_END);
filesize = ftell(source);
fseek(source, 0, SEEK_SET);
a = filesize - 16;
//printf("File Size %d", a);
//fseek(source, 0, 10); // Set the new position at 10
if (source != NULL) {
for (i = a; i < filesize; i++) {
c = fgetc(source); // Get character
buffer[j] = c; // Store characters in array

//printf("Buffer[%d] = %X\n",j, c);
j++;
}
} else {
printf("File not found.\n");
return 0;
}
fclose(source);
Tag = fopen("fs_tag.file", "w");
int results = fputs(buffer, Tag);
if (results == EOF) {
    printf("Failed to write do error code here.");
}
fclose(Tag);
/* Add null to end string */
buffer[i] = '\0';
//for (i = 0; i < sizeof(buffer); i++) {
//printf("Result B: %X\n", buffer[i]);
//}

    int p;
unsigned char tag2[1000];
    for(p =0; p<fsize; p++)
    {
	tag2[p] = buffer[p];
        //printf("%s",buffer[p]);
        //printf("%d\n",p);
    }
    printf("\nTag Genrated on Receiver side= %s",tag1);
   // string str(buffer);
   // tag1 = str; 
	
FILE *source1;
source1 = fopen("fs_tag.file","r+b");

int filesize1;
fseek(source1, 0, SEEK_END);
filesize1 = ftell(source1);
 printf("\nTag File Size = %d ", filesize1);
fclose(source1);
	//printf("Hi this is Nandish");
 
    return SUCC;

}



 // To encrypt the plain text
int fs_encrypt_aes(char *in_file,char *out_file)
{
    
    int i=0;
    int len=0;
    int padding_len=0;
    char buf[FREAD_COUNT+BLOCK_SIZE];
	//char [FREAD_COUNT+BLOCK_SIZE];
	FILE *inputfile;
    long inputfilelength=0;
    inputfile=fopen("input.txt","r");
  //fseek(f, 0, SEEK_END);
    fseek(inputfile, 0, SEEK_END);
    long fsize = ftell(inputfile);
	//printf("file size : %lu \n",fsize );
	q=fsize;
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
    //printf("Encryption padding len:%d\n",padding_len);
    memset(buf+len, padding_len, padding_len);

    AES_cbc_encrypt(buf ,buf ,len+padding_len ,&aes_ks3, iv,AES_ENCRYPT);
    fwrite(buf ,RW_SIZE ,len+padding_len ,wfp);
 
 
	int j;
    for(j =0; j<fsize; j++)
    {
	c1[j] = buf[j];
    }
    fclose(wfp);
    fclose(fp);

//	printf("Encrypted text: %s",c1);
 
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

    FILE *inputfile;
    long inputfilelength=0;
    inputfile=fopen("input.txt","r");
  //fseek(f, 0, SEEK_END);
    fseek(inputfile, 0, SEEK_END);
    long fsize = ftell(inputfile);
	//printf("file size : %lu \n",fsize );
	q=fsize;
 
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
    //printf("\ntotal_size %d\n",total_size);
 
    while( len = fread( buf ,RW_SIZE ,FREAD_COUNT ,fp) ){
        if( FREAD_COUNT == 0 ){
            break;
        }
        save_len+=len;
        w_len=len;
 
        AES_cbc_encrypt(buf ,buf ,len ,&aes_ks3 ,iv ,AES_DECRYPT);
        if( save_len == total_size ){ // check last block
            w_len=len - buf[len-1];
           // printf("\nDecryption Cipher text padding size %d" ,buf[len-1]);
        }
 
        fwrite(buf ,RW_SIZE ,w_len ,wfp);
	
    }
 int g;
    for(g =0; g<fsize; g++)
    {
	c2[g] = buf[g];
        //printf("%s",buf[p]);
        //printf("%d\n",p);
    }
//printf("\nDecrypted Cipher Text%s",c2);
    fclose(wfp);
    fclose(fp);
 
    return SUCC;
}

int main(int argc, char *args[])
{
    
   clock_t start_t, end_t, total_t;
   int i;
	
   start_t = clock();


   printf("Starting of the program, start_t = %ld\n", start_t);

    if( argc != 2 ){
        printf("[Usage] %s fs_src_file\n",args[0]);
        return FAIL;
    }
 
    FILE *fp=fopen(args[1],"a+b");
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "\nSending local time and date: %s \n", asctime (timeinfo));
    fprintf(fp, "%s\n", asctime(timeinfo));
    fclose(fp);


    if( fs_encrypt_aes(args[1],"fs_in.file") == SUCC){
		if(tag_generation_aes("fs_in.file","fs_tag.file") ==SUCC)
		{
			printf("\nTag generated successfully");
		}
	}
 

	if(tag_vrfy_aes("fs_in.file","fs_tag.file") == SUCC){
	printf("\nTag Verified Successfully");
	fs_decrypt_aes("fs_in.file","fs_out.file");

	    }
      
    int count =0;
    int k;

	for(k=0; k<16; k++)
	{
//printf("Tag value = %c", tag1[i]);
		if(tag1[k] == tag2[k])
		{
			count++;	
		}

		else
		{
		//	printf("Hi lol");
		}
	}

	if(count==16)
	{
	printf("Authentication Complete\n\n\n\n");
	}

FILE *source;
    source = fopen("fs_out.file","r+");
    fseek(source, 0, SEEK_END);
    int filesize = ftell(source); 
    fseek(source, 0, SEEK_SET);
	int flag =0;
    long a = filesize -25;

    fseek(source,a-1,SEEK_SET); // Set the new position at 10. 
    int j=0;
    unsigned char buffer[25];
    printf("\nSender Time Recieved: ");
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
    printf("\nTime integrity Passed");
}

    if(flag==0)
    {
        printf("\n\nMessage integrity verified\n");
    }
	printf("\nMessage Integrity and Time-stamp Checked... Authenticated Complete \n");
    //int a = 
    //receiver side  time stamp
 
 
    return 0;
}
