#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#define SHIFT 1

/* 
    Prints program usage 
*/
int printUsage() {
    printf("Usage: ./cbc [-d] <key> <sourceFile> <destFile> \n");
    return 0;
}

/*
    This methods crypts the buffer passed as parameter
    with a xor on the last crypted block, then a xor on the key
*/
int xorBuffer(int length, char *destination, char *buffer, char *lastCryptedBlock, char *key, bool crypt) {
    int i = 0;

    if(!crypt) {
        destination[i] = (char)(buffer[i] ^ key[i]);
    }

    for(i = 0; i < length; i ++) {
        /* CBC : Xor on last crypted block */
        destination[i] = (char)(buffer[i] ^ lastCryptedBlock[i]);
    }

    if(crypt) {
        destination[i] = (char)(buffer[i] ^ key[i]);
    }

    return i;
}

/*  
    This method crypts or decrypts (depending on "crypt" bool) 
    the source file and write the result in destination file
    using the key parameter, in CBC mode 
*/
int chiffre(char *sourceFilePath, char *destFilePath, char *key, bool crypt) {

    /* Open the destination file in write mode */
    FILE *fileWrite = fopen(destFilePath, "wb");
    if (fileWrite == NULL) {
        printf("Error opening destination file!\n");
        exit(1);
    }

    /* Open source file in read mode */
    FILE *fileRead = fopen(sourceFilePath, "rb");
    if (fileRead == NULL) {
        printf("Error opening source file!\n");
        exit(1);
    }

    /* Get key length */
    int len = (sizeof(char) * strlen(key)); 
    printf("- Key length : %d \n", len);

    /* Store the last crypted block in this
        We initialize this with our key to have an IV */
    char *lastXoredBlock = malloc(sizeof(char) * len);
    if(lastXoredBlock == NULL) {
        printf("Allocation Error !\n");
        exit(1);
    }
    memcpy(lastXoredBlock, key, len);

    /* The read buffer */
    char *buffer = malloc(sizeof(char) * len);
    size_t bytesRead = 0;

    /* set all entries in buffer to NULL by default*/
    memset(buffer, 0, len);

    printf("- %s content ...  \n", crypt ? "Crypting" : "Decrypting");
    
    char *crypted = malloc(sizeof(char) * len);
    if(crypted == NULL) {
        printf("Allocation Error !\n");
        exit(1);
    }

    /* Read file using buffer */
    while ((bytesRead = fread(buffer, sizeof(char), len, fileRead)) > 0)
    {   
        int cryptedBytes = xorBuffer((int)bytesRead, crypted, buffer, lastXoredBlock, key, crypt);
    
        // Store last crypted block for next iteration
        memcpy(lastXoredBlock, crypt ? crypted : buffer, len);

        /* Write crypted buffer in result file */
        fwrite(crypted, sizeof(char), cryptedBytes, fileWrite);


        /* Reset buffer content */
        memset(buffer, 0, bytesRead);
        memset(crypted, 0, len);
    }

    printf("- Content %s  !\n", crypt ? "crypted" : "decrypted");
    
    /* Close our files */
    fclose(fileRead);
    fclose(fileWrite);
    

    // Finally we free our allocations
    free(lastXoredBlock);
    free(buffer);
    free(crypted);

    return 0;
}

int main(int argc, char *argv[])
{
    int opt;
    int arg = 0;
    bool crypt = true;

    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch(opt) {
            case 'd': crypt = false; arg++; break;
            case '?': 
                printUsage();
                return 1;
        }
    }

    if (argc < 4 + arg) {
        printUsage();
        return 1;
    } else {
        char *key = argv[1 + arg]; 
        char *sourceFilePath = argv[2 + arg];
        char *destFilePath = argv[3 + arg];
        chiffre(sourceFilePath, destFilePath, key, crypt);
    }
}