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

    // for(i = 0; i < length; i ++) {
    //     if(!crypt) {
    //         destination[i] = (char)(buffer[i] ^ key[i]);
    //     }
    // }
    
    // printf(" After part 1 : %s\n", destination);

    for(i = 0; i < length; i ++) {
        printf("i : %d", i);
        /* CBC : Xor on last crypted block */
        destination[i] = buffer[i] ^ lastCryptedBlock[i];
    }

    // for(i = 0; i < length; i ++) {
    //     if(crypt) {
    //         destination[i] = (char)(destination[i] ^ key[i]);
    //     }
    // }
    return i;
}

int getFileNumberOfChars(char *filePath) {
    FILE *source = fopen(filePath, "r");
    if (source == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    fseek(source, 0, SEEK_END);
    int byteCount = ftell(source);
    fclose(source);

    return byteCount;
}

int dechiffre(char *cryptedBuffer, int cryptedBufferLength, char *decryptedFilePath, char *key) {

    /* Get key length */
    int len = (sizeof(char) * strlen(key)); 
    
    /* Open the destination file in write mode */
    FILE *fileWrite = fopen(decryptedFilePath, "wb");
    if (fileWrite == NULL) {
        printf("Error opening destination file!\n");
        exit(1);
    }

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
    if(buffer == NULL) {
        printf("Allocation Error !\n");
        exit(1);
    }
    
    /* The decrypted read buffer */
    char *decryptedBuffer = malloc(sizeof(char) * len);
    if(decryptedBuffer == NULL) {
        printf("Allocation Error !\n");
        exit(1);
    }

    /* set all entries in buffer to NULL by default*/
    memset(buffer, 0, len);
    memset(decryptedBuffer, 0, len);
    
    int count = 0;
    int i = 0;
    int padding = cryptedBufferLength % len;
    int paddingFrom = padding > 0 ? cryptedBufferLength - padding : cryptedBufferLength;

    printf("Padding %d, from : %d", padding, paddingFrom);
    
    for(i = 0; i <= cryptedBufferLength; i++) {
        // printf("Buffer %d => %c \n", i, cryptedBuffer[i]);
        if(count < len - 1 && (i != cryptedBufferLength)) {
            /* fill buffer */
            buffer[count++] = cryptedBuffer[i];

        } else {
            printf("__________\n");
            
            /* Buffer full, let's decrypt it */
            int decryptedBytes = 0;
            if(i != paddingFrom) {
                decryptedBytes = xorBuffer(len, decryptedBuffer, buffer, lastXoredBlock, key, false);
            } else {
                decryptedBytes = xorBuffer(padding, decryptedBuffer, buffer, lastXoredBlock, key, false);
            }
            
            printf("Decrypted %d bytes : %s\n", decryptedBytes, decryptedBuffer);
            memcpy(lastXoredBlock, buffer, len);
            fwrite(decryptedBuffer, sizeof(char), decryptedBytes, fileWrite);
            
            /* Reset for next buffer */
            count = 0;
            memset(buffer, 0, len);
            memset(decryptedBuffer, 0, len);
        }
    }



    free(buffer);
    free(decryptedBuffer);
    free(lastXoredBlock);
    fclose(fileWrite);

    return 0;
}

/*  
    This method crypts or decrypts (depending on "crypt" bool) 
    the source file and write the result in destination file
    using the key parameter, in CBC mode 
*/
int chiffre(char *sourceFilePath, char *destFilePath, char *key, bool crypt) {

    /* Open source file in read mode */
    FILE *fileRead = fopen(sourceFilePath, "rb");
    if (fileRead == NULL) {
        printf("Error opening source file!\n");
        exit(1);
    }

    int nbCharsInFile = getFileNumberOfChars(sourceFilePath);
    char *cryptedBuffer = malloc(sizeof(char) * nbCharsInFile);
    memset(cryptedBuffer, 0, nbCharsInFile);
    int count = 0;

    printf("Number of chars in file : %d \n", nbCharsInFile);

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
        //  printf(" decrypted : %s\n", decrypted);
        // printf("Crypted => %s\n", crypted);

        strncat(cryptedBuffer, crypted, bytesRead);
        printf("cryptedBufferContent %s \n", cryptedBuffer);
        // int i = 0;
        // for(i = 0; i < bytesRead; i++) {
        //     /* We fill the globalBuffer with the crypted buffer */
        //     cryptedBuffer[count++] = crypted[i];
        // }
        count+= bytesRead;

        // Store last crypted block for next iteration
        memcpy(lastXoredBlock, crypted, len);

        memset(buffer, 0, bytesRead);
        memset(crypted, 0, len);
    }
    
    /* Close our files */
    fclose(fileRead);

    // ---------------------TEST------------------------
    // DONE Crypting buffer, let's decrypt it
    dechiffre(cryptedBuffer, count, destFilePath, key);
    // ------------------- ENDTEST ---------------------

    // Finally we free our allocations
    free(lastXoredBlock);
    free(buffer);
    free(crypted);
    free(cryptedBuffer);

    return 0;
}

int main(int argc, char *argv[]) {
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