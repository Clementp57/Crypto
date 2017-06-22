#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Prints program usage */
int printUsage() {
    printf("Usage: ./cbc [-d] <key> <file>\n");
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

    if (argc < 3 + arg) {
        printUsage();
        return 1;
    } else {
        char *key = argv[1 + arg]; 
        char *filePath = argv[2 + arg];
        if(crypt) {
            printf("Crypting file : %s, with key: %s \n", filePath, key);
            chiffre(filePath, key);
        } else {
            printf("Decrypting file : %s, with key: %s \n", filePath, key);
            dechiffre(filePath, key);
        }
    }
}

/* Returns the number of chars in the file represented by the given filePath */
int getFileNumberOfChars(char *filePath) {
    FILE *source = fopen(filePath, "rb");
    if (source == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }
    fseek(source, 0, SEEK_END);
    int byteCount = ftell(source);
    fclose(source);

    return byteCount;
}

/* This method crypts the file referenced by the filePath parameter
   using the key parameter, in CBC mode */
int chiffre(char *filePath, char *key) {

    /* Open the destination file in write mode */
    FILE *fileWrite = fopen("crypted.txt", "wb");
    if (fileWrite == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    /* Open source file in read mode */
    FILE *fileRead = fopen(filePath, "rb");
    if (fileRead == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    /* Get key length */
    int len = (sizeof(char) * strlen(key)); 
    printf("- Key length : %d \n", len);

    /* Store the last crypted block in this
        We initialize this with our key to have an IV */
    char *lastXoredBlock = malloc(sizeof(char) * len);
    memcpy(lastXoredBlock, key, len);

    /* The read buffer */
    char *buffer = malloc(sizeof(char) * len);
    size_t bytesRead = 0;

    /* set all entries in buffer to NULL by default*/
    memset(buffer, 0, len);

    printf("- Crypting content ...  \n");
    
    char *xored = malloc(sizeof(char) * len);

    /* Read file using buffer */
    while ((bytesRead = fread(buffer, sizeof(char), len, fileRead)) > 0)
    {   
        printf("bytesRead => %d \n", bytesRead);
         /* let's encrypt the buffer */
        int i = 0;
        for(i = 0; i < bytesRead; i ++) {
            /* CBC : Xor on last crypted block */
            xored[i] = (char)(buffer[i] ^ lastXoredBlock[i]);
        }

        // Store last crypted block for next iteration
        memcpy(lastXoredBlock, xored, len);

        /* Write crypted buffer in result file */
        fwrite(xored, sizeof(char), i, fileWrite);


        /* Reset buffer content */
        memset(buffer, 0, bytesRead);
        // memset(xored, 0, len);
    }

    printf("- Content encrypted  !\n");
    
    /* Close our files */
    fclose(fileRead);
    fclose(fileWrite);
    

    // Finally we free our allocations
    free(lastXoredBlock);
    free(buffer);
    free(xored);

    return 0;
}

// This method decrypts the file referenced by the filePath parameter
// using the key parameter, in CBC mode
int dechiffre(char *filePath, char *key) {

     /* Open destination file in write mode */
    FILE *fileWrite = fopen("decrypted.txt", "wb");
    if (fileWrite == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    /* Open crypted file in read mode */
    FILE *fileRead = fopen(filePath, "rb");
    if (fileRead == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    /* Get key length */
    int len = (sizeof(char) * strlen(key)); 
    printf("- Key length : %d \n", len);

    /* Store the last crypted block in this
        We initialize this with our key to have an IV */
    char *lastXoredBlock = malloc(sizeof(char) * len);
    memcpy(lastXoredBlock, key, len);
    
    printf("- Decrypting content ... \n");

     /* The read buffer */
    char *buffer = malloc(sizeof(char) * len);
    size_t bytesRead = 0;

    /* set all entries in buffer to NULL by default*/
    memset(buffer, 0, len);

    char *decrypted = malloc(sizeof(char) * len);

    /* Read file using buffer */
    while ((bytesRead = fread(buffer, sizeof(char), len, fileRead)) > 0)
    {
         /* let's decrypt the buffer */
        int i = 0;
        for(i = 0; i < bytesRead; i++) {
            // Xor on last crypted block
            decrypted[i] = (char)(buffer[i] ^ lastXoredBlock[i]);
        }

        /* Write decrypted buffer in result file */
        fwrite(decrypted, sizeof(char), i, fileWrite);
        

        memcpy(lastXoredBlock, buffer, bytesRead);

         /* Reset buffer and xored content */
        memset(buffer, 0, bytesRead);
        // memset(decrypted, 0, len);
    }

    /* Close our files */
    fclose(fileWrite);
    fclose(fileRead);

    printf("- Content decrypted ! \n");

    // Finally we free our allocations
    free(decrypted);
    free(buffer);
    free(lastXoredBlock);


    return 0;
}
