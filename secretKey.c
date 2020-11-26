/**************************************************************************
* Author: Chelsea Marie Hicks
*
* Description: Program utilizes OpenSSL EVP to determine the encryption key
*       given the following information:
*       -plaintext known: This is a top secret.
*       -ciphertext known: 8d20e5056a8d24d0462ce74e4904c1b5
*                          13e10d1df4a2ef2ad4540fae1ca0aaf9
*       -iv known: 00000000000000000000000000000000
*       -aes-128-cbc used to encrypt
*
* Sources: This resource was incredibly helpful: 
* https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
*************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <string.h>
#include <openssl/evp.h>

//Function takes a word from words.txt and adds spaces to the end to make it 128 bits
void addPadding(char *wordtoPad) {
    int wordLength;
    //Obtain length of word passed in
    wordLength = strlen(wordtoPad);

    //Add spaces to end of word until it is length 16
    while(wordLength < 16) {
        wordtoPad[wordLength] = ' ';
        wordLength++;
    }

    //Add null terminator to string
    wordtoPad[wordLength] = '\0';
}

//Function to print the word used as key, ciphertext produced, and whether or not it matches
//provided ciphertext to locate the key
int printResults(unsigned char* buffer, char* key, int length, FILE* out, char* outcome) {

    char newline = '\n';
    char space = ' ';
    //Counters for for loops
    int i, j, k;

    //Print the word used as the key to file
    for(i = 0; i < strlen(key); i++) {
        fprintf(out, "%c", key[i]);
    }
    
    //Print a space between the key and cipher
    fprintf(out, "%c", space);

    //Print cipher 
    for(j = 0; j < length; j++) {
        fprintf(out, "%02x", buffer[j]);
    }

    //Print a space between cipher and outcome
    fprintf(out, "%c", space);

    //Print outcome
    for(k = 0; k < strlen(outcome); k++) {
        fprintf(out, "%c", outcome[k]);
    }

    //Print a newline character
    fprintf(out, "%c", newline);

    return 0;
}

int main() {

    EVP_CIPHER_CTX *ctx;

    //Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();

    //Variable for 128 bit IV provided in scenario, all zeroes
    unsigned char iv[16] = {0};

    //Buffer for 128 bit key that we are to find, every word in the words.txt file will be checked
    char word[16];

    //Known plaintext message
    char plaintext[] = "This is a top secret.";

    //Known ciphertext
    char cipher[] = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";

    //Variable for key file and output file
    FILE* possibleKey, *outputFile;

    //Output buffer
    unsigned char outputBuffer[1024 + EVP_MAX_BLOCK_LENGTH];

    //Open words.txt file as possibleKey for reading in words
    possibleKey = fopen("words.txt", "r");

    //Open a results.txt file to read and append 
    outputFile = fopen("results.txt", "a+");

    //Error handling for file opening
    if(possibleKey < 0 || outputFile < 0) {
        perror("Unable to open file!");
        exit(1);
    }

    //Messages to be printed in outputFile when comparing ciphertext given to 
    //ciphertext produced with key from dictionary 
    unsigned char success[] = "KEY LOCATED";
    unsigned char failure[] = " ";

    int length, outputLength, ciphLength;

    //Loop for entire program operation, goes through every word in words.txt
    while(fgets(word, 16, possibleKey)) {
        //Obtain the length of the word read in from words.txt, remove null val at the end and reset length
        length = strlen(word);
        word[length-1] = '\0';
        length = strlen(word);

        //If the length is less than 16, padding of space characters must be added to make the key 128 bits
        if(length < 16) {
            //Call addPadding function to insert spaces at the end of the word
            addPadding(word);
        }

        //Initialize the encryption operation
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, word, iv);

        //Provide message to be encrypted and obtain ciphertext
        //plaintext message is the buffer in, outputBuffer is buffer out
        if(1 != EVP_EncryptUpdate(ctx, outputBuffer, &outputLength, plaintext, strlen(plaintext))) {
            perror("Error in encryptUpdate");
            exit(1);
        }

        //Finalize encryption
        if(1 != EVP_EncryptFinal_ex(ctx, outputBuffer + outputLength, &ciphLength)) {
            perror("Error in encryptFinal");
            exit(1);
        }
        //update the outputLength
        outputLength += ciphLength;

        //Setup to write contents to results file
        int i;
        //Variable for buffer contents to print ciphertext to file
        char* bufferContent = (char*) malloc (2*outputLength + 1);
        char* bufferPtr = bufferContent;

        //For loop to generate hexadecimal 
        for(i = 0; i < outputLength; i++) {
            //Set the bufferPtr to the contents of the outputBuffer as a hexadecimal
            //number with a field width of 2
            bufferPtr += sprintf(bufferPtr, "%02x", outputBuffer[i]);
        }
        //Reset null terminator for use with strcasecmp
        *(bufferPtr + 1) = '\0';

        //Compare the cipher text provided to the bufferContent, if they match, then the word used as the
        //key for encryption in this iteration of the while loop is the actual key we're looking for
        if(strcasecmp(cipher, bufferContent) == 0) {
            printResults(outputBuffer, word, outputLength, outputFile, success);
        }
        else {
            printResults(outputBuffer, word, outputLength, outputFile, failure);
        }
    }

    //Close files before program completion
    fclose(outputFile);
    fclose(possibleKey);

    return 1;
}