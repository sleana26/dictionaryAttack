/**
 * @file crack.c
 * @author Sean Leana (smleana)
 * This program makes a dictionary attack against a file including users information includinghashes
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "password.h"

/** Maximum username length */
#define USERNAME_LIMIT 32

/** Maximum number of words we can have in the dictionary. */
#define DLIST_LIMIT 1000

/** Number of required arguments on the command line. */
#define REQ_ARGS 2

/** Type for representing a word in the dictionary. */
typedef char Password[PW_LIMIT + 1];

/** Print out a usage message and exit unsuccessfully. */
static void usage()
{
    fprintf( stderr, "Usage: crack dictionary-filename shadow-filename\n");
    exit( EXIT_FAILURE);
}

/**
 * read line reads in a file and parses it until EOF or EOL
 * @param fp the file to be read
 * @return the string read
 */
char* readLine(FILE *fp)
{
    if (fp == NULL) {
        fp = stdin;
    }

    char ch = 0;
    if ((ch = fgetc(fp)) == EOF) {
        return NULL;
    } else {
        ungetc(ch, fp);
    }

    int capacity = 5;
    char *line = (char*) malloc(capacity * sizeof(char));
    int len = 0;
    while ((ch = fgetc(fp)) != '\n' && ch != EOF) {
        if (len >= capacity) {
            capacity *= 2;
            char *newLine = (char*) malloc(capacity * sizeof(char));
            for (int i = 0; i < len; i++) {
                newLine[i] = line[i];
            }
            free(line);
            line = newLine;
        }
        line[len++] = ch;
    }
    line[len] = '\0';
    return line;
}

/**
 * read word reads in a word and parses it until EOF or EOL or a space
 * @param fp the file to be read
 * @return the word read
 */
char* readWord(FILE *fp)
{
    if (fp == NULL) {
        fp = stdin;
    }

    char ch = 0;
    if ((ch = fgetc(fp)) == EOF) {
        return NULL;
    } else {
        ungetc(ch, fp);
    }
    int len = 0;
    char *word = (char*) malloc(16 * sizeof(char));
    while ((ch = fgetc(fp)) != '\n' && ch != EOF) {
        if (ch == ' ') {
            fprintf(stderr, "Invalid dictionary word\n");
            fclose(fp);
            exit(1);
        }
        word[len++] = ch;
    }
    word[len] = '\0';
    return word;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        usage();
        exit(1);
    }
    FILE *dictionary = fopen(argv[1], "r");

    int capacity = 10; // initial capacity
    char **dictionaryWords = malloc(capacity * sizeof(char*));
    int count = 0;
    char *word;

    while ((word = readWord(dictionary)) != NULL) {
        if (count >= capacity) {
            if (count > 1000) {
                fprintf(stderr, "Too many dictionary words\n");
                exit(1);
            }
            capacity *= 2; // double the capacity
            dictionaryWords = realloc(dictionaryWords,
                    capacity * sizeof(char*));
        }
        dictionaryWords[count] = malloc(strlen(word) + 1);
        strcpy(dictionaryWords[count], word);
        count++;
    }

    fclose(dictionary);

    FILE *shadow = fopen(argv[2], "r");

    char *line;
    char name[33];
    char salt[9];
    char hash[23];
    char buffer[11];

    int len;
    
    while ((line = readLine(shadow)) != NULL) {
        int offset = 0;
        if (sscanf(line, "%31[^: ]%n", name, &len) == 1) {
            offset += len;
        }
        if (sscanf(line + offset, "%[:$1]%n", buffer, &len) == 1) {
            offset += len;
            if ((strlen(buffer) != 4)
                    || (buffer[0] != ':' && buffer[1] != '$' && buffer[2] != '1'
                            && buffer[3] != '$')) {
                for (int i = 0; i < count; i++) {
                    free(dictionaryWords[i]);
                }
                free(dictionaryWords);
                //error is here somewhere, probably not scanning enough after the first user and hash is parsed, put breakpoint at 144
                fprintf(stderr, "Invalid shadow file entry\n");
                exit(1);
            }
        }
        if (sscanf(line + offset, "%[^$ ]%n", salt, &len) == 1) {
            offset += len;
            sscanf(line + offset, "%c%n", buffer, &len);
            offset += len;
            if (strlen(salt) != SALT_LENGTH) {
                for (int i = 0; i < count; i++) {
                    free(dictionaryWords[i]);
                }
                free(dictionaryWords);
                fprintf(stderr, "Invalid shadow file entry\n");
                exit(1);
            }
        }
        if (sscanf(line + offset, "%[^: ]%n", hash, &len) == 1) {
            offset += len;
            if (strlen(hash) != PW_HASH_LIMIT) {
                for (int i = 0; i < count; i++) {
                    free(dictionaryWords[i]);
                }
                free(dictionaryWords);
                fprintf(stderr, "Invalid shadow file entry\n");
                exit(1);
            }
        }

        char result[PW_HASH_LIMIT + 1];

        for (int i = 0; i < count; i++) {
            hashPassword(dictionaryWords[i], salt, result);
            if (strcmp(result, hash) == 0) {
                printf("%s : %s\n", name, dictionaryWords[i]);
            }
        }
    }
    for (int i = 0; i < count; i++) {
        free(dictionaryWords[i]);
    }
    free(dictionaryWords);
    fclose(shadow);
}