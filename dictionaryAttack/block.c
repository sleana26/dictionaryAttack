/**
 * @file block.c
 * @author Sean Leana (smleana
 * This file is used to create a block of data in bytes and function to add to the data.
 * also keeps track of the length
 */

#include "block.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * This function dynamically allocated storage for a Block,
 * initializes its fields to indicate the block is empty and returns a pointer to the block.
 * @return Block ...
 */
Block* makeBlock() {
    Block *block = (Block*) malloc(sizeof(Block));
    block->len = 0;
    return block;
}

/**
 *This function frees the memory for the given block.
 * @param block pointer to a block
 */
void freeBlock(Block *block) {
    free(block);
}

/** 
 * This function stores the given byte value at the end of the given block. If this exceeds
 * the block’s capacity, the program should print a line with the error message ““Block
 * overflow” to standard error and exit unsuccessfully, although this should actually never
 * happen when this component is used in this program.
 * @param dest bloack to append byte to
 * @param b byte to append onto the end of the given block
 */
void appendByte(Block *dest, byte b) {
    if (dest->len >= BLOCK_SIZE) {
        fprintf(stderr, "Block overflow\n");
        freeBlock(dest);
        exit(1);
    }
    dest->data[dest->len++] = b;
}

/**
 * This function stores all the bytes from the given string at the end of the given block.
 * It should handle block overflow the same as the appendByte() function.
 * @param dest
 * @param src
 */
void appendString(Block *dest, char const *src) {
    if ((strlen(src) + dest->len) > BLOCK_SIZE) {
        fprintf(stderr, "Block overflow\n");
        freeBlock(dest);
        exit(1);
    }
    for (int i = 0; i < strlen(src); i++) {
        dest->data[dest->len++] = src[i];
    }
}
