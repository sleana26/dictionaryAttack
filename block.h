/** 
 * @file block.h
 * @author Sean Leana (smleana)
 * This file is used to define Block and define finctions within block
 */

#ifndef _BLOCK_H_
#define _BLOCK_H_

#include "magic.h"

/** A (partially filled) block of up to 64 bytes. */
typedef struct {
    // Array of bytes in this block. */
    byte data[BLOCK_SIZE];

    // Number of bytes in the data array currently in use.
    int len;
} Block;

/**
 *This function frees the memory for the given block.
 * @param block pointer to a block
 */
void freeBlock(Block *block);

/** creates a block */
Block* makeBlock();

/** appends a byte to the block */
void appendByte(Block *dest, byte b);

/** appends a string to the block */
void appendString(Block *dest, char const *src);

#endif
