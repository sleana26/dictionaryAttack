/** 
 * @file password.c
 * @author Sean Leana (smleana
 * This file is used to perform an MD5
 */

#include "md5.h"
#include <stdlib.h>
#include <stdio.h>  // Maybe for some debugging

/** Function type for the f functions in the md5 algorithm. */
typedef word (*FFunction)( word, word, word);

/** Function type for the g functions in the md5 algorithm. */
typedef int (*GFunction)(int);

/** The MD5 algorithm uses four different versions of a function named F,
 * a different version for each round. This is version 0.
 * @param B
 * @param C
 * @param D
 * @return ...
 */
word fVersion0(word B, word C, word D)
{
    return (B & C) | (~B & D);
}

/** The MD5 algorithm uses four different versions of a function named F,
 * a different version for each round. This is version 1.
 * @param B
 * @param C
 * @param D
 * @return ...
 */
word fVersion1(word B, word C, word D)
{
    return (B & D) | (C & ~D);
}

/** The MD5 algorithm uses four different versions of a function named F,
 * a different version for each round. This is version 2.
 * @param B
 * @param C
 * @param D
 * @return ...
 */
word fVersion2(word B, word C, word D)
{
    return (B ^ C ^ D);
}

/** The MD5 algorithm uses four different versions of a function named F,
 * a different version for each round. This is version 3.
 * @param B
 * @param C
 * @param D
 * @return ...
 */
word fVersion3(word B, word C, word D)
{
    return C ^ (B | ~D);
}

/** The MD5 algorithm uses four different versions of a function named G,
 * a different version for each round. This is version 0
 * @param idx index
 * @return ...
 */
int gVersion0(int idx)
{
    return idx;
}

/** The MD5 algorithm uses four different versions of a function named G,
 * a different version for each round. This is version 1
 * @param idx index
 * @return ...
 */
int gVersion1(int idx)
{
    return (5 * idx + 1) % 16;
}

/** The MD5 algorithm uses four different versions of a function named G,
 * a different version for each round. This is version 2
 * @param idx index
 * @return ...
 */
int gVersion2(int idx)
{
    return (3 * idx + 5) % 16;
}

/** The MD5 algorithm uses four different versions of a function named G,
 * a different version for each round. This is version 3
 * @param idx index
 * @return ...
 */
int gVersion3(int idx)
{
    return (7 * idx) % 16;
}

GFunction G[4] = { gVersion0, gVersion1, gVersion2, gVersion3 };

FFunction F[4] = { fVersion0, fVersion1, fVersion2, fVersion3 };

/**
 * This function implements the rotate left operation from the MD5 algorithm,
 * shifting the given value to the left by s bits, with wraparound. It returns
 * the resulting value. 
 * @param value the given word value
 * @param s number of bits to shift to the left
 */
word rotateLeft(word value, int s)
{
    unsigned int mask = (1 << s) - 1;
    mask = mask << (32 - s);
    unsigned int leftBits = value & mask;
    leftBits = leftBits >> (32 - s);
    value = value << s;
    return value | leftBits;
}

/** This function implements an iteration of the MD5 algorithm on a 64-byte block
 * (16 words). The first parameter is the contents of the block, the next four parameters
 * are the A, B, C, and D variables representing the MD5 state, passed by reference so
 * the function can change them. The last parameter is the iteration number, a value
 * between 0 and 63.
 * @param M array of words
 * @param A 
 * @param B
 * @param C
 * @param D
 * @param i
 */
void md5Iteration(word M[BLOCK_WORDS], word *A, word *B, word *C, word *D, int i)
{
    *A += (*F[i / 16])(*B, *C, *D);
    *A += M[G[i / 16](i)];
    *A += md5Noise[i];
    *A = rotateLeft(*A, md5Shift[i]);
    *A += *B;
    word temp = *B;
    *B = *A;
    *A = *D;
    *D = *C;
    *C = temp;
}

/**
 * This function pads the given block, bringing its length up to 64 bytes, adding byte
 * values as described in the MD5 algorithm.
 * @param block pointer to a block
 */
void padBlock(Block *block)
{
    unsigned int origLen = block->len;
    unsigned long long origLenBits = (unsigned long long) origLen * 8;

    appendByte(block, 0x80);
    while (block->len < 56) {
        appendByte(block, 0x00);
    }

    appendByte(block, (origLenBits) & 0xFF);
    appendByte(block, (origLenBits >> 8) & 0xFF);
    appendByte(block, (origLenBits >> 16) & 0xFF);
    appendByte(block, (origLenBits >> 24) & 0xFF);
    appendByte(block, (origLenBits >> 32) & 0xFF);
    appendByte(block, (origLenBits >> 40) & 0xFF);
    appendByte(block, (origLenBits >> 48) & 0xFF);
    appendByte(block, (origLenBits >> 56) & 0xFF);
}

/** 
 * This is the only public function provided by the md5 component. It pads the given
 * input block, computes the MD5 hash using the helper functions above and stores the
 * result in the given hash array.
 * @param block 
 * @param hash 
 */
void md5Hash(Block *block, byte hash[HASH_SIZE])
{
    word A = md5Initial[0];
    word B = md5Initial[1];
    word C = md5Initial[2];
    word D = md5Initial[3];

    word M[BLOCK_WORDS];
    padBlock(block);
    block->len = 64;

    for (int i = 0; i < BLOCK_WORDS; i++) {
        M[i] = (block->data[i * 4] & 0xFF)
                | ((block->data[i * 4 + 1] & 0xFF) << 8)
                | ((block->data[i * 4 + 2] & 0xFF) << 16)
                | ((block->data[i * 4 + 3] & 0xFF) << 24);
    }

    for (int i = 0; i < 64; i++) {
        md5Iteration(M, &A, &B, &C, &D, i);
    }

    A += md5Initial[0];
    B += md5Initial[1];
    C += md5Initial[2];
    D += md5Initial[3];

    hash[0] = (A & 0x000000FF);
    hash[1] = (A & 0x0000FF00) >> 8;
    hash[2] = (A & 0x00FF0000) >> 16;
    hash[3] = (A & 0xFF000000) >> 24;

    hash[4] = (B & 0x000000FF);
    hash[5] = (B & 0x0000FF00) >> 8;
    hash[6] = (B & 0x00FF0000) >> 16;
    hash[7] = (B & 0xFF000000) >> 24;

    hash[8] = (C & 0x000000FF);
    hash[9] = (C & 0x0000FF00) >> 8;
    hash[10] = (C & 0x00FF0000) >> 16;
    hash[11] = (C & 0xFF000000) >> 24;

    hash[12] = (D & 0x000000FF);
    hash[13] = (D & 0x0000FF00) >> 8;
    hash[14] = (D & 0x00FF0000) >> 16;
    hash[15] = (D & 0xFF000000) >> 24;
}
