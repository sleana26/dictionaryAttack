/** 
 * @file password.c
 * @author Sean Leana (smleana
 * This file is used to hash a password
 */

#include "password.h"
#include "magic.h"
#include "md5.h"
#include "block.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // For debugging.

/** Number of iterations of hashing to make a password. */
#define PW_ITERATIONS 1000

/** Given a password and a salt string, this function computes the alternate hash used in the
 * MD5 password encryption algorithm and leaves it in the altHash array.
 * @param pass the password to hash
 * @param salt a saltstring to help hash the function 
 * @param altHash the alternate hash
 */
void computeAlternateHash(char const pass[], char const salt[SALT_LENGTH + 1], byte altHash[HASH_SIZE])
{
    Block *block = makeBlock();
    appendString(block, pass);
    appendString(block, salt);
    appendString(block, pass);

    md5Hash(block, altHash);
}

/** Given a password, a salt string and an alternate hash, this function computes the first intermediate hash
 * used in the MD5 password encryption algorithm and leaves it in the intHash array.
 * @param pass the password to hash
 * @param salt a salt string to help hash the password
 * @param altHash the alternate hash
 * @param intHash 
 */
void computeFirstIntermediate(char const pass[], char const salt[SALT_LENGTH + 1], byte altHash[HASH_SIZE],
        byte intHash[HASH_SIZE]) 
{
    Block *block = makeBlock();
    int passLen = strlen(pass);

    appendString(block, pass);
    appendString(block, "$1$");
    appendString(block, salt);
    for (int i = 0; i < passLen; i++) {
        appendByte(block, altHash[i]);
    }

    while (passLen > 0) {
        if ((passLen & 1) == 0) {
            appendByte(block, pass[0]);
        } else {
            appendByte(block, 0);
        }
        passLen >>= 1;
    }
    md5Hash(block, intHash);
}

/**
 * Given a password, a salt string and the one of the intermediate hash values, this function computes the next
 * intermediate hash used in the MD5 password encryption algorithm. The previous alternate hash is given in the
 * intHash array, and the next alternate hash is stored in in this same array when this function returns. The
 * inum parameter is the iteration number for the algorithm, between 0 and 999.
 */
void computeNextIntermediate(char const pass[], char const salt[SALT_LENGTH + 1], int inum, byte intHash[HASH_SIZE])
{
    Block *block = makeBlock();
    if (inum % 2 == 0) {
        for (int i = 0; i < 16; i++) {
            appendByte(block, intHash[i]);
        }
    } else {
        appendString(block, pass);
    }
    if (inum % 3 != 0) {
        appendString(block, salt);
    }
    if (inum % 7 != 0) {
        appendString(block, pass);
    }

    if (inum % 2 == 0) {
        appendString(block, pass);
    } else {
        for (int i = 0; i < 16; i++) {
            appendByte(block, intHash[i]);
        }
    }
    md5Hash(block, intHash);
}

/** Given a 16-byte hash value, this function converts it to a string of
 * printable characters in the set “./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz”.
 * @param hash hash value to be truned into a string
 * @param result the resulting string after turning the hash into a string
 */
void hashToString(byte hash[HASH_SIZE], char result[PW_HASH_LIMIT + 1])
{
    byte permutedHash[HASH_SIZE];

    permutedHash[2] = hash[0];
    permutedHash[5] = hash[1];
    permutedHash[8] = hash[2];
    permutedHash[11] = hash[3];
    permutedHash[14] = hash[4];
    permutedHash[12] = hash[5];
    permutedHash[1] = hash[6];
    permutedHash[4] = hash[7];
    permutedHash[7] = hash[8];
    permutedHash[10] = hash[9];
    permutedHash[13] = hash[10];
    permutedHash[15] = hash[11];
    permutedHash[0] = hash[12];
    permutedHash[3] = hash[13];
    permutedHash[6] = hash[14];
    permutedHash[9] = hash[15];

    int sixByteCount = 0;
    byte sixBitHash[SIX_BYTE_HASH];

    for (int i = 0; i < HASH_SIZE; i += 3) {
        byte a = (permutedHash[i] & 0xC0) >> 6;
        byte b = (permutedHash[i] & 0x3F);
        byte c = 0;
        byte d = 0;
        byte e = 0;
        byte f = 0;
        if (i != 15) {
            c = ((permutedHash[i + 1] & 0xF0) >> 4);
            d = (permutedHash[i + 1] & 0x0F) << 2;
            e = (permutedHash[i + 2] & 0xFC) >> 2;
            f = (permutedHash[i + 2] & 0x03) << 4;
        }
        sixBitHash[sixByteCount] = b;
        if (i != 15) {
            sixBitHash[sixByteCount + 1] = a | d;
            sixBitHash[sixByteCount + 2] = c | f;
            sixBitHash[sixByteCount + 3] = e;
        } else {
            sixBitHash[SIX_BYTE_HASH - 1] = a;
        }
        sixByteCount += 4;
    }

    for (int i = 0; i < PW_HASH_LIMIT; i++) {
        result[i] = pwCode64[sixBitHash[i]];
    }
}

/**
 * Given a password and a salt string, this function computes an MD5 hash of the password and stores it in 
 * the result array.
 * @param 
 */
void hashPassword(char const pass[], char const salt[SALT_LENGTH + 1], char result[PW_HASH_LIMIT + 1])
{
    byte altHash[HASH_SIZE];

    byte intHash[HASH_SIZE];

    computeAlternateHash(pass, salt, altHash);

    computeFirstIntermediate(pass, salt, altHash, intHash);

    for (int i = 0; i < PW_ITERATIONS; i++) {
        computeNextIntermediate(pass, salt, i, intHash);
    }

    hashToString(intHash, result);
}