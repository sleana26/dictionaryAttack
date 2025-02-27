/**
   @file magic.h
   @author CSC230 Instructors
   Header for isolating magic numbers and type definitions 
 */

#ifndef _MAGIC_H_
#define _MAGIC_H_

/** Type used to represent a byte. */
typedef unsigned char byte;

/** Type used to represent a 32-bit unsigned int. */
typedef unsigned int word;

/** Size of a block of data processed by md5. */
#define BLOCK_SIZE 64

/** Size of a block, measured in 4-byte words. */
#define BLOCK_WORDS ( BLOCK_SIZE / sizeof( word ) ) 

/** Within each iteration of MD5, how many bits left do we rotate the
    a value? */
extern int md5Shift[ BLOCK_SIZE ];

/** Constants, to mix in some random-looking bits during the MD5
    calculation.  These are computed from the sin() function.  They're
    examples of what might be called "Nothing-Up-My-Sleeve"
    numbers. */
extern word md5Noise[ BLOCK_SIZE ];

// Initial values for the four words, a, b, c, d, in the md5 state.
extern word md5Initial[];

/** Permutation of the final MD5 hash array used to create the password
    hash. */
extern int pwPerm[];

/** Characters used to encode the final, permuted MD5 hash array, with 6
    bits represented by each character. */
extern char pwCode64[];

#endif
