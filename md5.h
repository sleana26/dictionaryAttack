/** 
 * @file md5.h
 * @author Sean Leana (smleana)
 * This file is used as a helper to hash a password
 */

#ifndef _MD5_H_
#define _MD5_H_

#include "block.h"

/** Number of bytes in a MD5 hash */
#define HASH_SIZE 16

/** hashes with md5 */
void md5Hash( Block *block, byte hash[ HASH_SIZE ] );

#endif
