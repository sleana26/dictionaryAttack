/** 
 * @file password.h
 * @author Sean Leana (smleana
 */

#ifndef _PASSWORD_H_
#define _PASSWORD_H_

/** Required length of the salt string. */
#define SALT_LENGTH 8

/** Maximum length of a password.  Just to simplify our program; passwords
    aren't really required to be this short. */
#define PW_LIMIT 15

/** Maximum length of a password hash string created by hashPassword() */
#define PW_HASH_LIMIT 22

/** Size of the 6byte hash arr */
#define SIX_BYTE_HASH 22

/** hashes the password given the pass salt and a result string
 * @return pass pass to hash
 * @return salt salt of the user
 * @return result result hash for the dictionary word entered
 */
void hashPassword( char const pass[], char const salt[ SALT_LENGTH + 1 ], char result[ PW_HASH_LIMIT + 1 ] );


#endif
