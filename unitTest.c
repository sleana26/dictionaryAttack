/**
 @file unitTest.c
 @author CSC230 Instructors
 Unit test program for the block, md5 and password components.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "magic.h"
#include "block.h"
#include "md5.h"
#include "password.h"

/** Number of tests we should have, if they're all turned on. */
#define EXPECTED_TOTAL 60

/** Total number or tests we tried. */
static int totalTests = 0;

/** Number of test cases passed. */
static int passedTests = 0;

/** Macro to check the condition on a test case, keep counts of
    passed/failed tests and report a message if the test fails (but
    don't automatically terminate). */
#define TestCase( conditional ) {\
  totalTests += 1; \
  if ( conditional ) { \
    passedTests += 1; \
  } else { \
    printf( "**** Failed unit test on line %d of %s\n", __LINE__, __FILE__ );    \
  } \
}

/** Return true if A and B contain the same sequence of n bytes. */
bool cmpBytes( byte const A[], byte const B[], int n )
{
  for ( int i = 0; i < n; i++ )
    if ( A[ i ] != B[ i ] )
      return false;
  return true;
}

// These functions shouldn't be visible outside the md5 component, but
// we will leave them non-static so we can test them from an external
// unit test component.  We give prototypes here so the compiler won't
// complain when it sees us trying to call them below.
word fVersion0( word B, word C, word D );
word fVersion1( word B, word C, word D );
word fVersion2( word B, word C, word D );
word fVersion3( word B, word C, word D );
int gVersion0( int idx );
int gVersion1( int idx );
int gVersion2( int idx );
int gVersion3( int idx );
word rotateLeft( word value, int s );
void padBlock( Block *block );
void md5Iteration( word M[ 16 ], word *A, word *B,
                   word *C, word *D, int i );

// Here are similar declarations for the password component.
void computeAlternateHash( char const pass[],
                           char const salt[ SALT_LENGTH + 1 ],
                           byte altHash[ HASH_SIZE ] );
void computeFirstIntermediate( char const pass[],
                               char const salt[ SALT_LENGTH + 1 ],
                               byte altHash[ HASH_SIZE ],
                               byte intHash[ HASH_SIZE ] );
void computeNextIntermediate( char const pass[],
                              char const salt[ SALT_LENGTH + 1 ],
                              int inum,
                              byte intHash[ HASH_SIZE ] );
void hashToString( byte hash[ HASH_SIZE ], char result[ PW_HASH_LIMIT + 1 ] );

int main()
{
  // We're using conditional compilation code to turn on different
  // tests gradually.  As you finish parts of your implementation,
  // move the ifdef directive down past the blocks of code below (be
  // sure to put it between blocks, not in the middle of a block).
  // That will enable tests of various functions you're expected to
  // implement.



  ///////////////////////////////////////////////////////////////
  // Test the block component

  // Test constructor and appendByte()
  
  {
    Block *block = makeBlock();

    // Block should start out empty.
    TestCase( block->len == 0 );

    // Add a single byte to the end.
    appendByte( block, 0xA7 );
    TestCase( block->len == 1 );
    TestCase( block->data[ 0 ] == 0xA7 );
    
    freeBlock( block );
  }



  // Test the appendString() function
  
  {
    Block *block = makeBlock();

    // Add a short string.
    appendString( block, "abc" );

    {
      // Make sure the block contains a copy of the string.
      byte expected[] = { 0x61, 0x62, 0x63 };
      TestCase( block->len == 3 );
      TestCase( cmpBytes( block->data, expected, block->len ) );
    }
      
    // Add more characters to the string.
    appendString( block, "123" );

    {
      // Make sure the block contains a copy of the string.
      byte expected[] = { 0x61, 0x62, 0x63, 0x31, 0x32, 0x33 };
      TestCase( block->len == 6 );
      TestCase( cmpBytes( block->data, expected, block->len ) );
    }
      
    freeBlock( block );
  }


  ///////////////////////////////////////////////////////////////
  // Tests for the md5 component

  // Test the four versions of the F function
  
  {
    {
      word B = 0x00000001;
      word C = 0x00000003;
      word D = 0x00000007;
      word result;
      
      result = fVersion0( B, C, D );
      TestCase( result == 0x00000007 );
      
      result = fVersion1( B, C, D );
      TestCase( result == 0x00000001 );
      
      result = fVersion2( B, C, D );
      TestCase( result == 0x00000005 );
      
      result = fVersion3( B, C, D );
      TestCase( result == 0xFFFFFFFA );
    }

    {
      word B = 0xAB659F92;
      word C = 0xE4C6A120;
      word D = 0xC0D29093;
      word result;
      
      result = fVersion0( B, C, D );
      TestCase( result == 0xE0D68101 );
      
      result = fVersion1( B, C, D );
      TestCase( result == 0xA444B1B2 );
      
      result = fVersion2( B, C, D );
      TestCase( result == 0x8F71AE21 );
      
      result = fVersion3( B, C, D );
      TestCase( result == 0x5BAB5EDE );
    }
  }

  // Test the four versions of the G function
  
  {
    {
      int result;
      
      result = gVersion0( 7 );
      TestCase( result == 7 );
      
      result = gVersion0( 9 );
      TestCase( result == 9 );

      result = gVersion1( 12 );
      TestCase( result == 13 );

      result = gVersion1( 0 );
      TestCase( result == 1 );

      result = gVersion2( 4 );
      TestCase( result == 1 );
      
      result = gVersion2( 14 );
      TestCase( result == 15 );
      
      result = gVersion3( 8 );
      TestCase( result == 8 );
      
      result = gVersion3( 10 );
      TestCase( result == 6 );
    }
  }

  // Test the rotateLeft() function.
    
  {
    word result;
    
    result = rotateLeft( 0x00000001, 1 );
    TestCase( result == 0x00000002 );
    
    result = rotateLeft( 0x80000000, 1 );
    TestCase( result == 0x00000001 );

    
    result = rotateLeft( 0x6223818F, 3 );
    TestCase( result == 0x111C0C7B );

    
    result = rotateLeft( 0x9C913C27, 11 );
    TestCase( result == 0x89E13CE4 );
  }

  // Test the padBlock() function.
  
  {
    Block *block = makeBlock();
    appendString( block, "abc123" );

    padBlock( block );

    byte expected[] = { 0x61, 0x62, 0x63, 0x31, 0x32, 0x33, 0x80, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    TestCase( block->len == 64 );
    TestCase( cmpBytes( block->data, expected, block->len ) );
    
    freeBlock( block );
  }

  {
    Block *block = makeBlock();
    appendString( block, "The quick brown fox jumps over the lazy dog" );

    padBlock( block );

    byte expected[] = { 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63,
                        0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20,
                        0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70,
                        0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x74,
                        0x68, 0x65, 0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20,
                        0x64, 0x6F, 0x67, 0x80, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    TestCase( block->len == 64 );
    TestCase( cmpBytes( block->data, expected, block->len ) );
    
    freeBlock( block );
  }
  
  
  // Test the md5Iteration() function, a test for each round.
  
  {
    {
      word M[] =
        { 0x3E89FFA4U, 0x56AF8963U, 0x72B214EFU, 0x6E078ACEU,
          0x539FAB27U, 0x754D1F0AU, 0xBC496D95U, 0x11695FEFU,
          0xBA9ED1AAU, 0x192B3715U, 0x88D80898U, 0xAEE9F73EU,
          0x02F429EDU, 0x7E840F0BU, 0x498B4509U, 0xFA54CF37U };
      word A = 0x8C91FCE1U;
      word B = 0xa3DFC292U;
      word C = 0x1247C589U;
      word D = 0X5403C3DCU;
      md5Iteration( M, &A, &B, &C, &D, 0 );
      
      TestCase( A == 0x5403C3DC );
      TestCase( B == 0x0B11278E );
      TestCase( C == 0xA3DFC292 );
      TestCase( D == 0x1247C589 );
    }

    {
      word M[] =
        { 0x7D7B9A46U, 0xB7851D52U, 0xECCDFCF2U, 0x4F0192C4U,
          0xB4587C78U, 0x149D9A7BU, 0xF24026F6U, 0x867C8D4FU,
          0x044D387CU, 0xBEEC6302U, 0x3103F912U, 0xEB240372U,
          0x688E8689U, 0x86566ADFU, 0xD4D78755U, 0x3ABE596BU };
      word A = 0x36F3E5FEU;
      word B = 0xF7CC2E7DU;
      word C = 0xC6CF8729U;
      word D = 0xF369EB5CU;
      md5Iteration( M, &A, &B, &C, &D, 21 );

      TestCase( A == 0xF369EB5C );
      TestCase( B == 0x0C0FEF41 );
      TestCase( C == 0xF7CC2E7D );
      TestCase( D == 0xC6CF8729 );
    }

    {
      word M[] =
        { 0x7998A7E9U, 0xD67277FFU, 0xB6CFE5D6U, 0x42B44CAEU,
          0xA0B8C114U, 0x606240D3U, 0xAF64D1C9U, 0x51E7D5CAU,
          0x2CD988C3U, 0x647164DAU, 0xB42C169AU, 0x27710515U,
          0xD442D6F8U, 0xC51BA1A9U, 0x54ECBB60U, 0xC34B15D8U };
      word A = 0x67F629DFU;
      word B = 0x8E302042U;
      word C = 0x8C198D10U;
      word D = 0x9ADE4754U;
      md5Iteration( M, &A, &B, &C, &D, 38 );
      
      TestCase( A == 0x9ADE4754 );
      TestCase( B == 0xC33F69D3 );
      TestCase( C == 0x8E302042 );
      TestCase( D == 0x8C198D10 );
    }

    {
      word M[] =
        {
         0xEA4902D6U, 0x6B7E4628U, 0xAAA617A2U, 0xE1D86531U,
         0x09107730U, 0xE98F9D4BU, 0x3ACC9173U, 0xC006C27AU,
         0xB9B3044DU, 0x7F809884U, 0x62D9856DU, 0xCEB1E48AU,
         0xC1B33EA0U, 0x45AFC5EEU, 0x5C22A633U, 0x944E0062U
        };
      word A = 0xC5F26E0AU;
      word B = 0x9BA81115U;
      word C = 0x8C0C4CD4U;
      word D = 0x665F2162U;
      md5Iteration( M, &A, &B, &C, &D, 59 );
      
      TestCase( A == 0x665F2162 );
      TestCase( B == 0xB7F63AF0 );
      TestCase( C == 0x9BA81115 );
      TestCase( D == 0x8C0C4CD4 );
    }
  }

  // Test the md5Hash() function.
  
  {
    Block *block = makeBlock();
    appendString( block, "The quick brown fox jumps over the lazy dog" );
    
    byte hash[ HASH_SIZE ];
    md5Hash( block, hash );

    // Make sure we got the right hash value back.
    byte expected[] = { 0x9E, 0x10, 0x7D, 0x9D, 0x37, 0x2B, 0xB6, 0x82,
                        0x6B, 0xD8, 0x1D, 0x35, 0x42, 0xA4, 0x19, 0xD6 };
    TestCase( cmpBytes( hash, expected, sizeof( hash ) ) );

    freeBlock( block );
  }


  {
    Block *block = makeBlock();
    appendString( block, "The quick brown fox jumps over the lazy dog." );
    
    byte hash[ HASH_SIZE ];
    md5Hash( block, hash );

    // Make sure we got the right hash value back.
    byte expected[] = { 0xE4, 0xD9, 0x09, 0xC2, 0x90, 0xD0, 0xFB, 0x1C,
                        0xA0, 0x68, 0xFF, 0xAD, 0xDF, 0x22, 0xCB, 0xD0 };
    TestCase( cmpBytes( hash, expected, sizeof( hash ) ) );
    
    freeBlock( block );
  }

  {
    Block *block = makeBlock(); // Empty block.
    
    byte hash[ HASH_SIZE ];
    md5Hash( block, hash );

    // Make sure we got the right hash value back.
    byte expected[] = { 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
                        0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E };
    TestCase( cmpBytes( hash, expected, sizeof( hash ) ) );
    
    freeBlock( block );
  }

  ///////////////////////////////////////////////////////////////
  // Test the password component

  // test the computeAlternateHash() function
  
  {
    // This test matches the call to computeAlternateHash() for the
    // first pair of test input files.
    char pass[] = "abc123";
    char salt[ ] = "abcdefgh";
    byte altHash[ HASH_SIZE ];
    
    computeAlternateHash( pass, salt,  altHash );

    // Make sure we got the right hash value.
    byte expected[] = { 0xA2, 0x8F, 0x9B, 0xD8, 0xA8, 0x6E, 0xB0, 0x0F,
                        0xE8, 0xE8, 0x52, 0x18, 0x1E, 0x4F, 0xB0, 0x04 };
    TestCase( cmpBytes( altHash, expected, HASH_SIZE ) );
  }

  {
    // This test matches a call to computeAlternateHash() for the
    // second pair of test input files.
    char pass[] = "password";
    char salt[ ] = "rVu9zC1N";
    byte altHash[ HASH_SIZE ];

    computeAlternateHash( pass, salt,  altHash );

    // Make sure we got the right hash value.
    byte expected[] = { 0x19, 0xB0, 0x1F, 0x09, 0x8B, 0x98, 0x1B, 0xB1,
                        0x4C, 0xE7, 0x58, 0xB4, 0x3E, 0x3F, 0x57, 0x40 };
    TestCase( cmpBytes( altHash, expected, HASH_SIZE ) );
  }

  // test the computeFirstIntermediate() function
    
  {
    // This test matches the call to computeFirstIntermediate() for the
    // first pair of test input files.
    char pass[] = "abc123";
    char salt[ ] = "abcdefgh";
    byte altHash[] = { 0xA2, 0x8F, 0x9B, 0xD8, 0xA8, 0x6E, 0xB0, 0x0F,
                       0xE8, 0xE8, 0x52, 0x18, 0x1E, 0x4F, 0xB0, 0x04 };
    byte intHash[ HASH_SIZE ];

    computeFirstIntermediate( pass, salt, altHash, intHash );

    // Make sure we got the right hash value.
    byte expected[] = { 0x99, 0x93, 0x6D, 0x1D, 0x85, 0x61, 0x0E, 0xD7,
                        0xD4, 0xFC, 0x13, 0x62, 0x49, 0x38, 0x7B, 0xFF};
    TestCase( cmpBytes( intHash, expected, HASH_SIZE ) );
  }

  {
    // This test matches a call to computeFirstIntermediate() for the
    // second pair of test input files.
    char pass[] = "password";
    char salt[ ] = "rVu9zC1N";
    byte altHash[] = { 0x19, 0xB0, 0x1F, 0x09, 0x8B, 0x98, 0x1B, 0xB1,
                       0x4C, 0xE7, 0x58, 0xB4, 0x3E, 0x3F, 0x57, 0x40 };
    byte intHash[ HASH_SIZE ];

    computeFirstIntermediate( pass, salt, altHash, intHash );

    // Make sure we got the right hash value.
    byte expected[] = { 0xFE, 0x6F, 0x9D, 0x74, 0xEC, 0x09, 0x43, 0x86,
                        0x21, 0x47, 0x47, 0xB6, 0x9C, 0xD7, 0xD8, 0xFF };
    TestCase( cmpBytes( intHash, expected, HASH_SIZE ) );
  }

  // Test the computeNextIntermediate() function
 
  {
    // This test matches the first call to computeNextIntermediate()
    // for the first pair of test input files.
    char pass[] = "abc123";
    char salt[ ] = "abcdefgh";
    byte intHash[] = { 0x99, 0x93, 0x6D, 0x1D, 0x85, 0x61, 0x0E, 0xD7,
                       0xD4, 0xFC, 0x13, 0x62, 0x49, 0x38, 0x7B, 0xFF };
    
    computeNextIntermediate( pass, salt, 0, intHash );
    
    // Make sure we got the right hash value.
    byte expected[] = { 0x0A, 0xBF, 0x73, 0x98, 0x91, 0x22, 0xF7, 0x63,
                        0x92, 0xFA, 0x7E, 0xAC, 0x80, 0xA8, 0x2D, 0x7E };
    TestCase( cmpBytes( intHash, expected, HASH_SIZE ) );
  }

  {
    // This test matches the second call to computeNextIntermediate()
    // for the first pair of test input files.
    char pass[] = "abc123";
    char salt[ ] = "abcdefgh";
    byte intHash[] = { 0x0A, 0xBF, 0x73, 0x98, 0x91, 0x22, 0xF7, 0x63,
                       0x92, 0xFA, 0x7E, 0xAC, 0x80, 0xA8, 0x2D, 0x7E };
    
    computeNextIntermediate( pass, salt, 1, intHash );
    
    // Make sure we got the right hash value.
    byte expected[] = { 0x63, 0x82, 0x2B, 0x93, 0x74, 0xBF, 0xD1, 0x02,
                        0x64, 0xD1, 0x1A, 0xA2, 0xC5, 0xC8, 0xC9, 0x94 };
    TestCase( cmpBytes( intHash, expected, HASH_SIZE ) );
  }

  // Test the hashToString() function
  
  {
    // This test matches the call to hashToString() for the
    // first pair of test input files.
    byte hash[] = { 0x95, 0xA7, 0x2B, 0x5F, 0x1F, 0x2D, 0xB6, 0x4A,
                    0x07, 0xC9, 0xBF, 0xCB, 0xD8, 0x95, 0x86, 0x8B };
    char result[ PW_HASH_LIMIT + 1 ];
    
    hashToString( hash, result );
    
    // Make sure we got the right result.
    TestCase( strcmp( result, "MPPZJeod4Sk89awLhwv591" ) == 0 );
  }

  {
    // This test matches a call to hashToString() for the
    // first pair of test input files.
    byte hash[] = { 0xB2, 0x8B, 0xF1, 0xF1, 0xA1, 0x58, 0x05, 0xE3,
                    0x6E, 0x34, 0x74, 0xCF, 0x95, 0x43, 0xD1, 0x6F };
    char result[ PW_HASH_LIMIT + 1 ];
    
    hashToString( hash, result );
    
    // Make sure we got the right result.
    TestCase( strcmp( result, "JKUg1ByWFvKwjFHwMFLcD1" ) == 0 );
  }
 
  // Test the hashPassword() function
  
  {
    // This test matches the call to hashPassword() in the first pair
    // of test input files.
    char pass[] = "abc123";
    char salt[ ] = "abcdefgh";
    char result[ PW_HASH_LIMIT + 1 ];
    
    hashPassword( pass, salt,  result );
    
    // Make sure we got the right result.
    TestCase( strcmp( result, "MPPZJeod4Sk89awLhwv591" ) == 0 );
  }

  {
    // This test matches a call to hashPassword() in the
    // second pair of test input files.
    char pass[] = "password";
    char salt[ ] = "rVu9zC1N";
    char result[ PW_HASH_LIMIT + 1 ];
    
    hashPassword( pass, salt,  result );
    
    // Make sure we got the right result.
    TestCase( strcmp( result, "JKUg1ByWFvKwjFHwMFLcD1" ) == 0 );
  }
#ifdef DISABLE_TESTS
  // Once you move the #ifdef DISABLE_TESTS to here, you've enabled
  // all the tests.

#endif
  
 // Report a message if some tests are still disabled.
  if ( totalTests < EXPECTED_TOTAL )
    printf( "** %d of %d unit tests currently enabled.\n", totalTests,
            EXPECTED_TOTAL );

  // Exit successfully if all tests are enabled and they all pass.
  if ( passedTests != EXPECTED_TOTAL )
    return EXIT_FAILURE;
  else {
    printf( "** All unit tests passed\n" );
    return EXIT_SUCCESS;
  }
}
