#!/bin/bash
# This is a shell script to check your program(s) on test cases.
# It usese the same language you normally use to type commands in
# a terminal window.  You can write whole programs in shell.

# Assume we've succeeded until we see otherwise.
FAIL=0

# Print an error message and set the fail flag.
fail() {
    echo "**** $1"
    FAIL=1
}

# Check the exit status.  The actual exit status (ASTATUS) should match
# the expected status (ESTATUS)
checkStatus() {
    ESTATUS="$1"
    ASTATUS="$2"

    # Make sure the program exited with the right exit status.
    if [ "$ASTATUS" -ne "$ESTATUS" ]; then
	fail "FAILED - incorrect program exit status. (expected $ESTATUS,  Got: $ASTATUS)"
	return 1
    fi

    return 0
}

# Check the contents of an a file.  If the expected file (EFILE)
# exists, then the actual file (AFILE) should exist and it should match.
checkFile() {
    NAME="$1"
    EFILE="$2"
    AFILE="$3"

    # Make sure we're really expecting this file.
    if [ ! -f "$EFILE" ]; then
	return 0
    fi

    # Make sure the output matches the expected output.
    echo "   diff $EFILE $AFILE"
    diff -q "$EFILE" "$AFILE" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	fail "FAILED - $NAME ($AFILE) doesn't match expected ($EFILE)"
	return 1
    fi

    return 0
}

# Same as checkFile, but if the expected file (EFILE) doesn't exist, the
# actual file (AFILE) should be empty.
checkFileOrEmpty() {
    NAME="$1"
    EFILE="$2"
    AFILE="$3"

    # if the expected output file doesn't exist, the actual file should be
    # empty.
    if [ ! -f "$EFILE" ]; then
	if [ -s "$AFILE" ]; then
	    fail "FAILED - $NAME ($AFILE) should be empty."
	    return 1
	fi
	return 0
    fi

    # Make sure the output matches the expected output.
    echo "   diff $EFILE $AFILE"
    diff -q "$EFILE" "$AFILE" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	fail "FAILED - $NAME ($AFILE) doesn't match expected ($EFILE)"
	return 1
    fi

    return 0
}

# Same as checkFile, but if the expected file (EFILE) doesn't exist, the
# actual file (AFILE) should not exist.
checkFileOrDNE() {
    NAME="$1"
    EFILE="$2"
    AFILE="$3"
    
    # if the expected output file doesn't exist, the actual file should not exist
    if [ ! -f "$EFILE" ]; then
	if [ -f "$AFILE" ]; then
	    fail "FAILED - $NAME ($AFILE) should not exist."
	    return 1
	fi
	return 0
    fi

    # Make sure the output matches the expected output.
    echo "   diff $EFILE $AFILE"
    diff -q "$EFILE" "$AFILE" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	fail "FAILED - $NAME ($AFILE) doesn't match expected ($EFILE)"
	return 1
    fi

    return 0
}

# The given file should exist but should be empty.
checkEmpty() {
    NAME="$1"
    AFILE="$2"
    
    if [ -s "$AFILE" ]; then
	fail "FAILED - $NAME ($AFILE) should be empty."
	return 1
    fi

    return 0
}

# Test the ident program.
runTest() {
    TESTNO=$1
    ESTATUS=$2

    echo "Test $TESTNO"
    rm -f stdout.txt stderr.txt

    echo "   ./crack ${args[@]} > stdout.txt 2> stderr.txt"
    ./crack ${args[@]} > stdout.txt 2> stderr.txt
    ASTATUS=$?

    if ! checkStatus "$ESTATUS" "$ASTATUS" ||
       ! checkFile "Terminal output" "expected-$TESTNO.txt" "stdout.txt" ||
       ! checkFileOrEmpty "Stderr output" "error-$TESTNO.txt" "stderr.txt"
    then
	return 1
    fi

    echo "Test $TESTNO PASS"
    return 0
}

# Try the unit tests
make clean
make unitTest

if [ -x unitTest ]
then
    if ./unitTest
    then
       echo "Unit tests executed successfully"
    else
	fail "Unit tests didn't execute successfully";
    fi
else
    fail "Unit tests didn't build successfully";
fi

# make a fresh copy of the target programs
make crack

if [ $? -ne 0 ]; then
    fail "Make exited unsuccessfully"
fi

# Run test cases
if [ -x crack ]; then
    args=(dictionary-01.txt shadow-01.txt)
    runTest 01 0
    
    args=(dictionary-02.txt shadow-02.txt)
    runTest 02 0
    
    args=(dictionary-03.txt shadow-03.txt)
    runTest 03 0
    
    args=(dictionary-04.txt shadow-04.txt)
    runTest 04 0
    
    args=(dictionary-05.txt shadow-05.txt)
    runTest 05 0
    
    args=(dictionary-06.txt shadow-06.txt)
    runTest 06 0
    
    args=(dictionary-07.txt shadow-07.txt)
    runTest 07 0
    
    args=(dictionary-08.txt shadow-08.txt)
    runTest 08 1
    
    args=(dictionary-09.txt shadow-09.txt)
    runTest 09 1
    
    args=(dictionary-10.txt shadow-10.txt)
    runTest 10 1
    
    args=(dictionary-11.txt shadow-11.txt)
    runTest 11 1
    
    args=(dictionary-12.txt missing-shadow-12.txt)
    runTest 12 1
    
    args=(-extra dictionary-13.txt shadow-13.txt)
    runTest 13 1
    
else
    fail "Since your program didn't compile, no tests were run."
fi

if [ $FAIL -ne 0 ]; then
  echo "FAILING TESTS!"
  exit 13
else 
  echo "TESTS SUCCESSFUL"
  exit 0
fi
