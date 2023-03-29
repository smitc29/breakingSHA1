# breakingSHA1
Sample code used to demonstrate the vulnerabilities of the SHA-1 encryption scheme with a 64-bit key.

To run this project, from the command line use "python grader.py [injectionMessage]". This will generate a random key value for this attempt, in addition to injecting your target message into another message. The default message is defined on line 15 of 'grader.py'. 

If the program gives an error message, please check crypto.py. The sha1() function might be
giving you issues. 
