## CS3006- Network Security & Cryptography

#### Created a client and server application to provide confidentiality, authentication and integrity using socket programming and encrypted by RSA Algorithm and decrypted by AES variant..
*Client -*
*< input >*
Message: <>
Secret Key: <>
Public Key parameters: <p,q,e>
*< output >*
Encrypted Secret Key: <>
Cipher text intermediate computation process:
After Pre-round transformation:
Round key K0:
After Round 1 Substitute nibbles:
After Round 1 Shift rows:
After Round 1 Mix columns:
After Round 1 Add round key:
Round key K1:
After Round 2 Substitute nibbles:
After Round 2 Shift rows:
After Round 2 Add round key:
Round Key K2:
Cipher text: <>
Digest: <>
Digital Signature: <>

*Server -*
*< input >*
Public Key parameters: <p,q,e>
*< output >*
Decrypted Secret key: <>
Decryption Intermediate process:
After Pre-round transformation:
Round key K2:
After Round 1 InvShift rows::
After Round 1 InvSubstitute nibbles:
After Round 1 InvAdd round key:
Round key K1:
After Round 1 InvMix columns:
After Round 2 InvShift rows:
After Round 2 InvSubstitute nibbles
After Round 2 Add round key:
Round Key K0:
Decrypted Plaintext: <>
Message Digest: <>
Intermediate verification code: <>
Signature verified/ Signature Not Verified

### //Code

1. *Send_msg*: This function is used to share data b/w receiver and server.
2. *SubstituteNibble*: This function is used to generate substitution nibbles.
3. *key_generation*: This function generates key0,key1,key2 using SubstituteNibble function.
4. *DectoBin*: This function is used to convert a number to binary.
5. *m*: This function is used to initialize the plain text.
6. *AES_Encryption*: this function is used to implement AES variant for encrypting cipher text.
7. *getMd5*: Function used as Hash algorithm
8. *inverse*: To calculate inverse of r1 and r2
9. *RSA_Encryption*: RSA implementation
10. *RSA_Digital_Signature*: Generate signature using RSA algorithm
11. *AES_Decryption*: this function is used to implement AES variant for decrypting cipher text.
12. *gcd*: To calculate gcd of two numbers.
13. *pi*: Function to calculate value of phi
