#Written by Aritra Ray

#the library was installed using
#pip3 install simonspeckciphers

#importing the ciphers
from simon import SimonCipher


#initialising the cipher object that is an encyption key
my_simon = SimonCipher(0xABC125)
#here we initialized with an encryption key of 11256101
#that is, 0xABC125 when converted to hexadecimal


#my_plaintext contains the text that is to be encrypted
my_plaintext = 0x111
#Say, we want to encrypt 273. 
#We have thus entered 0x111, which is the hexadecimal value for 273


#encrypt() is the function by which the plaintext gets converted to ciphertext
simon_ciphertext = my_simon.encrypt(my_plaintext)
print("The encrypted message is")
print(simon_ciphertext)
#the encrypted message was displayed


#decrypt() is the function by which the ciphertext gets converted to plaintext
simon_plaintext = my_simon.decrypt(simon_ciphertext)
print("The decrypted message is")
print(simon_plaintext)
#the decrypted message was displayed
