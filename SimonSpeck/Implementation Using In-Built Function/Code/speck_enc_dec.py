#Written by Aritra Ray

#the library was installed using
#pip3 install simonspeckciphers

#importing the ciphers
from speck import SpeckCipher


#initialising the cipher object that is an encyption key
my_speck = SpeckCipher(0xABC125)
#here we initialized with an encryption key of 11256101
#that is, 0xABC125 when converted to hexadecimal


#my_plaintext contains the text that is to be encrypted
my_plaintext = 0x111
#Say, we want to encrypt 273. 
#We have thus entered 0x111, which is the hexadecimal value for 273


#encrypt() is the function by which the plaintext gets converted to ciphertext
speck_ciphertext = my_speck.encrypt(my_plaintext)
print("The encrypted message is")
print(speck_ciphertext)
#the encrypted message was displayed


#decrypt() is the function by which the ciphertext gets converted to plaintext
speck_plaintext = my_speck.decrypt(speck_ciphertext)
print("The decrypted message is")
print(speck_plaintext)
#the decrypted message was displayed
