# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from base64 import b64encode, b64decode
from urllib import quote_plus, unquote_plus
from hashlib import new, md5, sha1, sha224, sha256, sha384, sha512
from binascii import hexlify
from string import ascii_uppercase
from random import choice
from Crypto.PublicKey import RSA 

"""
This function receives a text and encodes it directly into the other formats.
"""
def encode_ascii(text):
    try:
        b64_text = b64encode(text.encode())
        url_text = quote_plus(text)
        hex_text = text.encode('hex')
        return {'ascii':text, 'base64':b64_text, 'url':url_text, 'hex':hex_text}
    except:
        return {'ascii':'The text has an error.', 'base64':'', 'url':'', 'hex':''}


"""
This function receives a base64 text, encodes it into ascii-format and uses this new
text to encode into the other formats.
"""
def encode_base64(text):
    try:
        ascii_text = b64decode(text.encode())
        url_text = quote_plus(ascii_text)
        hex_text = ascii_text.encode('hex')
        return {'ascii':ascii_text, 'base64':text, 'url':url_text, 'hex':hex_text}
    except:
        return {'ascii':'', 'base64':'The text has an error.', 'url':'', 'hex':''}


"""
This function receives an url text, encodes it into ascii-format and uses this new
text to encode into the other formats.
"""
def encode_url(text):
    try:
        ascii_text = unquote_plus(text)
        b64_text = b64encode(ascii_text.encode())
        hex_text = ascii_text.encode('hex')
        return {'ascii':ascii_text, 'base64':b64_text, 'url':text, 'hex':hex_text}
    except:
        return {'ascii':'', 'base64':'', 'url':'The text has an error.', 'hex':''}
    

"""
This function receiives an hex text, encodes it into ascii-format and uses this new 
text to encode into the other formats.
"""
def encode_hex(text):
    try:
        ascii_text = text.decode('hex')
        b64_text = b64encode(ascii_text.encode())
        url_text = quote_plus(ascii_text)
        return {'ascii':ascii_text, 'base64':b64_text, 'url':url_text, 'hex':text}
    except:
        return {'ascii':'', 'base64':'', 'url':'', 'hex':'The text has an error.'}


"""
This text receives a simple text and calculates its hashes. The algorithms that this
function uses are: md4, md5, sha1, sha224, sha256, sha384, sha512 and ntlm.
"""
def get_hashes(text):
    md4_hash = new('md4', text.encode('utf-16le')).hexdigest()
    md5_hash = md5(text).hexdigest()
    ntlm = hexlify(md4_hash)
    sha1_hash = sha1(text).hexdigest()
    sha224_hash = sha224(text).hexdigest()
    sha256_hash = sha256(text).hexdigest()
    sha384_hash = sha384(text).hexdigest()
    sha512_hash = sha512(text).hexdigest()
    return {'hash_text':text, 'md4':md4_hash, 'md5':md5_hash, 'sha1':sha1_hash, 'sha224':sha224_hash, 
            'sha256':sha256_hash, 'sha384':sha384_hash, 'sha512':sha512_hash, 'ntlm':ntlm}


"""
All the cryptographic functions return a dictionary, but this can change depending on the mode
(encrypt/decrypt). This also changes depending on the state of execution, if an error ocurred,
the message goes in the dictionary. That's why it's necessary to make a specific function for this
(if I leave it in each function, the code grows a lot)
"""
def returnDict(clear_name, encrypted_name, key_name, text, new_text, key, mode):
    if mode == 'encrypt':
        return {clear_name:text, encrypted_name:new_text, key_name:key}
    else:
        return {clear_name:new_text, encrypted_name:text, key_name:key}


"""
This function implements the classic cryptographic algorythm "Caesar cipher".
Gets the key modulus to get the real key. 
Calculates the new key wether if it is encrypting or decrypting.
Adds (or substracts) to get the new character.
"""
def caesar(mode, text, key):
    try:
        key_int = int(key)%26
        message = list(text.upper())
        key_int = key_int if mode == "encrypt" else (26-key_int)
        for i in range(len(message)):
            if message[i] not in ascii_uppercase:
                continue
            if ord(message[i])+key_int <= 90:
                message[i] = chr(ord(message[i])+key_int) 
            else:
                message[i] = chr(ord(message[i])-(26-key_int))
        new_text = ''.join(message)
        return returnDict('clear_caesar','encrypted_caesar','key_caesar', text, new_text, key, mode)
    except:
        return returnDict('clear_caesar','encrypted_caesar','key_caesar', text, 'An error occurred.', key, mode)


"""
Uses an alphabet specified by the user. First of all, the functions verifies if the
alphabet is correct.
After that, generates a dictionary assigning each letter of the real alphabet to the
user-defined one.
It also generates the inverse alphabet (value -> key into key -> value) in the dictionary.
"""
def monoalphabetic(mode, text, key):
    try:
        cipher = {}
        inverse_cipher = {}
        text = text.upper()
        new_text = []
        #Checks if the key has the correct format
        new_key = key.upper()
        if len(new_key) != 26 or len(new_key) > len(set(new_key)):
            raise ValueError('The key must have 26 unique chars.')
        for l in new_key:
            if l not in ascii_uppercase:
                raise ValueError('The key must only have letters.')

        #Generates the dictionaries to work
        for i in range(26):
            cipher[ascii_uppercase[i]] = new_key[i]
        for k, v in cipher.iteritems():
            inverse_cipher[v] = k
        #Encrypts
        for letter in text:
            if letter not in ascii_uppercase:
                new_text.append(letter)
            else:
                if mode == 'encrypt':
                    new_text.append(cipher[letter])
                else:
                    new_text.append(inverse_cipher[letter])
        #Returns result
        return returnDict('clear_monoalphabetic','encrypted_monoalphabetic','key_monoalphabetic', text, ''.join(new_text), new_key, mode)
    except Exception as e:
        return returnDict('clear_monoalphabetic','encrypted_monoalphabetic','key_monoalphabetic', text, e, new_key, mode)


"""
This function applies the classic Vigenere algorithm. Here, the key is a word, 
the longer the word, the safer the algorithm. 
"""
def vigenere(mode, text, key):
    try:
        new_text = []
        keyIndex = 0
        key = key.upper()
        text = text.upper()
        for letter in text:
            num = ascii_uppercase.find(letter.upper())
            if num != -1:
                if mode == 'encrypt':
                    num += ascii_uppercase.find(key[keyIndex])
                else:
                    num -= ascii_uppercase.find(key[keyIndex])
                num %= len(ascii_uppercase)
                new_text.append(ascii_uppercase[num])
                keyIndex += 1
                if keyIndex == len(key):
                    keyIndex = 0
            else:
                new_text.append(letter) 
        return returnDict('clear_vigenere','encrypted_vigenere','key_vigenere', text, ''.join(new_text), key, mode)
    except:
        return returnDict('clear_vigenere','encrypted_vigenere','key_vigenere', 'An error ocurred', ''.join(new_text), key, mode)


"""
Function used by the transposition function.
Adds a padding to the text, so its length is multiple of the key.
"""
def complete(text, key):
    while((len(text)%key) != 0):
        text += choice(ascii_uppercase)
    return text


"""
Function used by the transposition function.
Split a text into 'num' columns.
Return a list of columns (which are also lists)
"""
def splitCol(text, num):
    columns = ['']*num
    width = int(len(text)/num)
    first = 0
    end = width
    for i in range(num):
        for j in range(first,end):
            columns[i] += text[j]
        first += width
        end += width
    return columns


"""
Transposition encryption: used by the transposition function to encrypt.
First of all, adds the padding to the text if needed.
Writes the text into a list of lists (which are the columns).
Afetr than, joins the columns so the text is rearranged
"""
def trans_enc(text, key):
    text = complete(text.replace(" ",""),key).upper()
    columns = ['']*key
    j = 0
    for i in range(len(text)):
        columns[j] += text[i] #
        if j == (key-1):
            j = 0
        else:
            j += 1
    return ''.join(columns)


"""
Transposition decryption: used by the transposition function to decrypt.
Splits the encrypted text into columns.
Rewrites the text using a correct format.
"""
def trans_dec(text, key):
    columns = splitCol(text,key)
    text = ''
    for i in range(len(columns[0])):
        for column in columns:
            text +=  column[i] 
    return text


"""
This algorithm writes a text into columns and rewrites the text by columns so
all the characters are moved.
"""
def transposition(mode, text, key):
    try:
        if mode == "encrypt":
            new_text = trans_enc(text, int(key))
        else:
            new_text = trans_dec(text, int(key))
        return returnDict('clear_transposition','encrypted_transposition','key_transposition', text, new_text, key, mode)
    except:
        return returnDict('clear_transposition','encrypted_transposition','key_transposition', text, 'An error occurred.', key, mode)


def get_keypair(length):
    try:
        if length not in ['1024', '2048']:
            raise ValueError('The key does not have a valid length.')
        length = int(length)
        new_key = RSA.generate(length, e=65537) 
        pub_key = new_key.publickey().exportKey("PEM") 
        priv_key = new_key.exportKey("PEM") 
        return {'priv_key':priv_key, 'pub_key':pub_key}
    except Exception as e:
        return {'priv_key':e, 'pub_key':'An error occurred'}
