#!/usr/bin/env python3
from typing import Tuple

# Feel free to import anything you need from the standard library.
import oracle
import crypto

# We need to go through every possible combination a valid forgery key could be
import math

# This function takes in a hash tag, then separates it into 5 memory/hex addresses
# These hex addresses are then turned into integers, which can be passed into 
# function sha1.hexdigest() to set the addresses used for calculating the new hash 
def getIntListFromHash(hash):
    real_tag_bytes = bytes(hash, 'utf-8')
    tagSegment = int(len(real_tag_bytes) * 0.2)
    print(f'realTagBytes: {real_tag_bytes[:tagSegment]} {real_tag_bytes[tagSegment:tagSegment*2]} {real_tag_bytes[tagSegment*2:tagSegment*3]} {real_tag_bytes[tagSegment*3:tagSegment*4]} {real_tag_bytes[tagSegment*4:]}')

    # We need an array for the initial memory addresses used in the hash function
    real_tag_hex = []   
    for i in range(0,5):
        real_tag_hex.append(int(real_tag_bytes[tagSegment*i:tagSegment*(i+1)], 16))
    print(f'tag  hex: {real_tag_hex}')
    return real_tag_hex

def main(message: bytes, injection: bytes) -> Tuple[bytes, str]:
    """ 
    Your goal is to bypass the oracle's integrity check.

    This will break UF-CMA security of the scheme and demonstrate a length
    extension attack on the underlying SHA1 hash function, which relies on the
    Merkle-Damgard construction internally.

    Specifically, you must somehow craft a message that includes the given
    parameter WITHIN the default message AND find a valid tag for it WITHOUT
    querying the oracle.

    The attack should be able to inject any message you want, but we want you
    to include your username (as bytes) specifically.
    """
    # Get original tag, prints out original message and tag
    original_tag = oracle.query(message)

    # Get initial sha1 state by parsing digest
    target_state = getIntListFromHash(original_tag)

    # We need to check every possible length of a key, from length 0 to 100 
    for key_length in range(0,101):

        # First, let's make an object that can handle our sha1 hashing for us
        sha1 = crypto.Sha1()

        # Create message payload with unknown key of "x * key_length" with original message appended
        # 'x' can be swapped out for any valid character byte
        original_message = (b'x' * key_length) + message

        # Pad this message, removing key from beginning of the string (returning original message + padding for key+message)
        padded_original = sha1.pad_message(original_message)[key_length:]

        # Create our new message string, the original message padded plus injection
        new_message = padded_original + injection

        # Create a hash using extra padding and intial state
        offset = int(math.ceil((len(padded_original) + key_length) * 8 / 512)) * 64  

        new_hash = sha1.sha1(injection, extra_length=offset, initial_state=target_state)
        # The new hash function uses the following formula to determine padding for the new hash:
        # l = (len(message) + extra_length) * 8
        # l2 = ((l // 512) + 1) * 512 # Explained in following steps:
        # //1. Take "8*l", divide it by 512 and round down to the nearest int 
        # //2. Add 1 to this value 
        # //3. Multiply result by 512
        # padding_length = l2 - l

        # If the hash works, return it
        if oracle.check(new_message, new_hash):
            # For debugging/myself:
            # print(f'   original tag: {original_tag}')
            # print(f'  initial state: {target_state}')
            # print(f'   extra length: {offset}')
            # print(f'origin  message: {original_message}')
            # print(f'padded original: {padded_original}')
            # print(f'    new message: {new_message}')
            # print(f'       new hash: {new_hash}')
            # print(f'     key length: {key_length}')
            return new_message, new_hash
 
    return new_message, new_hash 