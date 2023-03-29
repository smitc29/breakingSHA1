import struct
import binascii

from typing import Union, List, Optional


class Sha1:
    """ Implements the SHA1 hash function [1].

    Emulates a barebones version of Python's `hashlib.hash` interface [2],
    providing the simplest parts:
        - update(data): adds binary data to the hash
        - hexdigest(): returns the hexed hash value for the data added thus far

    We ALSO provide some extra parameters to the hexdigest() method to make a
    length extension attack easier. However, you will still need to read the
    relevant sections of the RFC to understand how to use them.

    You can also ignore the interface entirely and use the static methods directly.

    [1]: https://tools.ietf.org/html/rfc3174.
    [2]: https://docs.python.org/3/library/hashlib.html.
    """


    def __init__(self, initial: Optional[Union[bytes, bytearray]] = None):
        self._buffer = bytearray()
        if initial is not None: self.update(initial)

    def update(self, data: Union[bytes, bytearray]):
        if not isinstance(data, (bytearray, bytes)):
            raise TypeError(f"expected bytes for data, got {type(data)}")

        self._buffer.extend(data)
        return self

    def hexdigest(self, extra_length=0, initial_state=None):
        tag = self.sha1(
            bytes(self._buffer),
            extra_length=extra_length,
            initial_state=initial_state)
        self.clear()
        return tag

    def clear(self):
        self._buffer = bytearray()

    #
    # You may (and probably do) want to access the SHA1 methods directly to
    # craft your exploit.
    #

    @staticmethod
    def create_padding(
        message: Union[bytearray, bytes],
        extra_length: Optional[int]=0   # should be 13 if not provided in forgery
    ) -> bytes:
        """ Creates message padding as described in
        https://tools.ietf.org/html/rfc3174#section-4
        """
        l = (len(message) + extra_length) * 8
        l2 = ((l // 512) + 1) * 512 # 1. Take "8*len(message)", divide it by 512 and round down to the nearest int 2. Add 1 to this value 3. Multiply result by 512
        padding_length = l2 - l

        # if extra_length > 0:
        #     print(f"\npadding calc for {message} of length {len(message)} with extra padding {extra_length}: l={l}, padding_length={padding_length}")
        
        if padding_length < 72:
            padding_length += 512
        assert padding_length >= 72, "padding too short"
        assert padding_length % 8 == 0, "padding not multiple of 8"

        # Encode the length and add it to the end of the message.
        zero_bytes = (padding_length - 72) // 8
        length = struct.pack(">Q", l)
        pad = bytes([0x80] + [0] * zero_bytes)

        return pad + length

    @staticmethod
    def pad_message(
        message: Union[bytes, bytearray],
        extra_length: Optional[int]=0   # should be 13 if not provided in forgery
    ) -> bytes:
        """ Actually pads the message via Sha1.create_padding,
        https://tools.ietf.org/html/rfc3174#section-4
        """
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError("expected bytes for message, got %s" % type(message))

        pad = Sha1.create_padding(message, extra_length)
        # print(f'message len: {len(message)}, pad length: {len(pad)}')
        message = message + pad
        assert (len(message) * 8) % 512 == 0, f"message bitlength ({len(message)}) not a multiple of 512"
        return message

    @staticmethod
    def sha1(
        message: bytes,
        initial_state: Optional[List[int]]=None,
        extra_length: Optional[int]=0   # IN BYTES, should be 13 if not provided in forgery
    ) -> str:
        """ Returns the 20-byte hex digest of the message.

        It's possible to override some of the SHA1 algorithm's internals using
        the keyword parameters.

        https://tools.ietf.org/html/rfc3174#section-6.1

        >>> Sha1.sha1(b"Hello, world!")
        '943a702d06f34599aee1f8da8ef9f7296031d699'
        """
        H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        if initial_state is not None:
            if len(initial_state) != 5 or \
               any(not isinstance(x, int) for x in initial_state):
                raise TypeError(f"expected list of 5 ints, got {initial_state}")
            H = initial_state
            # print(f'custom H/initial state: {initial_state}')
        # print(f"Mem addresses bef: {H}")
        # print(f"CryptMessage: {len(message)}")

        # pad according to the RFC (and then some, if specified)
        padded_msg = Sha1.pad_message(message, extra_length=extra_length)

        # break message into chunks
        M = [padded_msg[i:i+64] for i in range(0, len(padded_msg), 64)]
        assert len(M) == len(padded_msg) / 64
        for i in range(len(M)):
            assert len(M[i]) == 64  # sanity check
        # print(f"Initial M = {M}")

        # 'M' is an array; each value of 'M' is 64 bits, 
        # do hashing voodoo
        for i in range(len(M)):

            # This FOR loop groups every 4 characters into a single integer value
            # W is 16 values, M is strictly 64 characters
            W = [
                int.from_bytes(M[i][j:j+4], byteorder="big")
                for j in range(0, len(M[i]), 4)
            ]

            # if i > 0:
            # print(f"\nM at step {i+1}:{M[i]}")
            # print(f"W at step {i+1}:{W}")            

            assert len(W) == 16
            assert type(W[0]) == int
            assert W[0] == (M[i][0] << 24) + (M[i][1] << 16) + (M[i][2] << 8) + M[i][3]

            for t in range(16, 80):
                W.append(Sha1._S(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]))
            # print(f"W at step {i+1}:{W}")

            A, B, C, D, E = H
            for t in range(80):
                TEMP = (((((((Sha1._S(5, A) + Sha1._f(t, B, C, D)) & 0xFFFFFFFF) + E) & 0xFFFFFFFF) + W[t]) & 0xFFFFFFFF) + Sha1._K(t)) & 0xFFFFFFFF
                assert TEMP == (Sha1._S(5, A) + Sha1._f(t, B, C, D) + E + W[t] + Sha1._K(t)) & 0xFFFFFFFF
                E, D, C, B, A = D, C, Sha1._S(30, B), A, TEMP

            # print(H)
            H = [
                (H[0] + A) & 0xFFFFFFFF,
                (H[1] + B) & 0xFFFFFFFF,
                (H[2] + C) & 0xFFFFFFFF,
                (H[3] + D) & 0xFFFFFFFF,
                (H[4] + E) & 0xFFFFFFFF,
            ]

        # craft the hex digest
        # print(f"Mem addresses aft: {H}")
        th = lambda h: hex(h)[2:] # trimmed hex
        # print(f"final H: {H}") 
        temp0 = "0" * (8 - len(th(H[0]))) + th(H[0])
        temp1 = "0" * (8 - len(th(H[1]))) + th(H[1])
        temp2 = "0" * (8 - len(th(H[2]))) + th(H[2])
        temp3 = "0" * (8 - len(th(H[3]))) + th(H[3])
        temp4 = "0" * (8 - len(th(H[4]))) + th(H[4])
        # print(f" {H[0]} {H[1]} {H[2]} {H[3]} {H[4]}")
        # print(f" {th(H[0])} {th(H[1])} {th(H[2])} {th(H[3])} {th(H[4])}")
        # print(f" {temp0} {temp1} {temp2} {temp3} {temp4}")
        
        digest = ""
        # print(f"final H: {H}")
        for h in H:
            strh = hex(h)[2:]
            strh = "0" * (8 - len(strh)) + strh
            digest += strh
        # print(f'alt hex digest: {digest}')
        
        return "".join("0" * (8 - len(th(h))) + th(h) for h in H)
    
    @staticmethod
    def sha1NoPadding(
        message: bytes,
    ) -> str:
        """ 
        Returns the 20-byte hex digest of the message.
        It's possible to override some of the SHA1 algorithm's internals using
        the keyword parameters.
        """
        # break message into chunks
        M = [message[i:i+64] for i in range(0, len(message), 64)]
        assert len(M) == len(message) / 64
        for i in range(len(M)):
            assert len(M[i]) == 64  # sanity check
        # print(f"Initial M = {M}")

        # 'M' is an array; each value of 'M' is 64 bits, 
        # do hashing voodoo
        for i in range(len(M)):

            # This FOR loop groups every 4 characters into a single integer value
            # W is 16 values, M is strictly 64 characters
            W = [
                int.from_bytes(M[i][j:j+4], byteorder="big")
                for j in range(0, len(M[i]), 4)
            ]

            # if i > 0:
            # print(f"\nM at step {i+1}:{M[i]}")
            # print(f"W at step {i+1}:{W}")
            

            assert len(W) == 16
            assert type(W[0]) == int
            assert W[0] == (M[i][0] << 24) + (M[i][1] << 16) + (M[i][2] << 8) + M[i][3]

            for t in range(16, 80):
                W.append(Sha1._S(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]))
            # print(f"W at step {i+1}:{W}")

            A, B, C, D, E = H
            for t in range(80):
                TEMP = (((((((Sha1._S(5, A) + Sha1._f(t, B, C, D)) & 0xFFFFFFFF) + E) & 0xFFFFFFFF) + W[t]) & 0xFFFFFFFF) + Sha1._K(t)) & 0xFFFFFFFF
                assert TEMP == (Sha1._S(5, A) + Sha1._f(t, B, C, D) + E + W[t] + Sha1._K(t)) & 0xFFFFFFFF
                E, D, C, B, A = D, C, Sha1._S(30, B), A, TEMP

            # print(H)
            H = [
                (H[0] + A) & 0xFFFFFFFF,
                (H[1] + B) & 0xFFFFFFFF,
                (H[2] + C) & 0xFFFFFFFF,
                (H[3] + D) & 0xFFFFFFFF,
                (H[4] + E) & 0xFFFFFFFF,
            ]

        # craft the hex digest
        # print(f"Mem addresses aft: {H}")
        th = lambda h: hex(h)[2:] # trimmed hex
        # print(f"final H: {H}")
        temp0 = "0" * (8 - len(th(H[0]))) + th(H[0])
        temp1 = "0" * (8 - len(th(H[1]))) + th(H[1])
        temp2 = "0" * (8 - len(th(H[2]))) + th(H[2])
        temp3 = "0" * (8 - len(th(H[3]))) + th(H[3])
        temp4 = "0" * (8 - len(th(H[4]))) + th(H[4])
        # print(f" {H[0]} {H[1]} {H[2]} {H[3]} {H[4]}")
        # print(f" {th(H[0])} {th(H[1])} {th(H[2])} {th(H[3])} {th(H[4])}")
        # print(f" {temp0} {temp1} {temp2} {temp3} {temp4}")
        return "".join("0" * (8 - len(th(h))) + th(h) for h in H)

    @staticmethod
    def _f(t, B, C, D):
        if t >= 0 and t <= 19:    return ((B & C) | ((~B) & D)) & 0xFFFFFFFF
        elif t >= 20 and t <= 39: return (B ^ C ^ D) & 0xFFFFFFFF
        elif t >= 40 and t <= 59: return ((B & C) | (B & D) | (C & D)) & 0xFFFFFFFF
        elif t >= 60 and t <= 79: return (B ^ C ^ D) & 0xFFFFFFFF
        assert False

    @staticmethod
    def _K(t):
        if t >= 0 and t <= 19:    return 0x5A827999
        elif t >= 20 and t <= 39: return 0x6ED9EBA1
        elif t >= 40 and t <= 59: return 0x8F1BBCDC
        elif t >= 60 and t <= 79: return 0xCA62C1D6
        assert False

    @staticmethod
    def _S(n, X):
        assert n >= 0 and n < 32, "n not in range" # n is only 1, 5, or 30
        assert (X >> 32) == 0, "X too large" # X shifted over 32 bits to the right must be 0, aka X <= 2^32 aka X <= 4,294,967,296
        result = ((X << n) | (X >> (32-n))) & 0xFFFFFFFF # 1. Shifts first X value binary left by 'n' digits 2. Shifts second X value binary right by '32-n' digits  3. Applies bitwise OR to the two values 4. Applies bitwise AND to the values and all 1s (sanity check, can be ignored)
        assert (result >> 32) == 0, "result too large" # result shifted over 32 bits to the right must be 0, aka result <= 2^32 aka result <= 4,294,967,296
        return result
