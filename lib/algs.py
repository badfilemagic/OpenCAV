#!/usr/bin/env python3

class AES:
    """
    Describes the data associated with an AES operation vis-a-vis a CAVP test
    """
    def __init__(self, *args, **kwargs):
        self.count = 0
        self.key = b""
        self.iv= b""
        self.pt = b""
        self.ct = b""
        self.ans = b""
        self.op = b""


    def __str__(self):
        s = "COUNT: {}\nKEY: {}\nIV: {}\nPT: {}\nOP: {}".format(
            self.count,
            self.key,
            self.iv,
            self.pt,
            self.op)
        return s

class SHA2:
    def __init__(self):
        self.ddlen = 0
        self.msglen = 0
        self.msg = b""
        self.md = b""

    def __str__(self):
        s = "Digest Length: {}\nMessage Length: {}\nMessage: {}\nDigest: {}\n".format(
            self.dlen,
            self.mlen,
            self.msg,
            self.md
        )
        return s