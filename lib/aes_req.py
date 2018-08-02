#!/usr/bin/env python3
import sys, os, re
sys.path.append('.')
from lib.algs import AES


class UnknownArgError(Exception):
    pass

class AesReqParser:
    """
    Parse an AES req file
    """
    def __init__(self):
        self.req = ""
        self.eops = []
        self.dops = []

    def ingest(self, fname):
        try:
            with open(fname, 'r') as fh:
                self.req = fh.read()
        except Exception as e:
            print("Error reading file: " + e, file=sys.stderr)
            os.exit(1)
        finally:
            self.parse(self.req)

    def parse(self, req):
        eop = None
        for elm in req.split("\n\n"):
            if re.search('CAVS', elm) is not None:
                pass
            elif re.search('ENCRYPT', elm) is not None:
                eop = True
            elif re.search('DECRYPT', elm) is not None:
                eop = False
            elif elm == "":
                pass
            else:
                fields = elm.splitlines(keepends=False)
                aes = AES()
                for f in fields:
                    try:
                        o,a = f.split(' = ')
                        if "COUNT" in o:
                            aes.count = int(a)
                        elif "KEY" in o:
                            aes.key = a
                        elif "IV" in o:
                            aes.iv = a
                        elif "PLAINTEXT" in o:
                            aes.pt = a
                        elif "CIPHERTEXT" in o:
                            aes.ct = a
                        else:
                            assert False, "unknown field {}".format(o)
                    except ValueError as e:
                        print("Error: {} working on '{}'".format(str(e), f))
                if eop:
                    aes.op = "ENCRYPT"
                    self.eops.append(aes)
                elif not eop and eop is not None:
                    aes.op = "DECRYPT"
                    self.dops.append(aes)
                else:
                    assert False, "Did not set an encrypt or decrypt operation in the req file?"

