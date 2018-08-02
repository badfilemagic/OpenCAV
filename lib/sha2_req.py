#!/usr/bin/env python3
import sys, os, re
sys.path.append('.')
from lib.algs import SHA2


class UnknownArgError(Exception):
    pass

class Sha2ReqParser:
    """
    Parse a SHA1 req file
    """
    def __init__(self):
        self.req = ""
        self.ops = []
        self.mdlen = 0
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
        for elm in req.split("\n\n"):
            if re.search('CAVS', elm) is not None:
                pass
            elif re.search('^\[L = \d+\]$', elm) is not None:
                a,b = elm.split(" = ")
                self.mdlen = int(b[:-1])
            elif elm == "":
                pass
            else:
                sha2 = SHA2()
                sha2.mdlen = self.mdlen
                fields = elm.splitlines(keepends=False)
                for f in fields:
                    o,a = f.split(" = ")
                    if "Len" in o:
                        sha2.msglen = int(a)
                    elif "Msg" in o:
                        sha2.msg = a
                    elif "MD" in o:
                        sha2.md = a
                    else:
                        assert False, "Unknown element: {}".format(o)
                self.ops.append(sha2)


