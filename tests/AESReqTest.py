import unittest
import os, sys
sys.path.append("..\lib")
from aes_req import AesReqParser


class AESRespTest(unittest.TestCase):
    def test_1(self):
        p = AesReqParser()
        p.ingest("CBCMCT128.rsp")
        self.assertEqual(100, len(p.eops))
        self.assertEqual(100, len(p.dops))