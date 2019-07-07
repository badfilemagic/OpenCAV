# OpenCAV
OpenCAV is an open-source test harness for running CAVS (Cryptographic Algorithm Verification System) test vectors for the purpose of submission for evaluation to NIST's CAVP. This is done for both FIPS 140 and Common Criteria purposes.

# What
OpenCAV is written in Go. The Implementation Under Test can be written in Go, C, or C++. The 'cgo' module is used to wrap a C or C++ library for use by Go.

# before you begin
The CAVS tool only runs on Windows. As such, the text files that it generates are CRLF-delimited, which is a PITA.
Prior to running this tool, you'll want to fix the line endings. This can be done with the Bash one-liner (including on gitbash)
$ find . | grep -e '\.req$' | xargs sed -i 's/\r\n/\n/g'

From the root of your CAVS vectors. The above will also work in Git Bash on Windows.