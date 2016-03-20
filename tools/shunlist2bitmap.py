#!/usr/bin/env python
"""
Load ranges from file, edit bitmap file accordingly
Bitmap file must be seekable up to 1<<29 bytes.
Lines in the ranges file are processed if they are of the following forms:
  A 1.2.3.4
  D 1.2.3.4/24
  A 1.2.3.4-5.6.7.8
Where 'A' or 'D' means add or delete the range, respectively.
Anything after the range spec on a line is ignored.
Lines that don't start with a range spec are ignored.
"""

import sys
import os
import time
import socket
from bitarray import bitarray
import mdsutils as mds

def process_range_viabitarray(ba, ad, lo, hi):
    """
     bitfield is in network byte order, so we do updates bit-by-bit

     First consider bitwise operations on 0x01020304 (== 1.2.3.4)
     On big-endian architectures:
           ip = 0000 0001  0000 0010  0000 0011  0000 0100
     ip >> 3 -> 0000 0000  0010 0000  0100 0000  0110 0000
                    byte offset <- byte = outfil.seek(0x00204060)
     ip & 7  -> 0000 0000  0000 0000  0000 0000  0000 0100
                    bit in byte <- ison = byte & (1<<4)
     On little-endian architectures:
           ip = 0000 0001  0000 0010  0000 0011  0000 0100
     ip >> 3 -> 0100 0000  0110 0000  1000 0000  0000 0000
                    byte offset <- byte = outfil.seek(0x40608000)
     ip & 7  -> 0000 0001  0000 0000  0000 0000  0000 0000
                    bit in byte <- ison = byte & (1<<1)

     Now consider bitwise operations on 0x01020305 (== 1.2.3.5, above + 1)
     On big-endian architectures: consecutive IP == consecutive BIT
                        ip = 0000 0001  0000 0010  0000 0011  0000 0101
     ip >> 3 (== ABOVE)   -> 0000 0000  0010 0000  0100 0000  0110 0000
                    byte offset <- byte = outfil.seek(0x00204060)
     ip & 7  (== ABOVE+1) -> 0000 0000  0000 0000  0000 0000  0000 0101
                    bit in byte <- ison = byte & (1<<5)
     On little-endian architectures: NOT consecutive IP == consecutive BIT
                        ip = 0000 0001  0000 0010  0000 0011  0000 0101
     ip >> 3 (!= ABOVE)   -> 0100 0000  0110 0000  1010 0000  0000 0000
                    byte offset <- byte = outfil.seek(0x4060A000)
     ip & 7  (!= ABOVE+1) -> 0000 0001  0000 0000  0000 0000  0000 0000
                    bit in byte <- ison = byte & (1<<1)

     Could optimize by batching writes on big-endian systems.
     Could make bitfield portable by doing bitfield ops on
       ntohl() integers, but then the driver would have to
       ntohl() the packet's IP to check the bitfield.
     So the tradeoff is we get slower updates and
       non-portable bitfields, in exchange for avoiding
       htonl() overhead during packet filtering.
     So use normalized range files, representing the
       bitfield in text, to move bitfields around. <shrug>
     Would love to write a C version and compare
       performance.
    """
    for i in range(lo, hi+1):
        ba[socket.htonl(i)] = ad == 'a'

def main():
    """Usage: {} shunlist_file bitmap_file

    Where shunlist is a file with IPs, ranges, or CIDRs.
    The specified addresses will be 'A'dded or 'D'eleted:
        A 1.2.3.4
        D 1.2.3.4/24
        A 1.2.3.4-5.6.7.8
    The IP, range, or CIDR is only processed if it's the first thing
    on the line ...anything else is ignored.

    The bitmap file will be created if necessary, or else modified in
    place.
    """
    if not len(sys.argv) == 3 or not os.path.exists(sys.argv[1]):
        sys.stderr.write(main.__doc__.format(sys.argv[0]))
        sys.exit(1)

    ba = bitarray(endian='little')
    if os.path.exists(sys.argv[2]):
        sys.stderr.write("Reading existing bitfield from {}... ".format(
            sys.argv[2]))
        with open(sys.argv[2], "r") as outfil:
            outfil.seek(0, os.SEEK_END)
            if outfil.tell() != 1<<29:
                sys.exit("file is {} bytes (want {})".format(outfil.tell(),
                                                             1<<29))
            outfil.seek(0, os.SEEK_SET)
            ba.fromfile(outfil)
            if ba.length() != 1<<32:
                sys.exit("Bitfield size error: {} on disk, {} in core".format(
                    ba.length(), 1<<32))
    else:
        sys.stderr.write("Creating zero'd bitfield {}... ".format(
            sys.argv[2]))
        ba = bitarray(1<<32, endian='little')
        if ba.length() != 1<<32:
            sys.exit("in-core bitfield is {} bytes (want {})".format(
                ba.length(), 1<<32))
    sys.stderr.write("done.\n")

    sys.stderr.write("--------[ Begin timing\n")
    time_begin = time.clock()
    string_msg = ""
    sys.stderr.write("Updating bitfield from {}:\n".format(sys.argv[1]))
    with open(sys.argv[1]) as infil:
        lines = 0
        for line in infil:
            lines += 1
            ad, lo, hi = mds.range2lohi(line)
            if lo is None or hi is None:
                continue
            sys.stderr.write('\b'*len(string_msg))
            string_msg = "  Processing line {}, {} {:03}.{:03}.{:03}.{:03} - "
            string_msg += "{:03}.{:03}.{:03}.{:03}"
            string_msg = string_msg.format(lines, ad, *mds.ip2quad(lo)
                                           *mds.ip2quad(hi))
            sys.stderr.write(string_msg)
            process_range_viabitarray(ba, ad, lo, hi)
    sys.stderr.write("\nDone: bitfield updated in core.\n")
    sys.stderr.write("Writing updated bitfield to {}... ".format(sys.argv[2]))
    with open(sys.argv[2], "wb") as outfil:
        ba.tofile(outfil)
    sys.stderr.write("done.\n")
    time_diff = time.clock()-time_begin
    sys.stderr.write("--------[ {} ({}s)\n".format(
        mds.secs2duration(time_diff), time_diff))


if __name__ == '__main__':
    main()
