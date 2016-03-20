#!/usr/bin/env python
"""Load IP range bitmap from file, print a list of ranges."""

import time
import sys
import os
import socket
import itertools
from bitarray import bitarray
import mdsutils as mds

def print_shunlist(ips):
    """Print a list of IPs as a shunlist."""
    if len(ips) == 0:
        print("# No IPs in this bitmap")
        return
    ips.append(None)  # last item doesn't get processed
    lo = ips[0]
    hi = lo - 1
    for ip in ips:
        if ip == hi+1:
            hi = ip
            continue
        if lo == hi:  # range is single IP
            print("A " + ".".join(str(x) for x in mds.ip2quad(lo)))
            print("A " + ".".join(str(x) for x in mds.ip2quad(lo)))
        elif mds.is_cidr(lo, hi):  # range is a natural CIDR
            print("A {}/{}".format(".".join(str(x) for x in mds.ip2quad(lo)),
                                   int(mds.cidr_bits(lo, hi))))
        else:  # range isn't special
            print("A {}-{}".format(".".join(str(x) for x in mds.ip2quad(lo)),
                                   ".".join(str(x) for x in mds.ip2quad(hi))))
        lo = ip
        hi = ip

if not len(sys.argv) == 2 or not os.path.exists(sys.argv[1]):
    sys.stderr.write("Usage: {} bitmap_file\n".format(sys.argv[0]))
    sys.exit(1)

def ba_bypage():
    """Enumerate blocked IPs in a bitmap by reading in and analyzing one
        memory page at a time."""
    pgsiz = 4096
    ips = {}
    sys.stderr.write("Reading bitmap from {}... ".format(sys.argv[1]))
    sys.stderr.flush()
    with open(sys.argv[1]) as infil:
        infil.seek(0, os.SEEK_END)
        if infil.tell() != 1<<29:
            sys.exit("bitmap file is {} bytes, expected {}.  bail\n".format(
                infil.tell(), 1<<29))
        infil.seek(0, os.SEEK_SET)
        offset = 0
        while offset < 1<<29:
            mds.twirl()
            ba = bytearray(infil.read(pgsiz))
            for b in ba:
                if b == 0:
                    offset += 1
                    continue
                ip_at_seek = offset << 3
                for bit in range(8):
                    ip = ip_at_seek + bit
                    mask = 1<<bit
                    if b & mask == 0:
                        continue
                    ips[socket.ntohl(ip)] = True
                offset += 1
    mds.del_twirl()
    sys.stderr.write("done.\n")
    sys.stderr.write("Creating normalized ranges... ")
    ips = ips.keys()
    ips.sort()
    sys.stderr.write("done.\n")
    print_shunlist(ips)


def show_progress(i, state):
    """Print progress message, overwriting previous."""
    state["STAT_STR"] = state["STAT_STR"] or ''
    state["TIME_START"] = state["TIME_START"] or time.clock()
    state["STATS_PER_SEC"] = state["STATS_PER_SEC"] or 20
    state["SKIP"] = state["SKIP"] or 10001
    if i <= 0 or i % state['SKIP'] != 0:
        return
    q = mds.ip2quad(i)
    time_diff = int(time.clock() - state['TIME_START'])
    time2end = (float(time_diff<<32)/i) - time_diff
    if time_diff > 0:
        state['SKIP'] = int(i/(state['STATS_PER_SEC']*time_diff))
        while state["SKIP"]%10 == 0 or state["SKIP"]%0xa == 0:
            state["SKIP"] -= 1
    else:
        time_diff = 1
    sys.stderr.write('\b'*len(state["STAT_STR"]))
    state["STAT_STR"] = "{:03}.{:03}.{:03}.{:03} -- {:>10}/{:<10d} in ".format(
        q[0], q[1], q[2], q[3], i+1, 1<<32)
    state["STAT_STR"] += "{} @{:>7} Hz, finish in {}...".format(
        mds.secs2duration(time_diff), int(i/time_diff),
        mds.secs2duration(time2end))
    sys.stderr.write(state["STAT_STR"])

def ba_bitbybit():
    """Enumerate blocked IPs in a bitmap by reading in the whole file and
        analyzing one bit at a time."""
    sys.stderr.write("Reading bitmap from {}...".format(sys.argv[1]))
    sys.stderr.flush()
    ba = bytearray()
    with open(sys.argv[1]) as infil:
        infil.seek(0, os.SEEK_END)
        if infil.tell() != 1<<29:
            sys.exit("bitmap file is {} bytes, expected {}.  bail\n".format(
                infil.tell(), 1<<29))
        infil.seek(0, os.SEEK_SET)
        ba = bytearray(infil.read())
    ba.append(0)
    sys.stderr.write(" done creating {}-length bytearray.\n".format(len(ba)))
    lo = None
    hi = None
    sys.stderr.write("Writing ranges to stdout... ")
    state = {'TIME_START': time.clock()}
    for i in itertools.count():
        if i > 1<<32:
            break
        show_progress(i, state)
        seek = socket.htonl(i) >> 3
        bit = 1 << (socket.htonl(i) & 7)
        if lo is None:  # not ending a range
            if ba[seek] & bit:  # start or continue a range
                lo = i
            continue
        hi = i-1  # found range - process!
        if lo == hi:  # range is single IP
            print(".".join(str(x) for x in mds.ip2quad(lo)))
        elif mds.is_cidr(lo, hi):  # range is a natural CIDR
            print("{}/{}".format(".".join(str(x) for x in mds.ip2quad(lo)),
                                 int(mds.cidr_bits(lo, hi))))
        else:  # range isn't special
            print("{}-{}".format(".".join(str(x) for x in mds.ip2quad(lo)),
                                 ".".join(mds.ip2quad(hi))))
        lo = None
        hi = None
    sys.stderr.write(" done.\n")


def ba_forwardsearch():
    """Enumerate blocked IPs in a bitmap by reading in the whole file and
        asking the bitarray module to find the next on bit."""
    sys.stderr.write("Reading bitmap from {}...".format(sys.argv[1]))
    sys.stderr.flush()
    ips = {}
    ba = bitarray(endian='little') # nothing to do with system endianness.
    with open(sys.argv[1]) as infil:
        ba.fromfile(infil)
    sys.stderr.write("Seeking set bits... ")
    if ba.length() != 1<<32:
        exit("bitfield has length {}, needs to be {}\n".format(ba.length(),
                                                               1<<32))
    left = ba.count(True)
    if left == 0:
        sys.stderr.write("no IPs in this bitmap\n")
        return
    ip = -1
    try:
        while True:
            mds.twirl()
            ip = ba.index(True, ip+1)
            ips[socket.ntohl(ip)] = True
            left -= 1
            if left == 0:
                mds.del_twirl()
                sys.stderr.write(" (got all set bits) ")
                break
    except ValueError:
        mds.del_twirl()
        sys.stderr.write(" (fell off the end) ")
    sys.stderr.write("done.\n")
    sys.stderr.write("Creating normalized ranges... ")
    ips = ips.keys()
    ips.sort()
    sys.stderr.write("done.\n")
    print_shunlist(ips)


print("------[ Timing ba_forwardsearch")
begin = time.clock()
ba_forwardsearch()
print("\n------[ {}".format(mds.secs2duration(time.clock()-begin)))


#print("------[ Timing bytearray_bypage")
#begin = time.clock()
#ba_bypage()
#print("\n------[ {}".format(mds.secs2duration(time.clock()-begin)))


#print("------[ Timing ba_bitbybit")
#begin = time.clock()
#ba_bitbybit()
#print("\n------[ {}".format(mds.secs2duration(time.clock()-begin)))
