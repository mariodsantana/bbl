"""Some utility functions used throughout the bbl python scripts.
    TODO: replace these old homebrew things with stdlib or well-known libs."""
import socket
import struct
import math
import re
import sys

def quad2ip(quad):
    """
    Takes either a string in the form 1.2.3.4, or a 4-tuple of 8-bit integers
    Returns the IP so described as a single integer
    """
    q = []
    if isinstance(quad, str):
        try:
            q = (ord(x) for x in socket.inet_pton(socket.AF_INET, quad))
        except socket.error:
            raise ValueError("quad is not a valid IPv4 string")
    else:
        if len(quad) != 4:
            raise ValueError("quad is not a 4-len list: {}".format(quad))
        q = (int(x) for x in quad)
    ip = 0
    for i in range(4):
        if q[i] < 0 or q[i] > 255:
            raise ValueError("{} not 0-255, from quad {}".format(q[i], quad))
        ip += q[i] << ((3-i)*8)
    return ip

def ip2quad(ip):
    """
    Alias for ip2tuple
    """
    return ip2tuple(ip)

def ip2tuple(ip):
    """
    Takes either a string in the form 1.2.3.4, or an integer IP address
    Returns the IP so described as a list like (1, 2, 3, 4)
    """
    q = []
    if isinstance(ip, str):
        try:
            q = (ord(x) for x in socket.inet_pton(socket.AF_INET, ip))
        except:
            raise ValueError("ip {} not number nor dotted quad".format(ip))
        return q
    if ip < 0 or ip >= 1<<32:
        raise ValueError("ip {} not 0-0xffffffff".format(ip))
    for i in range(4):
        q[i] = (ip>>(32-((i+1)*8))) & 0xff
    return q

def ip2str(ip):
    """
    Takes whatever ip2tuple can take, returns a dotted-quad string
    """
    return ".".join((str(x) for x in ip2tuple(ip)))

def sixstr2ip(sixstr):
    """
    Takes either a string in usual IPv6 forms, or an 8-tuple of 16-bit integers
    Returns the IPv6 address so described as a single 128-bit integer
    """
    ss = []
    if isinstance(sixstr, str):
        try:
            ss = (ord(x) for x in socket.inet_pton(socket.AF_INET6, sixstr))
        except socket.error:
            raise ValueError("six-string isn't a valid IPv6")
    else:
        if len(sixstr) != 8:
            raise ValueError("six-string not a 8-len list: {}".format(sixstr))
        ss = (int(x) for x in sixstr)
    ip = 0
    for i in range(8):
        if ss[i] < 0 or ss[i] > 0xffff:
            raise ValueError("{} not 0-ffff in {}".format(ss[i], sixstr))
        ip += ss[i] << ((7-i)*16)
    return ip

def ip2tuple6(ip):
    """
    Takes either a string in usual IPv6 forms, or a 128-bit integer IP address
    Returns the IP so described as a 8-tuple of 16-bit integers
    """
    octuple = []
    if isinstance(ip, str):
        try:
            octuple = (ord(x) for x in socket.inet_pton(socket.AF_INET6, ip))
        except:
            raise ValueError("ip {} not number nor six-string".format(ip))
        return octuple
    if ip < 0 or ip >= 1<<128:
        raise ValueError("ip {} not 0-{}".format(ip, ":".join(["ffff"] * 8)))
    for i in range(8):
        octuple[i] = (ip>>(128-((i+1)*16))) & 0xffff
    return octuple

def ip2str6(ip):
    """
    Takes whatever ip2tuple6 can take, returns a valid IPv6 string
    """
    return socket.inet_ntop(socket.AF_INET6,
                            struct.pack("!HHHHHHHH", *ip2tuple6(ip)))

def is_cidr(lo, hi):
    """
    Returns true if lo/hi are network/broadcast addresses of a CIDR range.
    Works for IPv4 and IPv6
    """
    diff = abs(hi-lo)
    return diff & (diff+1) == 0

def is_cidr6(lo, hi):
    """
    Alias for is_cidr
    """
    return is_cidr(lo, hi)

def cidr_bits(lo, hi):
    """
    Returns the number of 1-bits in the IPv4 range's mask.  Returns fraction
    if lo/hi aren't network/broadcast addresses of a CIDR range.
    """
    bits = 32-math.log(hi-lo+1, 2)
    if is_cidr(lo, hi):
        return int(bits)
    return bits

def cidr_bits6(lo, hi):
    """
    Returns the number of 1-bits in the IPv6 range's mask.  Returns fraction
    if lo/hi aren't network/broadcast addresses of a CIDR range.
    """
    bits = 128-math.log(hi-lo+1, 2)
    if is_cidr(lo, hi):
        return int(bits)
    return bits

def lohi2str(lo, hi):
    """
    Returns IPv4 range as string
    Single address if lo == hi
    CIDR notation if lo/hi are network/broadcast addresses of a CIDR range
    IP-IP otherwise
    """
    if lo == hi: # range is single IP
        return ip2str(lo)
    elif is_cidr(lo, hi): # range is a natural CIDR
        return "{}/{}".format(ip2str(lo), cidr_bits(lo, hi))
    else: # range isn't special
        return "{}-{}".format(ip2str(lo), ip2str(hi))

def lohi2str6(lo, hi):
    """
    Returns IPv6 range as string
    Single address if lo == hi
    CIDR notation if lo/hi are network/broadcast addresses of a CIDR range
    IP-IP otherwise
    """
    if lo == hi: # range is single IP
        return ip2str6(lo)
    elif is_cidr(lo, hi): # range is a natural CIDR
        return "{}/{}".format(ip2str6(lo), int(cidr_bits6(lo, hi)))
    else: # range isn't special
        return "{}-{}".format(ip2str6(lo), ip2str6(hi))

def match2lohi(m, str2ip):
    """
      For a regex match m, and an appropriate function str2ip, returns
      what `range2lohi` and `range2lohi6` want to return.
    """
    groups = m.groupdict()
    if 'cidr' in groups and groups['cidr']:
        rsiz = 2**(32-int(m.group('cidr')))
        if rsiz < 0:
            return None, None, None
        try:
            lo = str2ip(m.group('lo'))
        except ValueError:
            return None, None, None
        lo = lo - lo%rsiz
        hi = lo + rsiz-1
    elif 'hi' in groups and groups['hi']:
        try:
            lo = str2ip(m.group('lo'))
            hi = str2ip(m.group('hi'))
        except ValueError:
            return None, None, None
        if hi < lo:
            ip = hi
            hi = lo
            lo = ip
    elif 'lo' in groups and groups['lo']:
        try:
            lo = str2ip(m.group('lo'))
            hi = lo
        except ValueError:
            return None, None, None
    return (m.group('ad').lower(), lo, lo)

# this ipv4 regex is imperfect.  the real check happens in quad2ip
IP_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
re_IP = re.compile(r'^\s*(?P<ad>[ad])\s*(?P<lo>'+IP_regex+r')\s.*$', re.I)
re_CIDR = re.compile(r'^\s*(?P<ad>[ad])\s*(?P<lo>'+IP_regex+
                     r')\s*/\s*(?P<cidr>\d{1,2})\s.*$', re.I)
re_range = re.compile(r'^\s*(?P<ad>[ad])\s*(?P<lo>'+IP_regex+
                      r')\s*-\s*(?P<hi>'+IP_regex+r')\s.*$', re.I)
def range2lohi(line):
    """
    Inverse of lohi2str.  If line is like:
      A IPv4_address
      D IPv4_address/CIDR
      A IPv4_address-IPv4_address
    then return (AD, lo, hi), where
      AD is "a" or "d" in first char
      lo and hi are bottom and top of described range
    """
    m = re_CIDR.match(line) or re_range.match(line) or re_IP.match(line)
    if not m:
        return None, None, None
    return match2lohi(m, quad2ip)

# this ipv6 regex is imperfect.  the real check happens in sixstr2ip
IP_regex6 = r'(?:[0-9a-f]{1,4}::?){0,7}[0-9a-f]{1,4}(?:'+IP_regex+')?'
re_IP6 = re.compile(r'^\s*(?P<ad>[ad])\s*(?P<lo>'+IP_regex6+r')\s.*$', re.I)
re_CIDR6 = re.compile(r'^\s*(?P<ad>[ad])\s*(?P<lo>'+IP_regex6+
                      r')\s*/\s*(?P<cidr>\d{1,3})\s.*$', re.I)
re_range6 = re.compile(r'^\s*(?P<ad>[ad])\s*(?P<lo>'+IP_regex6+
                       r')\s*-\s*(?P<hi>'+IP_regex6+r')\s.*$', re.I)
def range2lohi6(line):
    """
    Inverse of lohi2str6.  If line is like:
      A IPv6_address
      D IPv6_address/CIDR
      A IPv6_address-IPv6_address
    then return (AD, lo, hi), where
      AD is "a" or "d" in first char
      lo and hi are bottom and top of described range
    """
    m = re_CIDR6.match(line) or re_range6.match(line) or re_IP6.match(line)
    if not m:
        return None, None, None
    return match2lohi(m, sixstr2ip)

def secs2duration(i):
    """
    For i seconds, prints equivalent hours/minutes/seconds
    """
    return "{:02}h:{:02}m:{:02}s".format(
        int(i/(60*60)), int((i%(60*60))/60), int(i%60))

####### BEGIN MDS TWIRL PROTOCOL #######
twirlary = ['|', '/', '-', '\\']
twirlcnt = 0

def twirl():
    """
    Overwrites previous twirl character with next
    """
    # pylint: disable=locally-disabled,fixme
    # TODO: abort if stderr isn't a terminal
    global twirlary, twirlcnt  # pylint: disable=locally-disabled,W0602
    if twirlcnt:
        sys.stderr.write("\b")
    sys.stderr.write(twirlary[twirlcnt%4])
    sys.stderr.flush()
    twirlcnt += 1

def del_twirl():
    """
    Removes existing twirl character, resets twirl state
    """
    global twirlcnt  # pylint: disable=locally-disabled,W0603
    if twirlcnt:
        sys.stderr.write("\b \b")
        sys.stderr.flush()
    twirlcnt = 0
######## END MDS TWIRL PROTOCOL ########
