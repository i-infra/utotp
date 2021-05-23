try:
    import ustruct as struct
    from uhashlib import sha1
    from utime import time
except ImportError:
    # not micropython
    import struct
    from hashlib import sha1
    from time import time


class Sha1HMAC:
    def __init__(self, key, msg=None):
        def translate(d, t):
            return bytes(t[x] for x in d)

        _trans_5C = bytes((x ^ 0x5C) for x in range(256))
        _trans_36 = bytes((x ^ 0x36) for x in range(256))
        self.digest_cons = sha1
        self.outer = self.digest_cons()
        self.inner = self.digest_cons()
        self.digest_size = 20  # // hashlib.sha1().digest_size
        self.blocksize = 64
        if len(key) > self.blocksize:
            key = self.digest_cons(key).digest()
        key = key + bytes(self.blocksize - len(key))
        self.outer.update(translate(key, _trans_5C))
        self.inner.update(translate(key, _trans_36))
        if msg is not None:
            self.update(msg)

    def update(self, msg):
        self.inner.update(msg)

    def _current(self):
        self.outer.update(self.inner.digest())
        return self.outer

    def digest(self):
        return self._current().digest()


def get_epoch():
    # some micropython implementations use non-standard epochs
    maybe_time = time()
    if maybe_time < 946684801:
        maybe_time += 946684801
    return int(maybe_time)


def hotp(key, counter, digits=6):
    # key should be raw bytes
    # key = b32decode(key.upper() + '=' * ((8 - len(key)) % 8))
    counter = struct.pack(">Q", counter)
    mac = Sha1HMAC(key, counter).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(binary)[-digits:]
    return ((digits - len(code)) * "0") + code


def totp(key, time_step=30, digits=6):
    if isinstance(key,str):
        try:
            key = b32decode(key)
        except:
            raise ValueError("Key must be b32 string or seed bytes.")
    return hotp(key, get_epoch() // time_step, digits)


_b32alphabet = {
    0: b"A",
    9: b"J",
    18: b"S",
    27: b"3",
    1: b"B",
    10: b"K",
    19: b"T",
    28: b"4",
    2: b"C",
    11: b"L",
    20: b"U",
    29: b"5",
    3: b"D",
    12: b"M",
    21: b"V",
    30: b"6",
    4: b"E",
    13: b"N",
    22: b"W",
    31: b"7",
    5: b"F",
    14: b"O",
    23: b"X",
    6: b"G",
    15: b"P",
    24: b"Y",
    7: b"H",
    16: b"Q",
    25: b"Z",
    8: b"I",
    17: b"R",
    26: b"2",
}

_b32tab = [v[0] for k, v in sorted(_b32alphabet.items())]
_b32rev = dict([(v[0], k) for k, v in _b32alphabet.items()])


def unhexlify(data):
    if len(data) % 2 != 0:
        raise ValueError("Odd-length string")

    return bytes([int(data[i : i + 2], 16) for i in range(0, len(data), 2)])


def b32encode(s):
    if not isinstance(s, bytes_types):
        raise TypeError("expected bytes, not %s" % s.__class__.__name__)
    quanta, leftover = divmod(len(s), 5)
    # Pad the last quantum with zero bits if necessary
    if leftover:
        s = s + bytes(5 - leftover)  # Don't use += !
        quanta += 1
    encoded = bytearray()
    for i in range(quanta):
        c1, c2, c3 = struct.unpack("!HHB", s[i * 5 : (i + 1) * 5])
        c2 += (c1 & 1) << 16
        c3 += (c2 & 3) << 8
        encoded += bytes(
            [
                _b32tab[c1 >> 11],
                _b32tab[(c1 >> 6) & 0x1F],
                _b32tab[(c1 >> 1) & 0x1F],
                _b32tab[c2 >> 12],
                _b32tab[(c2 >> 7) & 0x1F],
                _b32tab[(c2 >> 2) & 0x1F],
                _b32tab[c3 >> 5],
                _b32tab[c3 & 0x1F],
            ]
        )
    if leftover == 1:
        encoded = encoded[:-6] + b"======"
    elif leftover == 2:
        encoded = encoded[:-4] + b"===="
    elif leftover == 3:
        encoded = encoded[:-3] + b"==="
    elif leftover == 4:
        encoded = encoded[:-1] + b"="
    return bytes(encoded)


def b32decode(s):
    if isinstance(s, str):
        s = s.encode()
    quanta, leftover = divmod(len(s), 8)
    if leftover:
        raise ValueError("Incorrect padding")
    s = s.upper()
    padchars = s.find(b"=")
    if padchars > 0:
        padchars = len(s) - padchars
        s = s[:-padchars]
    else:
        padchars = 0

    # Now decode the full quanta
    parts = []
    acc = 0
    shift = 35
    for c in s:
        val = _b32rev.get(c)
        if val is None:
            raise ValueError("Non-base32 digit found")
        acc += _b32rev[c] << shift
        shift -= 5
        if shift < 0:
            parts.append(unhexlify(bytes("%010x" % acc, "ascii")))
            acc = 0
            shift = 35
    # Process the last, partial quanta
    last = unhexlify(bytes("%010x" % acc, "ascii"))
    if padchars == 0:
        last = b""  # No characters
    elif padchars == 1:
        last = last[:-1]
    elif padchars == 3:
        last = last[:-2]
    elif padchars == 4:
        last = last[:-3]
    elif padchars == 6:
        last = last[:-4]
    else:
        raise ValueError("Incorrect padding")
    parts.append(last)
    return b"".join(parts)
