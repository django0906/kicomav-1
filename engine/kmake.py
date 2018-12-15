#_*_coding:utf-8_*_
import zlib
import hashlib

class EncModule():
    def __init__(self):
        self.e_bdata = b""

    def encrypt(self, vfile):
        """
        Encrypt "virus.db" file.
            1. Each bytes are "XOR" with 0xff.
            2. Add "KAVM"(Header)
            3. Compress "virus.db" file.
            4. Do a "MD5^3" by encrypted data.
            5. Add MD5(into end of encrypted data).
            6. Create File("virus.kmd") by [5]'s result data.

        Args:
            vfile (str): "virus.db"
        """
        with open(vfile, 'rb') as fp:
            bdata = fp.read()

        for c in bdata:
            self.e_bdata += chr(c ^ 0xff).encode("utf-8")
        self.ez_bdata = b"KAVM" + self.ez_bdata

        self.ez_bdata = zlib.compress(self.e_bdata)

        md5 = self.ez_bdata
        for i in range(0, 3):
            m = hashlib.md5()
            m.update(md5)
            md5 = m.hexdigest().encode("utf-8")
        self.ez_bdata += md5

        e_vfile = vfile.split('.')[0] + '.kmd'
        with open(e_vfile, 'wb') as fp:
            fp.write(self.ez_bdata)
        print('encrypt [{}] => [{}]\n'.format(vfile, e_vfile))


class DecModule():
    def __init__(self):
        pass

    def decrypt(self, e_vfile):
        with open(e_vfile, 'rb') as fp:
            ez_bdata = fp.read()
        z_md5 = ez_bdata[-32:]
        ez_bdata = ez_bdata[:-32]

        md5 = ez_bdata
        for i in range(0, 3):
            m = hashlib.md5()
            m.update(md5)
            md5 = m.hexdigest().encode()
        if z_md5 != md5:
            raise ValueError

        e_bdata = zlib.decompress(ez_bdata)

        bdata = ""
        for i in range(4, len(e_bdata), 2):
            bdata += chr(ord(e_bdata[i:i+2].decode("utf-8")) ^ 0xff)
        return bdata


