#_*_coding:utf-8_*_
import sys
import os
import hashlib

virus_db = []
vdb = []
vsize = []

def check_sample(md5):
    """
    Comapares the md5 of sample to the md5 of virus_db.
    if matching, it returns the variables "result", "detect".

    Args:
        md5 (bytearray): md5 of check sample

    Returns:
        bool: if matching, return "True",
        str: malware type. ex) Trojan, Ransomware
    """
    result = False
    detect = ""
    for t in vdb:
        if t[0] == md5:
            result = True
            detect = t[1]
            return result, detect.decode()
    return result, detect


if __name__=='__main__':
    fp = open("virus.db", "rb")

    while True:
        line = fp.readline()
        if not line:
            break
        line = line.strip()
        virus_db.append(line)
    fp.close()

    for pattern in virus_db:
        t = []
        v = pattern.split(b":")
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)

        size = int(v[0])
        if vsize.count(size) == 0:
            vsize.append(size)

    sample = sys.argv[1]
    if os.path.isfile(sample) == False:
        print("{} doesn't exist".format(sample))

    size = os.path.getsize(sample)
    if vsize.count(size):
        with open(sample, 'rb') as fp:
            bdata = fp.read()

        m = hashlib.md5()
        m.update(bdata)
        md5 = m.hexdigest().encode()

        result, detect = check_sample(md5)
        if result == True:
            print("[remove] {} : {}".format(sample, detect))
            os.remove(sample)
        else:
            print("{} : {}".format(sample, "Clean"))
    else:
        print("{} : {}".format(sample, "Clean"))


