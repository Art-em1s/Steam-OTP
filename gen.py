import base64, hmac, struct, time, sys
from hashlib import sha1
shared_secret = sys.argv[1] #pass secret as arg, 
timestamp = int(time.time())
time_buffer = struct.pack('>Q', timestamp // 30)
time_hmac = hmac.new(base64.b64decode(shared_secret), time_buffer, digestmod=sha1).digest()
begin = ord(time_hmac[19:20]) & 0xf
f = struct.unpack('>I', time_hmac[begin:begin + 4])[0] & 0x7fffffff
chars = '23456789BCDFGHJKMNPQRTVWXY'
code = ''
for _ in range(5):
    f, i = divmod(f, len(chars))
    code += chars[i]
print("Confirmation Code: {}".format(code))
