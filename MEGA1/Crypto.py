import json
import struct
import base64
import binascii

import Crypto.Cipher.AES

def AESEncrypt(Data, Key):
    AESCipher = Crypto.Cipher.AES.new(Key, Crypto.Cipher.AES.MODE_CBC, '\0' * 16)
    return AESCipher.encrypt(Data)

def AESDecrypt(Data, Key):
    AESCipher = Crypto.Cipher.AES.new(Key, Crypto.Cipher.AES.MODE_CBC, '\0' * 16)
    return AESCipher.decrypt(Data)

def AESEncryptBytes(Data, Key):
    return UTF8ToBytes(AESEncrypt(BytesToUTF8(Data), BytesToUTF8(Key)))

def AESDecryptBytes(Data, Key):
    return UTF8ToBytes(AESDecrypt(BytesToUTF8(Data), BytesToUTF8(Key)))

def EncryptKey(Data, Key):
    return sum((AESEncryptBytes(Data[Index:Index + 4], Key) for Index in range(0, len(Data), 4)), ())

def DecryptKey(Data, Key): 
    return sum((AESDecryptBytes(Data[Index:Index + 4], Key) for Index in range(0, len(Data), 4)), ())

def EncryptAttribute(Attribute, Key):
    Attribute = 'MEGA' + json.dumps(Attribute)
    if len(Attribute) % 16:
        Attribute = Attribute + '\0' * (16 - len(Attribute) % 16)
    return AESEncrypt(Attribute, BytesToUTF8(Key))

def DecryptAttribute(Attribute, Key):
    Attribute = AESDecrypt(Attribute, BytesToUTF8(Key)).rstrip(b'\0')
    Attribute = str(Attribute, "utf-8")
    return json.loads(Attribute[4:]) if Attribute[:6] == 'MEGA{"' else False

def BytesToUTF8(Data):
    return struct.pack('>%dI' % len(Data), *Data)

def UTF8ToBytes(Data):
    if len(Data) % 4:
        Data = Data + (b'\0' * (4 - len(Data) % 4))
    return struct.unpack('>%dI' % (len(Data) / 4), Data)

def BytesToString(Data):
    return str(struct.pack('>%dI' % len(Data), *Data), 'utf-8')

def StringToBytes(Data):
    if len(Data) % 4:
        Data = Data + ('\0' * (4 - len(Data) % 4))
    Data = bytes(Data, 'utf-8')
    return struct.unpack('>%dI' % (len(Data) / 4), Data)

def MPIToInteger(Data):
    return int(binascii.hexlify(Data[2:]), 16)

def Base64URLDecode(Data):
    Data = bytes(Data, 'utf-8') + b'=='[(2 - len(Data) * 3) % 4:]
    for Pattern, Replacement in ((b'-', b'+'), (b'_', b'/'), (b',', b'')):
        Data = Data.replace(Pattern, Replacement)
    return base64.b64decode(Data)

def Base64ToBytes(Data):
    return UTF8ToBytes(Base64URLDecode(Data))

def Base64URLEncode(Data):
    Data = base64.b64encode(Data)
    for Pattern, Replacement in ((b'+', b'-'), (b'/', b'_'), (b'=', b'')):
        Data = Data.replace(Pattern, Replacement)
    return str(Data, 'utf-8')

def BytesToBase64(Data):
    return Base64URLEncode(BytesToUTF8(Data))

def GenerateHash(InputString, HashKey):
    StringBytes = StringToBytes(InputString)
    Hash = [0, 0, 0, 0]
    for Index in range(len(StringBytes)):
        Hash[Index % 4] = Hash[Index % 4] ^ StringBytes[Index]
    for Index in range(0x4000):
        Hash = AESEncryptBytes(Hash, HashKey)
    return BytesToBase64((Hash[0], Hash[2]))

def PrepareKey(PasswordBytes):
    OutputKey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
    for Counter in range(0x10000):
        for Index in range(0, len(PasswordBytes), 4):
            EncryptionKey = [0, 0, 0, 0]
            for Offset in range(4):
                if Offset + Index < len(PasswordBytes):
                    EncryptionKey[Offset] = PasswordBytes[Offset + Index]
            OutputKey = AESEncryptBytes(OutputKey, EncryptionKey)
    return OutputKey
