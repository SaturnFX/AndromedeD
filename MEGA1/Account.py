import os
import json
import random
import requests
import binascii

import Crypto.PublicKey.RSA
import Crypto.Util.Counter
import Crypto.Cipher.AES

from .Crypto import *
from .Errors import *

class Account(object):
    _CharacterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    def __init__(self):      
        self.MEGAAddress = "https://mega.nz"
        self.APIEndpoint = "https://g.api.mega.co.nz/cs"
        self.PathSeparator = '\\'
        self.RequestTimeout = 160
        self.SequenceNumber = random.randint(0, 0xFFFFFFFF)
        self.RequestID = Account._GenerateID(10)
        self.SID = ""
    
    @staticmethod
    def _GenerateID(IDLength):
        OutputID = ""
        for Index in range(IDLength):
            OutputID = OutputID + random.choice(Account._CharacterSet)
        return OutputID    

    def _APIRequest(self, RequestData):
        Parameters = {'id': self.SequenceNumber}
        self.SequenceNumber = self.SequenceNumber + 1
        if len(self.SID) > 0:
            Parameters.update({'sid': self.SID})
        if not isinstance(RequestData, list):
            RequestData = [RequestData]
        ResponseData = requests.post(self.APIEndpoint, params=Parameters, data=json.dumps(RequestData), timeout=self.RequestTimeout)
        JSONResponse = json.loads(ResponseData.text)
        if isinstance(JSONResponse, int):
            raise RequestError(JSONResponse)
        return JSONResponse[0]

    def Login(self, Mail=None, Password=None):
        if Mail is not None:
            self._LoginUser(Mail, Password)
        else:
            self._LoginAnonymously()

    def _LoginUser(self, Mail, Password):
        PasswordKey = PrepareKey(StringToBytes(Password))
        PasswordHash = GenerateHash(Mail, PasswordKey)
        LoginResponse = self._APIRequest({'a': 'us', 'user': Mail, 'uh': PasswordHash})
        if isinstance(LoginResponse, int):
            raise RequestError(LoginResponse)
        self._LoginProcess(LoginResponse, PasswordKey)

    def _LoginAnonymously(self):
        MasterKey = [random.randint(0, 0xFFFFFFFF)] * 4
        PasswordKey = [random.randint(0, 0xFFFFFFFF)] * 4
        SessionChallenge = [random.randint(0, 0xFFFFFFFF)] * 4
        UserData = self._APIRequest({
            'a': 'up',
            'k': BytesToBase64(EncryptKey(MasterKey, PasswordKey)),
            'ts': Base64URLEncode(BytesToUTF8(SessionChallenge) + BytesToUTF8(EncryptKey(SessionChallenge, MasterKey)))
        })
        LoginResponse = self._APIRequest({'a': 'us', 'user': UserData})
        if isinstance(LoginResponse, int):
            raise RequestError(LoginResponse)
        self._LoginProcess(LoginResponse, PasswordKey)

    def _LoginProcess(self, LoginResponse, PasswordKey):
        EncryptedMasterKey = Base64ToBytes(LoginResponse['k'])
        self.MasterKey = DecryptKey(EncryptedMasterKey, PasswordKey)
        if 'tsid' in LoginResponse:
            TemporarySessionID = Base64URLDecode(LoginResponse['tsid'])
            EncryptedKey = BytesToUTF8(EncryptKey(UTF8ToBytes(TemporarySessionID[:16]), self.MasterKey))
            if EncryptedKey == TemporarySessionID[-16:]:
                self.SID = LoginResponse['tsid']
        elif 'csid' in LoginResponse:
            EncryptedRSAPrivateKey = Base64ToBytes(LoginResponse['privk'])
            RSAPrivateKey = DecryptKey(EncryptedRSAPrivateKey, self.MasterKey)
            PrivateKey = BytesToUTF8(RSAPrivateKey)
            self.RSAPrivateKey = [0, 0, 0, 0]
            for Index in range(4):
                DataLength = ((PrivateKey[0] * 256 + PrivateKey[1] + 7) // 8) + 2
                self.RSAPrivateKey[Index] = MPIToInteger(PrivateKey[:DataLength])
                PrivateKey = PrivateKey[DataLength:]
            EncryptedSID = MPIToInteger(Base64URLDecode(LoginResponse['csid']))
            RSADecrypter = Crypto.PublicKey.RSA.construct(
                (self.RSAPrivateKey[0] * self.RSAPrivateKey[1],
                 0, self.RSAPrivateKey[2], self.RSAPrivateKey[0],
                 self.RSAPrivateKey[1]))
            SID = "{0:x}".format(RSADecrypter.key._decrypt(EncryptedSID))
            SID = binascii.unhexlify('0' + SID if len(SID) % 2 else SID)
            self.SID = Base64URLEncode(SID[:43])
        self._InitializeSpecialNodes()
    
    def _InitializeSpecialNodes(self):
        SharedKeys = {}        
        NodesResponse = self._APIRequest({'a': 'f', 'c': 1})
        self._InitializeSharedKeys(NodesResponse, SharedKeys)
        for Node in NodesResponse['f']:
            if Node['t'] == 2:
                Node['a'] = {'n': "Cloud Drive"}
                self.RootNode = Node
            elif Node['t'] == 3:
                Node['a'] = {'n': "Inbox"}
                self.InboxNode = Node
            elif Node['t'] == 4:
                Node['a'] = {'n': "Rubbish Bin"}
                self.TrashNode = Node            
    
    def GetNode(self, NodePath, ParentNode=None):
        NameIndex = 0
        Nodes = self.GetAllNodes()
        CurrentNodeID = self.RootNode['h'] if ParentNode is None else ParentNode['h']
        PreviousNodeID = ""
        PathNames = NodePath.split(self.PathSeparator)
        while NameIndex < len(PathNames):
            PreviousNodeID = CurrentNodeID
            for NodeID, Node in Nodes.items():
                if (Node['p'] == CurrentNodeID) and (Node['a']['n'] == PathNames[NameIndex]):
                    CurrentNodeID = Node['h']
                    break
            if CurrentNodeID == PreviousNodeID:
                raise NodeNotFoundError("Could not find node at specified path")
            NameIndex = NameIndex + 1
        return Nodes[CurrentNodeID]     
    
    def GetAllNodes(self):
        Nodes = {}
        SharedKeys = {}        
        NodesResponse = self._APIRequest({'a': 'f', 'c': 1})
        self._InitializeSharedKeys(NodesResponse, SharedKeys)
        for Node in NodesResponse['f']:
            ProcessedNode = self._ProcessNode(Node, SharedKeys)
            if ProcessedNode['a']:
                Nodes[Node['h']] = ProcessedNode
        return Nodes

    def GetChlidrenNodes(self, ParentNode):
        Nodes = {}
        SharedKeys = {}
        ParentNodeID = ParentNode['h']
        NodesResponse = self._APIRequest({'a': 'f', 'c': 1})
        self._InitializeSharedKeys(NodesResponse, SharedKeys)
        for Node in NodesResponse['f']:
            ProcessedNode = self._ProcessNode(Node, SharedKeys)
            if ProcessedNode['a'] and ProcessedNode['p'] == ParentNodeID:
                Nodes[Node['h']] = ProcessedNode
        return Nodes

    def _InitializeSharedKeys(self, NodesResponse, SharedKeys):
        KeysDict = {}
        for KeyItem in NodesResponse['ok']:
            KeysDict[KeyItem['h']] = DecryptKey(Base64ToBytes(KeyItem['k']), self.MasterKey)
        for KeyItem in NodesResponse['s']:
            if KeyItem['u'] not in SharedKeys:
                SharedKeys[KeyItem['u']] = {}
            if KeyItem['h'] in KeysDict:
                SharedKeys[KeyItem['u']][KeyItem['h']] = KeysDict[KeyItem['h']]    

    def _ProcessNode(self, Node, SharedKeys):
        if Node['t'] == 0 or Node['t'] == 1:
            NodeKey = None
            Owner = Node['u']
            Keys = dict(KeyPart.split(':', 1) for KeyPart in Node['k'].split('/') if ':' in KeyPart)
            if Owner in Keys:
                NodeKey = DecryptKey(Base64ToBytes(Keys[Owner]), self.MasterKey)
            elif 'su' in Node and 'sk' in Node and ':' in Node['k']:
                SharedKey = DecryptKey(Base64ToBytes(Node['sk']), self.MasterKey)
                NodeKey = DecryptKey(Base64ToBytes(Keys[Node['h']]), SharedKey)
                if Node['su'] not in SharedKeys:
                    SharedKeys[Node['su']] = {}
                SharedKeys[Node['su']][Node['h']] = SharedKey
            elif Owner and Owner in SharedKeys:
                for CurrentKey in SharedKeys[Owner]:
                    SharedKey = SharedKeys[Owner][CurrentKey]
                    if CurrentKey in Keys:
                        NodeKey = Keys[CurrentKey]
                        NodeKey = DecryptKey(Base64ToBytes(NodeKey), SharedKey)
                        break
            if NodeKey is not None:
                if Node['t'] == 0:
                    AttributesKey = (NodeKey[0] ^ NodeKey[4], NodeKey[1] ^ NodeKey[5], NodeKey[2] ^ NodeKey[6], NodeKey[3] ^ NodeKey[7])
                    Node['iv'] = NodeKey[4:6] + (0, 0)
                    Node['meta_mac'] = NodeKey[6:8]
                else:
                    AttributesKey = NodeKey
                Node['key'] = NodeKey
                Node['k'] = AttributesKey
                NodeAttributes = Base64URLDecode(Node['a'])
                NodeAttributes = DecryptAttribute(NodeAttributes, AttributesKey)
                Node['a'] = NodeAttributes
            elif Node['k'] == '':
                Node['a'] = False
        elif Node['t'] == 2:
            Node['a'] = {'n': "Cloud Drive"}
            self.RootNode = Node
        elif Node['t'] == 3:
            Node['a'] = {'n': "Inbox"}
            self.InboxNode = Node
        elif Node['t'] == 4:
            Node['a'] = {'n': "Rubbish Bin"}
            self.TrashNode = Node
        return Node
    
    def GetUserData(self):
        UserDataResponse = self._APIRequest({'a': 'ug'})
        return (UserDataResponse['name'], UserDataResponse['email'], UserDataResponse['since'])
    
    def GetStorageSpace(self):
        StorageDataResponse = self._APIRequest({'a': 'uq', 'xfer': 1, 'strg': 1})
        return (StorageDataResponse['cstrg'], StorageDataResponse['mstrg'])     

    def Download(self, Node, FilePath, ProgressHandler=None):
        FileData = self._APIRequest({'a': 'g', 'g': 1, 'n': Node['h']})
        self._DownloadFile(FileData, BytesToUTF8(Node['k']), Node['iv'], Node['meta_mac'], FilePath, ProgressHandler)    
    
    def DownloadURL(self, URL, FilePath, ProgressHandler=None):
        URLData = self._GetURLData(URL)
        URLKey = Base64ToBytes(URLData[1])
        FileData = self._APIRequest({'a': 'g', 'g': 1, 'p': URLData[0]})
        FileKey = (URLKey[0] ^ URLKey[4], URLKey[1] ^ URLKey[5], URLKey[2] ^ URLKey[6], URLKey[3] ^ URLKey[7])
        self._DownloadFile(FileData, BytesToUTF8(FileKey), URLKey[4:6] + (0, 0), URLKey[6:8], FilePath, ProgressHandler)
        
    def _GetURLData(self, URL):
        if URL.find(self.MEGAAddress + "/#!") != 0:
            raise ValueError("This is not valid MEGA address")
        URLData = URL[18:].split("!")
        if len(URLData) != 2:
            raise ValueError("This address does not contains all required data")
        return URLData
    
    def _DownloadFile(self, FileData, FileKey, IV, MetaMAC, FilePath, ProgressHandler=None):
        if 'g' not in FileData:
            raise RequestError("File is currently not accessible")
        FileMAC = b'\0' * 16
        MACEncryptor = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CBC, FileMAC)
        with open(FilePath, mode='wb') as FileStream:
            FilePosition = 0
            FileSize = FileData['s']
            if ProgressHandler is not None:
                ProgressHandler.Set(FileSize)
                ProgressHandler.Print(0)
            ResponseStream = requests.get(FileData['g'], stream=True).raw
            AESCounter = Crypto.Util.Counter.new(128, initial_value=((IV[0] << 32) + IV[1]) << 64)
            AESCipher = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CTR, counter=AESCounter)
            EncryptorIV = BytesToUTF8([IV[0], IV[1], IV[0], IV[1]])          
            if FileSize > 16:
                for ChunkStart, ChunkSize in Account._GetFileChunks(FileSize):
                    DataChunk = ResponseStream.read(ChunkSize)
                    DataChunk = AESCipher.decrypt(DataChunk)
                    FilePosition = FilePosition + len(DataChunk)
                    FileStream.write(DataChunk)
                    if ProgressHandler is not None:
                        ProgressHandler.Print(FilePosition)                    
                    BlockEncryptor = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CBC, EncryptorIV)
                    for DataIndex in range(0, len(DataChunk) - 16, 16):
                        DataBlock = DataChunk[DataIndex:DataIndex + 16]
                        BlockEncryptor.encrypt(DataBlock)
                    DataBlock = DataChunk[DataIndex + 16:DataIndex + 32]
                    if len(DataBlock) % 16:
                        DataBlock = DataBlock + (b'\0' * (16 - (len(DataBlock) % 16)))
                    FileMAC = MACEncryptor.encrypt(BlockEncryptor.encrypt(DataBlock))
            else:
                DataChunk = ResponseStream.read(FileSize)
                DataChunk = AESCipher.decrypt(DataChunk)
                FilePosition = FilePosition + len(DataChunk)
                FileStream.write(DataChunk)
                if ProgressHandler is not None:                    ProgressHandler.Print(FilePosition)                
                if len(DataChunk) % 16:
                    DataChunk = DataChunk + (b'\0' * (16 - (len(DataChunk) % 16)))
                BlockEncryptor = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CBC, EncryptorIV)
                FileMAC = MACEncryptor.encrypt(BlockEncryptor.encrypt(DataChunk))
            if ProgressHandler is not None:
                ProgressHandler.Print(FileSize)
                ProgressHandler.Finish()
        FileMAC = UTF8ToBytes(FileMAC)
        if (FileMAC[0] ^ FileMAC[1], FileMAC[2] ^ FileMAC[3]) != MetaMAC:
            raise TransferError("Failed to verify downloaded file")
        
    def UploadFile(self, FilePath, ParentNode, ProgressHandler=None):
        FileHandle = ""
        FileMAC = '\0' * 16
        Key = [random.randint(0, 0xFFFFFFFF) for _ in range(6)]
        FileKey = BytesToUTF8(Key[:4])        
        MACEncryptor = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CBC, FileMAC)
        with open(FilePath, mode='rb') as FileStream:
            FilePosition = 0
            FileStream.seek(0, os.SEEK_END)
            FileSize = FileStream.tell()
            FileStream.seek(0, os.SEEK_SET)
            if ProgressHandler is not None:
                ProgressHandler.Set(FileSize)
                ProgressHandler.Print(0)            
            UploadURL = self._APIRequest({'a': 'u', 's': FileSize})['p']
            AESCounter = Crypto.Util.Counter.new(128, initial_value=((Key[4] << 32) + Key[5]) << 64)
            AESCipher = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CTR, counter=AESCounter)
            EncryptorIV = BytesToUTF8([Key[4], Key[5], Key[4], Key[5]])
            if FileSize > 16:
                for ChunkStart, ChunkSize in Account._GetFileChunks(FileSize):
                    DataChunk = FileStream.read(ChunkSize)
                    FilePosition = FilePosition + len(DataChunk)
                    BlockEncryptor = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CBC, EncryptorIV)
                    for DataIndex in range(0, len(DataChunk) - 16, 16):
                        DataBlock = DataChunk[DataIndex:DataIndex + 16]
                        BlockEncryptor.encrypt(DataBlock)
                    DataBlock = DataChunk[DataIndex + 16:DataIndex + 32]
                    if len(DataBlock) % 16:
                        DataBlock = DataBlock + (b'\0' * (16 - len(DataBlock) % 16))
                    FileMAC = MACEncryptor.encrypt(BlockEncryptor.encrypt(DataBlock))
                    DataChunk = AESCipher.encrypt(DataChunk)
                    FileHandle = requests.post(UploadURL + "/" + str(ChunkStart), data=DataChunk, timeout=self.RequestTimeout).text
                    if ProgressHandler is not None:
                        ProgressHandler.Print(FilePosition)                
            else:
                DataChunk = FileStream.read(FileSize)
                FilePosition = FilePosition + len(DataChunk)
                DataBlock = DataChunk
                if len(DataBlock) % 16:
                    DataBlock = DataBlock + (b'\0' * (16 - len(DataBlock) % 16))
                BlockEncryptor = Crypto.Cipher.AES.new(FileKey, Crypto.Cipher.AES.MODE_CBC, EncryptorIV)
                FileMAC = MACEncryptor.encrypt(BlockEncryptor.encrypt(DataBlock))
                DataChunk = AESCipher.encrypt(DataChunk)
                FileHandle = requests.post(UploadURL + "/0", data=DataChunk, timeout=self.RequestTimeout).text
            if ProgressHandler is not None:
                ProgressHandler.Print(FileSize)
                ProgressHandler.Finish()
        FileMAC = UTF8ToBytes(FileMAC)
        MetaMAC = (FileMAC[0] ^ FileMAC[1], FileMAC[2] ^ FileMAC[3])
        FileAttributes = Base64URLEncode(EncryptAttribute({'n': os.path.basename(FilePath)}, Key[:4]))
        EncryptedKey = BytesToBase64(EncryptKey([
            Key[0] ^ Key[4], Key[1] ^ Key[5],
            Key[2] ^ MetaMAC[0], Key[3] ^ MetaMAC[1],
            Key[4], Key[5], MetaMAC[0], MetaMAC[1]
            ], self.MasterKey))
        return self._APIRequest({'a': 'p', 't': ParentNode['h'], 'n': [{'h': FileHandle, 't': 0, 'a': FileAttributes, 'k': EncryptedKey}]})['f'][0]
    
    @staticmethod
    def _GetFileChunks(FileSize):
        ChunkStart = 0
        ChunkSize = 0x20000
        while ChunkStart + ChunkSize < FileSize:
            yield(ChunkStart, ChunkSize)
            ChunkStart = ChunkStart + ChunkSize
            if ChunkSize < 0x100000:
                ChunkSize = ChunkSize + 0x20000
        yield(ChunkStart, FileSize - ChunkStart)    
    
    def CreateFolder(self, FolderName, ParentNode):
        Key = [random.randint(0, 0xFFFFFFFF) for _ in range(6)]
        FolderAttributes = Base64URLEncode(EncryptAttribute({'n': FolderName}, Key[:4]))
        EncryptedKey = BytesToBase64(EncryptKey(Key[:4], self.MasterKey))
        self._APIRequest({'a': 'p', 't': ParentNode['h'], 'n': [{'h': 'xxxxxxxx', 't': 1, 'a': FolderAttributes, 'k': EncryptedKey}], 'i': self.RequestID})

    def RenameNode(self, Node, NodeName):
        NodeAttributes = Base64URLEncode(EncryptAttribute({'n': NodeName}, Node['k']))
        EncryptedKey = BytesToBase64(EncryptKey(Node['key'], self.MasterKey))
        self._APIRequest([{'a': 'a', 'attr': NodeAttributes, 'key': EncryptedKey, 'n': Node['h'], 'i': self.RequestID}])

    def MoveNode(self, Node, ParentNode): 
        self._APIRequest({'a': 'm', 'n': Node['h'], 't': ParentNode['h'], 'i': self.RequestID})

    def DeleteNode(self, Node):
        self._APIRequest({'a': 'd', 'n': Node['h'], 'i': self.RequestID})
        
    def EmptyNode(self, Node):
        ChildrenNodes = self.GetChlidrenNodes(Node)
        if len(ChildrenNodes) == 0:
            return
        RequestList = []
        for ChildrenNodeID in ChildrenNodes:
            RequestList.append({"a": "d", "n": ChildrenNodeID, "i": self.RequestID})
        return self._APIRequest(RequestList)

    def CreatePublicURL(self, Node=None, UploadResult=None):
        if (Node is None) and (UploadResult is None):
            raise ValueError("You must specify at least one parameter")
        if Node is not None:
            if not ('h' in Node and 'k' in Node):
                raise ValidationError("This is not valid node")
            PublicHandle = self._APIRequest({'a': 'l', 'n': Node['h']})
            DecryptedKey = Node['key']
        else:
            PublicHandle = self._APIRequest({'a': 'l', 'n': UploadResult['h']})
            UploadedFileKey = UploadResult['k'][UploadResult['k'].index(':') + 1:]
            DecryptedKey = DecryptKey(Base64ToBytes(UploadedFileKey), self.MasterKey)            
        return "{0}/#!{1}!{2}".format(self.MEGAAddress, PublicHandle, BytesToBase64(DecryptedKey))
    
    def ImportPublicURL(self, URL, ParentNode):
        URLData = self._GetURLData(URL)
        URLKey = Base64ToBytes(URLData[1])
        FileKey = (URLKey[0] ^ URLKey[4], URLKey[1] ^ URLKey[5], URLKey[2] ^ URLKey[6], URLKey[3] ^ URLKey[7])        
        EncryptedKey = BytesToBase64(EncryptKey(URLKey, self.MasterKey))
        EncryptedName = Base64URLEncode(EncryptAttribute({'n': self._GetPublicFileInformation(URLData[0], FileKey)[0]}, FileKey))
        return self._APIRequest({'a': 'p', 't': ParentNode['h'], 'n': [{'ph': URLData[0], 't': 0, 'a': EncryptedName, 'k': EncryptedKey}]})
        
    def GetPublicURLInformation(self, URL):
        URLData = self._GetURLData(URL)
        URLKey = Base64ToBytes(URLData[1])
        FileKey = (URLKey[0] ^ URLKey[4], URLKey[1] ^ URLKey[5], URLKey[2] ^ URLKey[6], URLKey[3] ^ URLKey[7])        
        return self._GetPublicFileInformation(URLData[0], FileKey)    
    
    def _GetPublicFileInformation(self, FileHandle, FileKey):
        FileData = self._APIRequest({'a': 'g', 'p': FileHandle, 'ssm': 1})
        if 'at' not in FileData or 's' not in FileData:
            raise RequestError("Could not get data from provided URL", FileData)
        return (DecryptAttribute(Base64URLDecode(FileData['at']), FileKey)['n'], FileData['s'])