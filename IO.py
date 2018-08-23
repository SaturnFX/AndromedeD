import os
import math

def CopyDirectory(SourceDirectory, DestinationDirectory):
    DestinationPath = ""
    if not os.path.isdir(DestinationDirectory):
        os.mkdir(DestinationDirectory)
    for CurrentName in os.listdir(SourceDirectory):
        SourcePath = os.path.join(SourceDirectory, CurrentName)
        DestinationPath = os.path.join(DestinationDirectory, CurrentName)
        if os.path.isfile(SourcePath):
            CopyFile(SourcePath, DestinationPath)
        else:
            CopyDirectory(SourcePath, DestinationPath)
    
def CopyFile(SourcePath, DestinationPath):
    with open(SourcePath, "rb") as SourceFile:
        with open(DestinationPath, "wb") as DestinationFile:
            CopyStream(SourceFile, DestinationFile)
    
def CopyStream(SourceFile, DestinationFile):
    BufferSize = 16384
    Buffer = SourceFile.read(BufferSize)
    while Buffer:
        DestinationFile.write(Buffer)
        Buffer = SourceFile.read(BufferSize)

def GetDirectorySize(DirectoryPath):
    DirectorySize = 0
    for DirectoryPath, Directories, Files in os.walk(Path):
        for FileName in Files:
            DirectorySize = DirectorySize + os.path.getsize(os.path.join(DirectoryPath, FileName))
    return DirectorySize

def GetSizeString(Size):
    Suffixes = ["bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"]
    Exponent = math.floor(math.log(max(Size, 1), 1024))
    Value = Size / (1024 ** Exponent)
    return "{0:.2f}".format(Value).rstrip("0").rstrip(".") + " " + Suffixes[Exponent]