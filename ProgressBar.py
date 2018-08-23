import os
import sys
import math

class ProgressBar:
    def __init__(self):
        self.ProgressOffset = 0      
        
    def Set(self, MaximumValue):
        self.MaximumValue = MaximumValue

    def Generate(self, CurrentValue):
        CurrentFactor = CurrentValue / self.MaximumValue
        PercentValue = int(round(CurrentFactor * 100, 0))
        ProgressValue = int(round(CurrentFactor * 32, 0))
        ProgressShift = " " * (2 - math.floor(math.log10(max(PercentValue, 1))))
        return "\r{0}{1}% {2}|{3}{4}|".format(" " * self.ProgressOffset, PercentValue, ProgressShift, "#" * ProgressValue, " " * (32 - ProgressValue))

    def Print(self, CurrentValue):
        ProgressString = self.Generate(CurrentValue)
        sys.stdout.write(ProgressString + " " * (80 - len(ProgressString)))

    def Finish(self):
        sys.stdout.write(os.linesep)
 
import time

class TimeProgressBar(ProgressBar):
    def Set(self, MaximumValue):
        super(TimeProgressBar, self).Set(MaximumValue)
        self.StartTime = time.time()
        
    def UnitTime(self, CurrentValue):
        ElapsedTime = time.time() - self.StartTime
        return ElapsedTime / CurrentValue if CurrentValue != 0 else 0
    
    def ExtensionText(self, CurrentValue, TimeValue):
        EstimatedTime =  math.ceil(TimeValue * (self.MaximumValue - CurrentValue))        
        return " eta " + time.strftime("%H:%M:%S", time.gmtime(EstimatedTime))

    def Generate(self, CurrentValue):
        return super(TimeProgressBar, self).Generate(CurrentValue) + self.ExtensionText(CurrentValue, self.UnitTime(CurrentValue))

import IO

class TransferProgressBar(TimeProgressBar):
    def ExtensionText(self, CurrentValue, TimeValue):
        DownloadSpeed = IO.GetSizeString(math.floor(1 / TimeValue)) if TimeValue != 0 else "0 bytes"
        return " " + IO.GetSizeString(CurrentValue) + " " + DownloadSpeed + "/s" + super(TransferProgressBar, self).ExtensionText(CurrentValue, TimeValue)      
    
if __name__ == "__main__":
    Bar = TransferProgressBar()
    Bar.Set(100)
    for i in range(0, 101):
        Bar.Print(i)
        for i in range(0, 999999):
            pass
    Bar.Finish()
    