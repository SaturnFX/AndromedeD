import Command

import win32api
import win32gui
import win32con
import pywintypes

@Command.CommandFunction()
def Command(WallpaperPath, WallpaperStyle):
    print("Setting wallpaper..")
    try:
        SetWallpaperStyle(int(WallpaperStyle))
        win32gui.SystemParametersInfo(win32con.SPI_SETDESKWALLPAPER, WallpaperPath, win32con.SPIF_UPDATEINIFILE)
    except pywintypes.error as Error:
        print("Could not change desktop wallpaper")

def SetWallpaperStyle(WallpaperStyle):
    RegKey = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, win32con.KEY_WRITE)
    try:
        win32api.RegSetValueEx(RegKey, "WallpaperStyle", 0, win32con.REG_SZ, str(WallpaperStyle & 15))
        win32api.RegSetValueEx(RegKey, "TileWallpaper", 0, win32con.REG_SZ, str(WallpaperStyle >> 4))
    finally:
        RegKey.close()

class WallpaperStyle:
    Tiled = 17
    Centered = 1
    Stretched = 2
    Fit = 6
    Fill = 10