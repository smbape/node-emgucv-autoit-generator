# Emgucv autoit udf

Do you want to use [OpenCV](https://opencv.org/) v4+ in [AutoIt v3](https://www.autoitscript.com/) ?  
This udf might be for you.

# Usage of the UDF

Download [libemgucv-windesktop-4.5.2.4673.zip](https://github.com/emgucv/emgucv/releases/download/4.5.2/libemgucv-windesktop-4.5.2.4673.zip) and extract it a folder
Download the emgucv-autoit-bindings folder

Then in you autoit file

```autoit
#include "emgucv-autoit-bindings\cve_extra.au3"

_OpenCV_DLLOpen("libemgucv-windesktop-4.5.2.4673\libs\x64\cvextern.dll")

; you the emgucv user defined functions
Local $img = _cveImreadAndCheck("lena.jpg")
_cveImshowMat("Source image", $img )
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($img)

_Opencv_DLLClose()

```

## Running examples

```sh
curl -L 'https://github.com/emgucv/emgucv/releases/download/4.5.2/libemgucv-windesktop-4.5.2.4673.zip' -o libemgucv-windesktop-4.5.2.4673.zip
unzip libemgucv-windesktop-4.5.2.4673.zip -d libemgucv-windesktop-4.5.2.4673
```

## History

I wanted to use [OpenCV](https://opencv.org/) v4+ in [AutoIt v3](https://www.autoitscript.com/).

I found the [Opencv UDF](https://www.autoitscript.com/forum/topic/160732-opencv-udf/) on the forum.  
However it was for [OpenCV](https://opencv.org/) v2 and there was a [question](https://www.autoitscript.com/forum/topic/160732-opencv-udf/?do=findComment&comment=1441185) for [OpenCV](https://opencv.org/) without any anwser.

There was no other option than trying find an answer myself.

[AutoIt v3](https://www.autoitscript.com/) is a freeware BASIC-like scripting language designed for automating the Windows GUI and general scripting.
[AutoIt v3](https://www.autoitscript.com/) can use dynamic libraries (dll).  
However, since v3, [OpenCV](https://opencv.org/) do not expose all the needed functions for image processing. It is now focused on c++ project integration.
This means that, if you want to use [OpenCV](https://opencv.org/) in [AutoIt v3](https://www.autoitscript.com/), you need to write your own dll and export as many functions as you need.

It can be tedious.

It guessed that other languages will have the same problem.  
[AutoIt v3](https://www.autoitscript.com/) is focused on windows and .Net is, at least in the past, focused on windows.  
There was a high chance that an [OpenCV](https://opencv.org/) binding to .Net will have involved dlls.  
I looked for [OpenCV](https://opencv.org/) in .Net and I found [emgucv](https://github.com/emgucv/emgucv).

[emgucv](https://github.com/emgucv/emgucv) is a cross platform .Net wrapper to the [OpenCV](https://opencv.org/) image processing library.  
The project exported almost all the [OpenCV](https://opencv.org/) in a dll, making their dll suitable to be used with [AutoIt v3](https://www.autoitscript.com/)

## Build the addon dll

## Developpement

```sh
git clone https://github.com/smbape/node-emgucv-autoit-generator

cd node-emgucv-autoit-generator
git submodule update --init --recursive

git apply -v emgucv.patch --directory emgucv
find emgucv -type f -name '*.bat' -exec unix2dos '{}' \;

(cd emgucv/platforms/windows; cmd.exe //c Build_Binary_x86-64_doc.bat)
```
