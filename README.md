# Emgucv autoit udf

Do you want to use [OpenCV](https://opencv.org/) v4+ in [AutoIt v3](https://www.autoitscript.com/) ?  
If yes, then this udf might be for you.

# Usage of the UDF

## Prerequisites

  - Download and extract [libemgucv-windesktop-4.5.3.4721.zip](https://github.com/emgucv/emgucv/releases/download/4.5.3/libemgucv-windesktop-4.5.3.4721.zip) into a folder
  - Download the emgucv-autoit-bindings folder of this repository.

## Usage

```autoit
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include "emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $img = _cveImreadAndCheck("data\lena.jpg")
_cveImshowMat("Image", $img)
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()

```

## Running examples

```sh
# get the source files
git clone https://github.com/smbape/node-emgucv-autoit-generator
cd node-emgucv-autoit-generator

# download libemgucv-windesktop-4.5.3.4721 
curl -L 'https://github.com/emgucv/emgucv/releases/download/4.5.3/libemgucv-windesktop-4.5.3.4721.zip' -o libemgucv-windesktop-4.5.3.4721.zip
unzip libemgucv-windesktop-4.5.3.4721.zip -d libemgucv-windesktop-4.5.3.4721

```

Now you can run any file in the `samples\tutorial_code` folder.

### \[optional\] Build the addon dll

This shows how to put performance critical tasks in c++ functions, export those functions in a dll and then use them in autoit.

Look at `samples\tutorial_code\Histograms_Matching\calcHist_Demo.au3` for an example of usage.

#### Prerequisite

  - Install [CMAKE >= 3.5](https://cmake.org/download/)
  - Install [visual studio >= 10](https://visualstudio.microsoft.com/vs/community/)

#### Building

Run `build.bat` script located in the `autoit-addon` folder. 

## Developpement

### Prerequisites

  - Install [CMAKE >= 3.5](https://cmake.org/download/)
  - Install [visual studio >= 2017](https://visualstudio.microsoft.com/vs/community/)
  - Install [Git for Windows](https://gitforwindows.org/)
  - Install [nodejs](https://nodejs.org/en/download/)

### Environment

In Git BASH, excute the following commands

```sh
# get the source files
git clone https://github.com/smbape/node-emgucv-autoit-generator
cd node-emgucv-autoit-generator

# Install nodejs dependencies
npm ci

# Install submodules
git submodule update --init --recursive

# Build emgucv cvextern.dll
git apply -v emgucv.patch --directory emgucv
find emgucv/ -type f -name '*.bat' -exec unix2dos '{}' \;
(cd $(realpath emgucv)/platforms/windows; CMAKE_BUILD_TYPE=Release ADDITIONAL_BUILD_TARGET=opencv_modules cmd.exe //c Build_Binary_x86.bat 64 nogpu vc no-openni "" "" build)
```

### Generate the UDF files

```sh
node generate.js
```

## History

I wanted to use [OpenCV](https://opencv.org/) v4+ in [AutoIt v3](https://www.autoitscript.com/).

I found the [Opencv UDF](https://www.autoitscript.com/forum/topic/160732-opencv-udf/) on the forum.  
However it was for [OpenCV](https://opencv.org/) v2 and there was a [question](https://www.autoitscript.com/forum/topic/160732-opencv-udf/?do=findComment&comment=1441185) for [OpenCV](https://opencv.org/) v4+ without any anwser.

Therefore, there was no other option than trying find an answer myself.

[AutoIt v3](https://www.autoitscript.com/) is a freeware BASIC-like scripting language designed for automating the Windows GUI and general scripting.  
[AutoIt v3](https://www.autoitscript.com/) can use dynamic libraries (dll).  
However, since v3, [OpenCV](https://opencv.org/) does not expose all the needed functions for image processing.  
It is now focused on c++ project integration.  
That means, if you want to use [OpenCV](https://opencv.org/) in [AutoIt v3](https://www.autoitscript.com/),   
you will need to write your own dll and export as many functions as you need.

It can be tedious.

I supposed that other languages will have the same problem.  
[AutoIt v3](https://www.autoitscript.com/) is focused on windows and .Net is, at least in the past, focused on windows.  
There was a high chance that an [OpenCV](https://opencv.org/) binding to .Net will involve dlls.

Therefore, I looked for [OpenCV](https://opencv.org/) in .Net and I found [emgucv](https://github.com/emgucv/emgucv).

[emgucv](https://github.com/emgucv/emgucv) is a cross platform .Net wrapper to the [OpenCV](https://opencv.org/) image processing library.  
The project has exported almost all the [OpenCV](https://opencv.org/) functions in a dll, making their dll suitable to be used with [AutoIt v3](https://www.autoitscript.com/)
