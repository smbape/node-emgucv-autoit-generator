# Emgucv autoit udf

Do you want to use [OpenCV](https://opencv.org/) v4+ in [AutoIt v3](https://www.autoitscript.com/) ?  
If yes, then this udf might be for you.

# Usage of the UDF

## Prerequisites

  - Download and extract [libemgucv-windesktop-4.5.3.4721.zip](https://github.com/emgucv/emgucv/releases/download/4.5.3/libemgucv-windesktop-4.5.3.4721.zip) into a folder
  - Download and extract [emgucv-autoit-bindings-v1.0.0-rc.0.zip](https://github.com/smbape/node-emgucv-autoit-generator/releases/download/v1.0.0-rc.0/emgucv-autoit-bindings-v1.0.0-rc.0.zip) into a folder

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

## How to translate python/c++ code to the UDF

  - Finding the functions/constants names.
  - Transform the parameter types according to the UDF parameter. This step might involve looking at the [opencv documentation](https://docs.opencv.org/4.5.3/index.html).
  - Adjust the return type and variable. This step might involve looking at the [opencv documentation](https://docs.opencv.org/4.5.3/index.html).

### Finding the functions/constants names

For a function named **foo** or **Foo**, there is usually a function named `_cve`**Foo**

For a constant **FOO**, there is usually a Global Const ending with `_FOO` and starting with `$CV_`

### Transform the parameter types

For **cv::Point**, **cv::Range**, **cv::Rect**, **cv::Scalar** and **cv::Size** types, there are `_cv`**Point**, `_cv`**Range**, `_cv`**Rect**, `_cv`**Scalar** and `_cv`**Size** to convert parameters.

For **cv::ScalarAll**, there is **_cvScalarAll**

Types which are **\*Array** like **cv::\_InputArray**, are harder to translate because there is no automatic convertion in AutoIt like in c++.  
For this reason, for functionc which take those type of parameters, there will be 2 additionnal functions.  
`_cve`**Foo**`Typed` where you specified the type of the Array parameter and  
`_cve`**Foo**`Mat` where you specified the type of all the Array parameter are `Mat`.

For *vector*s, there are functions starting with `_VectorOf` that allows to managed.  
For example, for `std::vector<int>*`, there is
  - `_VectorOfInt`
  - `_VectorOfIntCreateSize`
  - `_VectorOfIntGetSize`
  - `_VectorOfIntPush`
  - `_VectorOfIntPushMulti`
  - `_VectorOfIntPushVector`
  - `_VectorOfIntClear`
  - `_VectorOfIntRelease`
  - `_VectorOfIntCopyData`
  - `_VectorOfIntGetStartAddress`
  - `_VectorOfIntGetEndAddress`
  - `_VectorOfIntGetItem`
  - `_VectorOfIntGetItemPtr`
  - `_VectorOfIntSizeOfItemInBytes`

### Example

Let's translate the following python code
```python
blurred = cv2.GaussianBlur(image, (3, 3), 0)
T, thresh_img = cv2.threshold(blurred, 215, 255, cv2.THRESH_BINARY)
cnts, _ = cv2.findContours(thresh_img, 
                                cv2.RETR_EXTERNAL, 
                                cv2.CHAIN_APPROX_SIMPLE)
```

#### First line

```python
blurred = cv2.GaussianBlur(image, (3, 3), 0)
```

The UDF function is
```autoit
Func _cveGaussianBlur($src, $dst, $ksize, $sigmaX, $sigmaY = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveGaussianBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* ksize, double sigmaX, double sigmaY, int borderType);
```

The [GaussianBlur](https://docs.opencv.org/4.5.3/d4/d86/group__imgproc__filter.html#gaabe8c836e97159a9193fb0b11ac52cf1) documentation gives the following information
```txt
void cv::GaussianBlur   (   InputArray    src,
    OutputArray   dst,
    Size    ksize,
    double    sigmaX,
    double    sigmaY = 0,
    int   borderType = BORDER_DEFAULT 
  )     
Python:
  cv.GaussianBlur(  src, ksize, sigmaX[, dst[, sigmaY[, borderType]]] ) ->  dst

src input image;
dst output image;
```

In python, the returned value `dst`, is the `OutputArray dst` parameter of the c++ function, hence the UDF function.  
`src` and `dst` are images, that means of type `Mat`

Because there are `Array` parameters, we have to use the `Typed` version of the version which allows to specify the type the `Array` parameters.

The python will therefore become
```autoit
$blurred = _cveMatCreate()
_cveGaussianBlurTyped("Mat", $image, "Mat", $blurred, _cvSize(3, 3), 0)
```

And because all the `Array` types are `Mat`, it is equivalent to
```autoit
$blurred = _cveMatCreate()
_cveGaussianBlurMat($image, $blurred, _cvSize(3, 3), 0)
```

#### Second line

```python
T, thresh_img = cv2.threshold(blurred, 215, 255, cv2.THRESH_BINARY)
```

Applying the same steps give

```autoit
$thresh_img = _cveMatCreate()
_cveThresholdMat($blurred, $thresh_img, 215, 255, $CV_THRESH_BINARY)
```

#### Third line

```python
cnts, _ = cv2.findContours(thresh_img, 
                                cv2.RETR_EXTERNAL, 
                                cv2.CHAIN_APPROX_SIMPLE)
```

Accoroding to [findContours](https://docs.opencv.org/4.5.3/d3/dc0/group__imgproc__shape.html#gadf1ad6a0b82947fa1fe3c3d497f260e0) documentation  
*countours* is a *std::vector\<std::vector\<cv::Point\> \>*  

The python code will become
```autoit
$cnts = _VectorOfVectorOfPointCreate()
$hierarchy = _cveMatCreate()
_cveFindContoursTyped("Mat", $thresh_img, "VectorOfVectorOfPoint", $cnts, "Mat", $hierarchy, $CV_RETR_EXTERNAL, $CV_CHAIN_APPROX_SIMPLE)
```

#### Final result

```autoit
$blurred = _cveMatCreate()
_cveGaussianBlurTyped("Mat", $image, "Mat", $blurred, _cvSize(3, 3), 0)

$thresh_img = _cveMatCreate()
_cveThresholdMat($blurred, $thresh_img, 215, 255, $CV_THRESH_BINARY)

$cnts = _VectorOfVectorOfPointCreate()
$hierarchy = _cveMatCreate()
_cveFindContoursTyped("Mat", $thresh_img, "VectorOfVectorOfPoint", $cnts, "Mat", $hierarchy, $CV_RETR_EXTERNAL, $CV_CHAIN_APPROX_SIMPLE)
```

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
