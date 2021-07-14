#include-once
#include <..\..\CVEUtils.au3>

Func _cveImgHashBaseCompute(ByRef $imgHash, ByRef $inputArr, ByRef $outputArr)
    ; CVAPI(void) cveImgHashBaseCompute(cv::img_hash::ImgHashBase* imgHash, cv::_InputArray* inputArr, cv::_OutputArray* outputArr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImgHashBaseCompute", "ptr", $imgHash, "ptr", $inputArr, "ptr", $outputArr), "cveImgHashBaseCompute", @error)
EndFunc   ;==>_cveImgHashBaseCompute

Func _cveImgHashBaseComputeMat(ByRef $imgHash, ByRef $matInputArr, ByRef $matOutputArr)
    ; cveImgHashBaseCompute using cv::Mat instead of _*Array

    Local $iArrInputArr, $vectorOfMatInputArr, $iArrInputArrSize
    Local $bInputArrIsArray = VarGetType($matInputArr) == "Array"

    If $bInputArrIsArray Then
        $vectorOfMatInputArr = _VectorOfMatCreate()

        $iArrInputArrSize = UBound($matInputArr)
        For $i = 0 To $iArrInputArrSize - 1
            _VectorOfMatPush($vectorOfMatInputArr, $matInputArr[$i])
        Next

        $iArrInputArr = _cveInputArrayFromVectorOfMat($vectorOfMatInputArr)
    Else
        $iArrInputArr = _cveInputArrayFromMat($matInputArr)
    EndIf

    Local $oArrOutputArr, $vectorOfMatOutputArr, $iArrOutputArrSize
    Local $bOutputArrIsArray = VarGetType($matOutputArr) == "Array"

    If $bOutputArrIsArray Then
        $vectorOfMatOutputArr = _VectorOfMatCreate()

        $iArrOutputArrSize = UBound($matOutputArr)
        For $i = 0 To $iArrOutputArrSize - 1
            _VectorOfMatPush($vectorOfMatOutputArr, $matOutputArr[$i])
        Next

        $oArrOutputArr = _cveOutputArrayFromVectorOfMat($vectorOfMatOutputArr)
    Else
        $oArrOutputArr = _cveOutputArrayFromMat($matOutputArr)
    EndIf

    _cveImgHashBaseCompute($imgHash, $iArrInputArr, $oArrOutputArr)

    If $bOutputArrIsArray Then
        _VectorOfMatRelease($vectorOfMatOutputArr)
    EndIf

    _cveOutputArrayRelease($oArrOutputArr)

    If $bInputArrIsArray Then
        _VectorOfMatRelease($vectorOfMatInputArr)
    EndIf

    _cveInputArrayRelease($iArrInputArr)
EndFunc   ;==>_cveImgHashBaseComputeMat

Func _cveImgHashBaseCompare(ByRef $imgHash, ByRef $hashOne, ByRef $hashTwo)
    ; CVAPI(double) cveImgHashBaseCompare(cv::img_hash::ImgHashBase* imgHash, cv::_InputArray* hashOne, cv::_InputArray* hashTwo);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveImgHashBaseCompare", "ptr", $imgHash, "ptr", $hashOne, "ptr", $hashTwo), "cveImgHashBaseCompare", @error)
EndFunc   ;==>_cveImgHashBaseCompare

Func _cveImgHashBaseCompareMat(ByRef $imgHash, ByRef $matHashOne, ByRef $matHashTwo)
    ; cveImgHashBaseCompare using cv::Mat instead of _*Array

    Local $iArrHashOne, $vectorOfMatHashOne, $iArrHashOneSize
    Local $bHashOneIsArray = VarGetType($matHashOne) == "Array"

    If $bHashOneIsArray Then
        $vectorOfMatHashOne = _VectorOfMatCreate()

        $iArrHashOneSize = UBound($matHashOne)
        For $i = 0 To $iArrHashOneSize - 1
            _VectorOfMatPush($vectorOfMatHashOne, $matHashOne[$i])
        Next

        $iArrHashOne = _cveInputArrayFromVectorOfMat($vectorOfMatHashOne)
    Else
        $iArrHashOne = _cveInputArrayFromMat($matHashOne)
    EndIf

    Local $iArrHashTwo, $vectorOfMatHashTwo, $iArrHashTwoSize
    Local $bHashTwoIsArray = VarGetType($matHashTwo) == "Array"

    If $bHashTwoIsArray Then
        $vectorOfMatHashTwo = _VectorOfMatCreate()

        $iArrHashTwoSize = UBound($matHashTwo)
        For $i = 0 To $iArrHashTwoSize - 1
            _VectorOfMatPush($vectorOfMatHashTwo, $matHashTwo[$i])
        Next

        $iArrHashTwo = _cveInputArrayFromVectorOfMat($vectorOfMatHashTwo)
    Else
        $iArrHashTwo = _cveInputArrayFromMat($matHashTwo)
    EndIf

    Local $retval = _cveImgHashBaseCompare($imgHash, $iArrHashOne, $iArrHashTwo)

    If $bHashTwoIsArray Then
        _VectorOfMatRelease($vectorOfMatHashTwo)
    EndIf

    _cveInputArrayRelease($iArrHashTwo)

    If $bHashOneIsArray Then
        _VectorOfMatRelease($vectorOfMatHashOne)
    EndIf

    _cveInputArrayRelease($iArrHashOne)

    Return $retval
EndFunc   ;==>_cveImgHashBaseCompareMat

Func _cveAverageHashCreate(ByRef $imgHash, ByRef $sharedPtr)
    ; CVAPI(cv::img_hash::AverageHash*) cveAverageHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::AverageHash>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAverageHashCreate", "ptr*", $imgHash, "ptr*", $sharedPtr), "cveAverageHashCreate", @error)
EndFunc   ;==>_cveAverageHashCreate

Func _cveAverageHashRelease(ByRef $hash, ByRef $sharedPtr)
    ; CVAPI(void) cveAverageHashRelease(cv::img_hash::AverageHash** hash, cv::Ptr<cv::img_hash::AverageHash>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAverageHashRelease", "ptr*", $hash, "ptr*", $sharedPtr), "cveAverageHashRelease", @error)
EndFunc   ;==>_cveAverageHashRelease

Func _cveBlockMeanHashCreate(ByRef $imgHash, $mode, ByRef $sharedPtr)
    ; CVAPI(cv::img_hash::BlockMeanHash*) cveBlockMeanHashCreate(cv::img_hash::ImgHashBase** imgHash, int mode, cv::Ptr<cv::img_hash::BlockMeanHash>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlockMeanHashCreate", "ptr*", $imgHash, "int", $mode, "ptr*", $sharedPtr), "cveBlockMeanHashCreate", @error)
EndFunc   ;==>_cveBlockMeanHashCreate

Func _cveBlockMeanHashRelease(ByRef $hash, ByRef $sharedPtr)
    ; CVAPI(void) cveBlockMeanHashRelease(cv::img_hash::BlockMeanHash** hash, cv::Ptr<cv::img_hash::BlockMeanHash>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlockMeanHashRelease", "ptr*", $hash, "ptr*", $sharedPtr), "cveBlockMeanHashRelease", @error)
EndFunc   ;==>_cveBlockMeanHashRelease

Func _cveColorMomentHashCreate(ByRef $imgHash, ByRef $sharedPtr)
    ; CVAPI(cv::img_hash::ColorMomentHash*) cveColorMomentHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::ColorMomentHash>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveColorMomentHashCreate", "ptr*", $imgHash, "ptr*", $sharedPtr), "cveColorMomentHashCreate", @error)
EndFunc   ;==>_cveColorMomentHashCreate

Func _cveColorMomentHashRelease(ByRef $hash, ByRef $sharedPtr)
    ; CVAPI(void) cveColorMomentHashRelease(cv::img_hash::ColorMomentHash** hash, cv::Ptr<cv::img_hash::ColorMomentHash>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveColorMomentHashRelease", "ptr*", $hash, "ptr*", $sharedPtr), "cveColorMomentHashRelease", @error)
EndFunc   ;==>_cveColorMomentHashRelease

Func _cveMarrHildrethHashCreate(ByRef $imgHash, $alpha, $scale, ByRef $sharedPtr)
    ; CVAPI(cv::img_hash::MarrHildrethHash*) cveMarrHildrethHashCreate(cv::img_hash::ImgHashBase** imgHash, float alpha, float scale, cv::Ptr<cv::img_hash::MarrHildrethHash>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMarrHildrethHashCreate", "ptr*", $imgHash, "float", $alpha, "float", $scale, "ptr*", $sharedPtr), "cveMarrHildrethHashCreate", @error)
EndFunc   ;==>_cveMarrHildrethHashCreate

Func _cveMarrHildrethHashRelease(ByRef $hash, ByRef $sharedPtr)
    ; CVAPI(void) cveMarrHildrethHashRelease(cv::img_hash::MarrHildrethHash** hash, cv::Ptr<cv::img_hash::MarrHildrethHash>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMarrHildrethHashRelease", "ptr*", $hash, "ptr*", $sharedPtr), "cveMarrHildrethHashRelease", @error)
EndFunc   ;==>_cveMarrHildrethHashRelease

Func _cvePHashCreate(ByRef $imgHash, ByRef $sharedPtr)
    ; CVAPI(cv::img_hash::PHash*) cvePHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::PHash>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePHashCreate", "ptr*", $imgHash, "ptr*", $sharedPtr), "cvePHashCreate", @error)
EndFunc   ;==>_cvePHashCreate

Func _cvePHashRelease(ByRef $hash, ByRef $sharedPtr)
    ; CVAPI(void) cvePHashRelease(cv::img_hash::PHash** hash, cv::Ptr<cv::img_hash::PHash>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePHashRelease", "ptr*", $hash, "ptr*", $sharedPtr), "cvePHashRelease", @error)
EndFunc   ;==>_cvePHashRelease

Func _cveRadialVarianceHashCreate(ByRef $imgHash, $sigma, $numOfAngleLine, ByRef $sharedPtr)
    ; CVAPI(cv::img_hash::RadialVarianceHash*) cveRadialVarianceHashCreate(cv::img_hash::ImgHashBase** imgHash, double sigma, int numOfAngleLine, cv::Ptr<cv::img_hash::RadialVarianceHash>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRadialVarianceHashCreate", "ptr*", $imgHash, "double", $sigma, "int", $numOfAngleLine, "ptr*", $sharedPtr), "cveRadialVarianceHashCreate", @error)
EndFunc   ;==>_cveRadialVarianceHashCreate

Func _cveRadialVarianceHashRelease(ByRef $hash, ByRef $sharedPtr)
    ; CVAPI(void) cveRadialVarianceHashRelease(cv::img_hash::RadialVarianceHash** hash, cv::Ptr<cv::img_hash::RadialVarianceHash>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRadialVarianceHashRelease", "ptr*", $hash, "ptr*", $sharedPtr), "cveRadialVarianceHashRelease", @error)
EndFunc   ;==>_cveRadialVarianceHashRelease