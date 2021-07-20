#include-once
#include "..\..\CVEUtils.au3"

Func _cveImgHashBaseCompute($imgHash, $inputArr, $outputArr)
    ; CVAPI(void) cveImgHashBaseCompute(cv::img_hash::ImgHashBase* imgHash, cv::_InputArray* inputArr, cv::_OutputArray* outputArr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImgHashBaseCompute", "ptr", $imgHash, "ptr", $inputArr, "ptr", $outputArr), "cveImgHashBaseCompute", @error)
EndFunc   ;==>_cveImgHashBaseCompute

Func _cveImgHashBaseComputeMat($imgHash, $matInputArr, $matOutputArr)
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

Func _cveImgHashBaseCompare($imgHash, $hashOne, $hashTwo)
    ; CVAPI(double) cveImgHashBaseCompare(cv::img_hash::ImgHashBase* imgHash, cv::_InputArray* hashOne, cv::_InputArray* hashTwo);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveImgHashBaseCompare", "ptr", $imgHash, "ptr", $hashOne, "ptr", $hashTwo), "cveImgHashBaseCompare", @error)
EndFunc   ;==>_cveImgHashBaseCompare

Func _cveImgHashBaseCompareMat($imgHash, $matHashOne, $matHashTwo)
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

Func _cveAverageHashCreate($imgHash, $sharedPtr)
    ; CVAPI(cv::img_hash::AverageHash*) cveAverageHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::AverageHash>** sharedPtr);

    Local $bImgHashDllType
    If VarGetType($imgHash) == "DLLStruct" Then
        $bImgHashDllType = "struct*"
    Else
        $bImgHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAverageHashCreate", $bImgHashDllType, $imgHash, $bSharedPtrDllType, $sharedPtr), "cveAverageHashCreate", @error)
EndFunc   ;==>_cveAverageHashCreate

Func _cveAverageHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveAverageHashRelease(cv::img_hash::AverageHash** hash, cv::Ptr<cv::img_hash::AverageHash>** sharedPtr);

    Local $bHashDllType
    If VarGetType($hash) == "DLLStruct" Then
        $bHashDllType = "struct*"
    Else
        $bHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAverageHashRelease", $bHashDllType, $hash, $bSharedPtrDllType, $sharedPtr), "cveAverageHashRelease", @error)
EndFunc   ;==>_cveAverageHashRelease

Func _cveBlockMeanHashCreate($imgHash, $mode, $sharedPtr)
    ; CVAPI(cv::img_hash::BlockMeanHash*) cveBlockMeanHashCreate(cv::img_hash::ImgHashBase** imgHash, int mode, cv::Ptr<cv::img_hash::BlockMeanHash>** sharedPtr);

    Local $bImgHashDllType
    If VarGetType($imgHash) == "DLLStruct" Then
        $bImgHashDllType = "struct*"
    Else
        $bImgHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlockMeanHashCreate", $bImgHashDllType, $imgHash, "int", $mode, $bSharedPtrDllType, $sharedPtr), "cveBlockMeanHashCreate", @error)
EndFunc   ;==>_cveBlockMeanHashCreate

Func _cveBlockMeanHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveBlockMeanHashRelease(cv::img_hash::BlockMeanHash** hash, cv::Ptr<cv::img_hash::BlockMeanHash>** sharedPtr);

    Local $bHashDllType
    If VarGetType($hash) == "DLLStruct" Then
        $bHashDllType = "struct*"
    Else
        $bHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlockMeanHashRelease", $bHashDllType, $hash, $bSharedPtrDllType, $sharedPtr), "cveBlockMeanHashRelease", @error)
EndFunc   ;==>_cveBlockMeanHashRelease

Func _cveColorMomentHashCreate($imgHash, $sharedPtr)
    ; CVAPI(cv::img_hash::ColorMomentHash*) cveColorMomentHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::ColorMomentHash>** sharedPtr);

    Local $bImgHashDllType
    If VarGetType($imgHash) == "DLLStruct" Then
        $bImgHashDllType = "struct*"
    Else
        $bImgHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveColorMomentHashCreate", $bImgHashDllType, $imgHash, $bSharedPtrDllType, $sharedPtr), "cveColorMomentHashCreate", @error)
EndFunc   ;==>_cveColorMomentHashCreate

Func _cveColorMomentHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveColorMomentHashRelease(cv::img_hash::ColorMomentHash** hash, cv::Ptr<cv::img_hash::ColorMomentHash>** sharedPtr);

    Local $bHashDllType
    If VarGetType($hash) == "DLLStruct" Then
        $bHashDllType = "struct*"
    Else
        $bHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveColorMomentHashRelease", $bHashDllType, $hash, $bSharedPtrDllType, $sharedPtr), "cveColorMomentHashRelease", @error)
EndFunc   ;==>_cveColorMomentHashRelease

Func _cveMarrHildrethHashCreate($imgHash, $alpha, $scale, $sharedPtr)
    ; CVAPI(cv::img_hash::MarrHildrethHash*) cveMarrHildrethHashCreate(cv::img_hash::ImgHashBase** imgHash, float alpha, float scale, cv::Ptr<cv::img_hash::MarrHildrethHash>** sharedPtr);

    Local $bImgHashDllType
    If VarGetType($imgHash) == "DLLStruct" Then
        $bImgHashDllType = "struct*"
    Else
        $bImgHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMarrHildrethHashCreate", $bImgHashDllType, $imgHash, "float", $alpha, "float", $scale, $bSharedPtrDllType, $sharedPtr), "cveMarrHildrethHashCreate", @error)
EndFunc   ;==>_cveMarrHildrethHashCreate

Func _cveMarrHildrethHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveMarrHildrethHashRelease(cv::img_hash::MarrHildrethHash** hash, cv::Ptr<cv::img_hash::MarrHildrethHash>** sharedPtr);

    Local $bHashDllType
    If VarGetType($hash) == "DLLStruct" Then
        $bHashDllType = "struct*"
    Else
        $bHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMarrHildrethHashRelease", $bHashDllType, $hash, $bSharedPtrDllType, $sharedPtr), "cveMarrHildrethHashRelease", @error)
EndFunc   ;==>_cveMarrHildrethHashRelease

Func _cvePHashCreate($imgHash, $sharedPtr)
    ; CVAPI(cv::img_hash::PHash*) cvePHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::PHash>** sharedPtr);

    Local $bImgHashDllType
    If VarGetType($imgHash) == "DLLStruct" Then
        $bImgHashDllType = "struct*"
    Else
        $bImgHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePHashCreate", $bImgHashDllType, $imgHash, $bSharedPtrDllType, $sharedPtr), "cvePHashCreate", @error)
EndFunc   ;==>_cvePHashCreate

Func _cvePHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cvePHashRelease(cv::img_hash::PHash** hash, cv::Ptr<cv::img_hash::PHash>** sharedPtr);

    Local $bHashDllType
    If VarGetType($hash) == "DLLStruct" Then
        $bHashDllType = "struct*"
    Else
        $bHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePHashRelease", $bHashDllType, $hash, $bSharedPtrDllType, $sharedPtr), "cvePHashRelease", @error)
EndFunc   ;==>_cvePHashRelease

Func _cveRadialVarianceHashCreate($imgHash, $sigma, $numOfAngleLine, $sharedPtr)
    ; CVAPI(cv::img_hash::RadialVarianceHash*) cveRadialVarianceHashCreate(cv::img_hash::ImgHashBase** imgHash, double sigma, int numOfAngleLine, cv::Ptr<cv::img_hash::RadialVarianceHash>** sharedPtr);

    Local $bImgHashDllType
    If VarGetType($imgHash) == "DLLStruct" Then
        $bImgHashDllType = "struct*"
    Else
        $bImgHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRadialVarianceHashCreate", $bImgHashDllType, $imgHash, "double", $sigma, "int", $numOfAngleLine, $bSharedPtrDllType, $sharedPtr), "cveRadialVarianceHashCreate", @error)
EndFunc   ;==>_cveRadialVarianceHashCreate

Func _cveRadialVarianceHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveRadialVarianceHashRelease(cv::img_hash::RadialVarianceHash** hash, cv::Ptr<cv::img_hash::RadialVarianceHash>** sharedPtr);

    Local $bHashDllType
    If VarGetType($hash) == "DLLStruct" Then
        $bHashDllType = "struct*"
    Else
        $bHashDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRadialVarianceHashRelease", $bHashDllType, $hash, $bSharedPtrDllType, $sharedPtr), "cveRadialVarianceHashRelease", @error)
EndFunc   ;==>_cveRadialVarianceHashRelease