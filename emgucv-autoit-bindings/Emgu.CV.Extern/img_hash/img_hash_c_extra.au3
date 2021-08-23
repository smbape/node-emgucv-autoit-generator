#include-once
#include "..\..\CVEUtils.au3"

Func _cveImgHashBaseCompute($imgHash, $inputArr, $outputArr)
    ; CVAPI(void) cveImgHashBaseCompute(cv::img_hash::ImgHashBase* imgHash, cv::_InputArray* inputArr, cv::_OutputArray* outputArr);

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    Else
        $sImgHashDllType = "ptr"
    EndIf

    Local $sInputArrDllType
    If IsDllStruct($inputArr) Then
        $sInputArrDllType = "struct*"
    Else
        $sInputArrDllType = "ptr"
    EndIf

    Local $sOutputArrDllType
    If IsDllStruct($outputArr) Then
        $sOutputArrDllType = "struct*"
    Else
        $sOutputArrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImgHashBaseCompute", $sImgHashDllType, $imgHash, $sInputArrDllType, $inputArr, $sOutputArrDllType, $outputArr), "cveImgHashBaseCompute", @error)
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

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    Else
        $sImgHashDllType = "ptr"
    EndIf

    Local $sHashOneDllType
    If IsDllStruct($hashOne) Then
        $sHashOneDllType = "struct*"
    Else
        $sHashOneDllType = "ptr"
    EndIf

    Local $sHashTwoDllType
    If IsDllStruct($hashTwo) Then
        $sHashTwoDllType = "struct*"
    Else
        $sHashTwoDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveImgHashBaseCompare", $sImgHashDllType, $imgHash, $sHashOneDllType, $hashOne, $sHashTwoDllType, $hashTwo), "cveImgHashBaseCompare", @error)
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

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    ElseIf $imgHash == Null Then
        $sImgHashDllType = "ptr"
    Else
        $sImgHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAverageHashCreate", $sImgHashDllType, $imgHash, $sSharedPtrDllType, $sharedPtr), "cveAverageHashCreate", @error)
EndFunc   ;==>_cveAverageHashCreate

Func _cveAverageHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveAverageHashRelease(cv::img_hash::AverageHash** hash, cv::Ptr<cv::img_hash::AverageHash>** sharedPtr);

    Local $sHashDllType
    If IsDllStruct($hash) Then
        $sHashDllType = "struct*"
    ElseIf $hash == Null Then
        $sHashDllType = "ptr"
    Else
        $sHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAverageHashRelease", $sHashDllType, $hash, $sSharedPtrDllType, $sharedPtr), "cveAverageHashRelease", @error)
EndFunc   ;==>_cveAverageHashRelease

Func _cveBlockMeanHashCreate($imgHash, $mode, $sharedPtr)
    ; CVAPI(cv::img_hash::BlockMeanHash*) cveBlockMeanHashCreate(cv::img_hash::ImgHashBase** imgHash, int mode, cv::Ptr<cv::img_hash::BlockMeanHash>** sharedPtr);

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    ElseIf $imgHash == Null Then
        $sImgHashDllType = "ptr"
    Else
        $sImgHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlockMeanHashCreate", $sImgHashDllType, $imgHash, "int", $mode, $sSharedPtrDllType, $sharedPtr), "cveBlockMeanHashCreate", @error)
EndFunc   ;==>_cveBlockMeanHashCreate

Func _cveBlockMeanHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveBlockMeanHashRelease(cv::img_hash::BlockMeanHash** hash, cv::Ptr<cv::img_hash::BlockMeanHash>** sharedPtr);

    Local $sHashDllType
    If IsDllStruct($hash) Then
        $sHashDllType = "struct*"
    ElseIf $hash == Null Then
        $sHashDllType = "ptr"
    Else
        $sHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlockMeanHashRelease", $sHashDllType, $hash, $sSharedPtrDllType, $sharedPtr), "cveBlockMeanHashRelease", @error)
EndFunc   ;==>_cveBlockMeanHashRelease

Func _cveColorMomentHashCreate($imgHash, $sharedPtr)
    ; CVAPI(cv::img_hash::ColorMomentHash*) cveColorMomentHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::ColorMomentHash>** sharedPtr);

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    ElseIf $imgHash == Null Then
        $sImgHashDllType = "ptr"
    Else
        $sImgHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveColorMomentHashCreate", $sImgHashDllType, $imgHash, $sSharedPtrDllType, $sharedPtr), "cveColorMomentHashCreate", @error)
EndFunc   ;==>_cveColorMomentHashCreate

Func _cveColorMomentHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveColorMomentHashRelease(cv::img_hash::ColorMomentHash** hash, cv::Ptr<cv::img_hash::ColorMomentHash>** sharedPtr);

    Local $sHashDllType
    If IsDllStruct($hash) Then
        $sHashDllType = "struct*"
    ElseIf $hash == Null Then
        $sHashDllType = "ptr"
    Else
        $sHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveColorMomentHashRelease", $sHashDllType, $hash, $sSharedPtrDllType, $sharedPtr), "cveColorMomentHashRelease", @error)
EndFunc   ;==>_cveColorMomentHashRelease

Func _cveMarrHildrethHashCreate($imgHash, $alpha, $scale, $sharedPtr)
    ; CVAPI(cv::img_hash::MarrHildrethHash*) cveMarrHildrethHashCreate(cv::img_hash::ImgHashBase** imgHash, float alpha, float scale, cv::Ptr<cv::img_hash::MarrHildrethHash>** sharedPtr);

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    ElseIf $imgHash == Null Then
        $sImgHashDllType = "ptr"
    Else
        $sImgHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMarrHildrethHashCreate", $sImgHashDllType, $imgHash, "float", $alpha, "float", $scale, $sSharedPtrDllType, $sharedPtr), "cveMarrHildrethHashCreate", @error)
EndFunc   ;==>_cveMarrHildrethHashCreate

Func _cveMarrHildrethHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveMarrHildrethHashRelease(cv::img_hash::MarrHildrethHash** hash, cv::Ptr<cv::img_hash::MarrHildrethHash>** sharedPtr);

    Local $sHashDllType
    If IsDllStruct($hash) Then
        $sHashDllType = "struct*"
    ElseIf $hash == Null Then
        $sHashDllType = "ptr"
    Else
        $sHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMarrHildrethHashRelease", $sHashDllType, $hash, $sSharedPtrDllType, $sharedPtr), "cveMarrHildrethHashRelease", @error)
EndFunc   ;==>_cveMarrHildrethHashRelease

Func _cvePHashCreate($imgHash, $sharedPtr)
    ; CVAPI(cv::img_hash::PHash*) cvePHashCreate(cv::img_hash::ImgHashBase** imgHash, cv::Ptr<cv::img_hash::PHash>** sharedPtr);

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    ElseIf $imgHash == Null Then
        $sImgHashDllType = "ptr"
    Else
        $sImgHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePHashCreate", $sImgHashDllType, $imgHash, $sSharedPtrDllType, $sharedPtr), "cvePHashCreate", @error)
EndFunc   ;==>_cvePHashCreate

Func _cvePHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cvePHashRelease(cv::img_hash::PHash** hash, cv::Ptr<cv::img_hash::PHash>** sharedPtr);

    Local $sHashDllType
    If IsDllStruct($hash) Then
        $sHashDllType = "struct*"
    ElseIf $hash == Null Then
        $sHashDllType = "ptr"
    Else
        $sHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePHashRelease", $sHashDllType, $hash, $sSharedPtrDllType, $sharedPtr), "cvePHashRelease", @error)
EndFunc   ;==>_cvePHashRelease

Func _cveRadialVarianceHashCreate($imgHash, $sigma, $numOfAngleLine, $sharedPtr)
    ; CVAPI(cv::img_hash::RadialVarianceHash*) cveRadialVarianceHashCreate(cv::img_hash::ImgHashBase** imgHash, double sigma, int numOfAngleLine, cv::Ptr<cv::img_hash::RadialVarianceHash>** sharedPtr);

    Local $sImgHashDllType
    If IsDllStruct($imgHash) Then
        $sImgHashDllType = "struct*"
    ElseIf $imgHash == Null Then
        $sImgHashDllType = "ptr"
    Else
        $sImgHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRadialVarianceHashCreate", $sImgHashDllType, $imgHash, "double", $sigma, "int", $numOfAngleLine, $sSharedPtrDllType, $sharedPtr), "cveRadialVarianceHashCreate", @error)
EndFunc   ;==>_cveRadialVarianceHashCreate

Func _cveRadialVarianceHashRelease($hash, $sharedPtr)
    ; CVAPI(void) cveRadialVarianceHashRelease(cv::img_hash::RadialVarianceHash** hash, cv::Ptr<cv::img_hash::RadialVarianceHash>** sharedPtr);

    Local $sHashDllType
    If IsDllStruct($hash) Then
        $sHashDllType = "struct*"
    ElseIf $hash == Null Then
        $sHashDllType = "ptr"
    Else
        $sHashDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRadialVarianceHashRelease", $sHashDllType, $hash, $sSharedPtrDllType, $sharedPtr), "cveRadialVarianceHashRelease", @error)
EndFunc   ;==>_cveRadialVarianceHashRelease