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

Func _cveImgHashBaseComputeTyped($imgHash, $typeOfInputArr, $inputArr, $typeOfOutputArr, $outputArr)

    Local $iArrInputArr, $vectorInputArr, $iArrInputArrSize
    Local $bInputArrIsArray = IsArray($inputArr)
    Local $bInputArrCreate = IsDllStruct($inputArr) And $typeOfInputArr == "Scalar"

    If $typeOfInputArr == Default Then
        $iArrInputArr = $inputArr
    ElseIf $bInputArrIsArray Then
        $vectorInputArr = Call("_VectorOf" & $typeOfInputArr & "Create")

        $iArrInputArrSize = UBound($inputArr)
        For $i = 0 To $iArrInputArrSize - 1
            Call("_VectorOf" & $typeOfInputArr & "Push", $vectorInputArr, $inputArr[$i])
        Next

        $iArrInputArr = Call("_cveInputArrayFromVectorOf" & $typeOfInputArr, $vectorInputArr)
    Else
        If $bInputArrCreate Then
            $inputArr = Call("_cve" & $typeOfInputArr & "Create", $inputArr)
        EndIf
        $iArrInputArr = Call("_cveInputArrayFrom" & $typeOfInputArr, $inputArr)
    EndIf

    Local $oArrOutputArr, $vectorOutputArr, $iArrOutputArrSize
    Local $bOutputArrIsArray = IsArray($outputArr)
    Local $bOutputArrCreate = IsDllStruct($outputArr) And $typeOfOutputArr == "Scalar"

    If $typeOfOutputArr == Default Then
        $oArrOutputArr = $outputArr
    ElseIf $bOutputArrIsArray Then
        $vectorOutputArr = Call("_VectorOf" & $typeOfOutputArr & "Create")

        $iArrOutputArrSize = UBound($outputArr)
        For $i = 0 To $iArrOutputArrSize - 1
            Call("_VectorOf" & $typeOfOutputArr & "Push", $vectorOutputArr, $outputArr[$i])
        Next

        $oArrOutputArr = Call("_cveOutputArrayFromVectorOf" & $typeOfOutputArr, $vectorOutputArr)
    Else
        If $bOutputArrCreate Then
            $outputArr = Call("_cve" & $typeOfOutputArr & "Create", $outputArr)
        EndIf
        $oArrOutputArr = Call("_cveOutputArrayFrom" & $typeOfOutputArr, $outputArr)
    EndIf

    _cveImgHashBaseCompute($imgHash, $iArrInputArr, $oArrOutputArr)

    If $bOutputArrIsArray Then
        Call("_VectorOf" & $typeOfOutputArr & "Release", $vectorOutputArr)
    EndIf

    If $typeOfOutputArr <> Default Then
        _cveOutputArrayRelease($oArrOutputArr)
        If $bOutputArrCreate Then
            Call("_cve" & $typeOfOutputArr & "Release", $outputArr)
        EndIf
    EndIf

    If $bInputArrIsArray Then
        Call("_VectorOf" & $typeOfInputArr & "Release", $vectorInputArr)
    EndIf

    If $typeOfInputArr <> Default Then
        _cveInputArrayRelease($iArrInputArr)
        If $bInputArrCreate Then
            Call("_cve" & $typeOfInputArr & "Release", $inputArr)
        EndIf
    EndIf
EndFunc   ;==>_cveImgHashBaseComputeTyped

Func _cveImgHashBaseComputeMat($imgHash, $inputArr, $outputArr)
    ; cveImgHashBaseCompute using cv::Mat instead of _*Array
    _cveImgHashBaseComputeTyped($imgHash, "Mat", $inputArr, "Mat", $outputArr)
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

Func _cveImgHashBaseCompareTyped($imgHash, $typeOfHashOne, $hashOne, $typeOfHashTwo, $hashTwo)

    Local $iArrHashOne, $vectorHashOne, $iArrHashOneSize
    Local $bHashOneIsArray = IsArray($hashOne)
    Local $bHashOneCreate = IsDllStruct($hashOne) And $typeOfHashOne == "Scalar"

    If $typeOfHashOne == Default Then
        $iArrHashOne = $hashOne
    ElseIf $bHashOneIsArray Then
        $vectorHashOne = Call("_VectorOf" & $typeOfHashOne & "Create")

        $iArrHashOneSize = UBound($hashOne)
        For $i = 0 To $iArrHashOneSize - 1
            Call("_VectorOf" & $typeOfHashOne & "Push", $vectorHashOne, $hashOne[$i])
        Next

        $iArrHashOne = Call("_cveInputArrayFromVectorOf" & $typeOfHashOne, $vectorHashOne)
    Else
        If $bHashOneCreate Then
            $hashOne = Call("_cve" & $typeOfHashOne & "Create", $hashOne)
        EndIf
        $iArrHashOne = Call("_cveInputArrayFrom" & $typeOfHashOne, $hashOne)
    EndIf

    Local $iArrHashTwo, $vectorHashTwo, $iArrHashTwoSize
    Local $bHashTwoIsArray = IsArray($hashTwo)
    Local $bHashTwoCreate = IsDllStruct($hashTwo) And $typeOfHashTwo == "Scalar"

    If $typeOfHashTwo == Default Then
        $iArrHashTwo = $hashTwo
    ElseIf $bHashTwoIsArray Then
        $vectorHashTwo = Call("_VectorOf" & $typeOfHashTwo & "Create")

        $iArrHashTwoSize = UBound($hashTwo)
        For $i = 0 To $iArrHashTwoSize - 1
            Call("_VectorOf" & $typeOfHashTwo & "Push", $vectorHashTwo, $hashTwo[$i])
        Next

        $iArrHashTwo = Call("_cveInputArrayFromVectorOf" & $typeOfHashTwo, $vectorHashTwo)
    Else
        If $bHashTwoCreate Then
            $hashTwo = Call("_cve" & $typeOfHashTwo & "Create", $hashTwo)
        EndIf
        $iArrHashTwo = Call("_cveInputArrayFrom" & $typeOfHashTwo, $hashTwo)
    EndIf

    Local $retval = _cveImgHashBaseCompare($imgHash, $iArrHashOne, $iArrHashTwo)

    If $bHashTwoIsArray Then
        Call("_VectorOf" & $typeOfHashTwo & "Release", $vectorHashTwo)
    EndIf

    If $typeOfHashTwo <> Default Then
        _cveInputArrayRelease($iArrHashTwo)
        If $bHashTwoCreate Then
            Call("_cve" & $typeOfHashTwo & "Release", $hashTwo)
        EndIf
    EndIf

    If $bHashOneIsArray Then
        Call("_VectorOf" & $typeOfHashOne & "Release", $vectorHashOne)
    EndIf

    If $typeOfHashOne <> Default Then
        _cveInputArrayRelease($iArrHashOne)
        If $bHashOneCreate Then
            Call("_cve" & $typeOfHashOne & "Release", $hashOne)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveImgHashBaseCompareTyped

Func _cveImgHashBaseCompareMat($imgHash, $hashOne, $hashTwo)
    ; cveImgHashBaseCompare using cv::Mat instead of _*Array
    Local $retval = _cveImgHashBaseCompareTyped($imgHash, "Mat", $hashOne, "Mat", $hashTwo)

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