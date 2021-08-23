#include-once
#include "..\..\CVEUtils.au3"

Func _cveOutputArrayFixedSize($obj)
    ; CVAPI(bool) cveOutputArrayFixedSize(cv::_OutputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveOutputArrayFixedSize", $sObjDllType, $obj), "cveOutputArrayFixedSize", @error)
EndFunc   ;==>_cveOutputArrayFixedSize

Func _cveOutputArrayFixedSizeMat($matObj)
    ; cveOutputArrayFixedSize using cv::Mat instead of _*Array

    Local $oArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $oArrObj = _cveOutputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $oArrObj = _cveOutputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveOutputArrayFixedSize($oArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveOutputArrayRelease($oArrObj)

    Return $retval
EndFunc   ;==>_cveOutputArrayFixedSizeMat

Func _cveOutputArrayFixedType($obj)
    ; CVAPI(bool) cveOutputArrayFixedType(cv::_OutputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveOutputArrayFixedType", $sObjDllType, $obj), "cveOutputArrayFixedType", @error)
EndFunc   ;==>_cveOutputArrayFixedType

Func _cveOutputArrayFixedTypeMat($matObj)
    ; cveOutputArrayFixedType using cv::Mat instead of _*Array

    Local $oArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $oArrObj = _cveOutputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $oArrObj = _cveOutputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveOutputArrayFixedType($oArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveOutputArrayRelease($oArrObj)

    Return $retval
EndFunc   ;==>_cveOutputArrayFixedTypeMat

Func _cveOutputArrayNeeded($obj)
    ; CVAPI(bool) cveOutputArrayNeeded(cv::_OutputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveOutputArrayNeeded", $sObjDllType, $obj), "cveOutputArrayNeeded", @error)
EndFunc   ;==>_cveOutputArrayNeeded

Func _cveOutputArrayNeededMat($matObj)
    ; cveOutputArrayNeeded using cv::Mat instead of _*Array

    Local $oArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $oArrObj = _cveOutputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $oArrObj = _cveOutputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveOutputArrayNeeded($oArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveOutputArrayRelease($oArrObj)

    Return $retval
EndFunc   ;==>_cveOutputArrayNeededMat