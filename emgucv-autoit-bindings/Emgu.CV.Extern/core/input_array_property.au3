#include-once
#include "..\..\CVEUtils.au3"

Func _cveInputArrayIsMat(ByRef $obj)
    ; CVAPI(bool) cveInputArrayIsMat(cv::_InputArray* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsMat", "ptr", $obj), "cveInputArrayIsMat", @error)
EndFunc   ;==>_cveInputArrayIsMat

Func _cveInputArrayIsMatMat(ByRef $matObj)
    ; cveInputArrayIsMat using cv::Mat instead of _*Array

    Local $iArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $iArrObj = _cveInputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $iArrObj = _cveInputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveInputArrayIsMat($iArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveInputArrayRelease($iArrObj)

    Return $retval
EndFunc   ;==>_cveInputArrayIsMatMat

Func _cveInputArrayIsUMat(ByRef $obj)
    ; CVAPI(bool) cveInputArrayIsUMat(cv::_InputArray* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsUMat", "ptr", $obj), "cveInputArrayIsUMat", @error)
EndFunc   ;==>_cveInputArrayIsUMat

Func _cveInputArrayIsUMatMat(ByRef $matObj)
    ; cveInputArrayIsUMat using cv::Mat instead of _*Array

    Local $iArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $iArrObj = _cveInputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $iArrObj = _cveInputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveInputArrayIsUMat($iArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveInputArrayRelease($iArrObj)

    Return $retval
EndFunc   ;==>_cveInputArrayIsUMatMat

Func _cveInputArrayIsMatVector(ByRef $obj)
    ; CVAPI(bool) cveInputArrayIsMatVector(cv::_InputArray* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsMatVector", "ptr", $obj), "cveInputArrayIsMatVector", @error)
EndFunc   ;==>_cveInputArrayIsMatVector

Func _cveInputArrayIsMatVectorMat(ByRef $matObj)
    ; cveInputArrayIsMatVector using cv::Mat instead of _*Array

    Local $iArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $iArrObj = _cveInputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $iArrObj = _cveInputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveInputArrayIsMatVector($iArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveInputArrayRelease($iArrObj)

    Return $retval
EndFunc   ;==>_cveInputArrayIsMatVectorMat

Func _cveInputArrayIsUMatVector(ByRef $obj)
    ; CVAPI(bool) cveInputArrayIsUMatVector(cv::_InputArray* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsUMatVector", "ptr", $obj), "cveInputArrayIsUMatVector", @error)
EndFunc   ;==>_cveInputArrayIsUMatVector

Func _cveInputArrayIsUMatVectorMat(ByRef $matObj)
    ; cveInputArrayIsUMatVector using cv::Mat instead of _*Array

    Local $iArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $iArrObj = _cveInputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $iArrObj = _cveInputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveInputArrayIsUMatVector($iArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveInputArrayRelease($iArrObj)

    Return $retval
EndFunc   ;==>_cveInputArrayIsUMatVectorMat

Func _cveInputArrayIsMatx(ByRef $obj)
    ; CVAPI(bool) cveInputArrayIsMatx(cv::_InputArray* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsMatx", "ptr", $obj), "cveInputArrayIsMatx", @error)
EndFunc   ;==>_cveInputArrayIsMatx

Func _cveInputArrayIsMatxMat(ByRef $matObj)
    ; cveInputArrayIsMatx using cv::Mat instead of _*Array

    Local $iArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $iArrObj = _cveInputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $iArrObj = _cveInputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveInputArrayIsMatx($iArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveInputArrayRelease($iArrObj)

    Return $retval
EndFunc   ;==>_cveInputArrayIsMatxMat

Func _cveInputArrayKind(ByRef $obj)
    ; CVAPI(int) cveInputArrayKind(cv::_InputArray* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayKind", "ptr", $obj), "cveInputArrayKind", @error)
EndFunc   ;==>_cveInputArrayKind

Func _cveInputArrayKindMat(ByRef $matObj)
    ; cveInputArrayKind using cv::Mat instead of _*Array

    Local $iArrObj, $vectorOfMatObj, $iArrObjSize
    Local $bObjIsArray = VarGetType($matObj) == "Array"

    If $bObjIsArray Then
        $vectorOfMatObj = _VectorOfMatCreate()

        $iArrObjSize = UBound($matObj)
        For $i = 0 To $iArrObjSize - 1
            _VectorOfMatPush($vectorOfMatObj, $matObj[$i])
        Next

        $iArrObj = _cveInputArrayFromVectorOfMat($vectorOfMatObj)
    Else
        $iArrObj = _cveInputArrayFromMat($matObj)
    EndIf

    Local $retval = _cveInputArrayKind($iArrObj)

    If $bObjIsArray Then
        _VectorOfMatRelease($vectorOfMatObj)
    EndIf

    _cveInputArrayRelease($iArrObj)

    Return $retval
EndFunc   ;==>_cveInputArrayKindMat