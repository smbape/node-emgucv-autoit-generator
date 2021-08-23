#include-once
#include "..\..\CVEUtils.au3"

Func _cveInputArrayIsMat($obj)
    ; CVAPI(bool) cveInputArrayIsMat(cv::_InputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsMat", $sObjDllType, $obj), "cveInputArrayIsMat", @error)
EndFunc   ;==>_cveInputArrayIsMat

Func _cveInputArrayIsMatMat($matObj)
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

Func _cveInputArrayIsUMat($obj)
    ; CVAPI(bool) cveInputArrayIsUMat(cv::_InputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsUMat", $sObjDllType, $obj), "cveInputArrayIsUMat", @error)
EndFunc   ;==>_cveInputArrayIsUMat

Func _cveInputArrayIsUMatMat($matObj)
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

Func _cveInputArrayIsMatVector($obj)
    ; CVAPI(bool) cveInputArrayIsMatVector(cv::_InputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsMatVector", $sObjDllType, $obj), "cveInputArrayIsMatVector", @error)
EndFunc   ;==>_cveInputArrayIsMatVector

Func _cveInputArrayIsMatVectorMat($matObj)
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

Func _cveInputArrayIsUMatVector($obj)
    ; CVAPI(bool) cveInputArrayIsUMatVector(cv::_InputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsUMatVector", $sObjDllType, $obj), "cveInputArrayIsUMatVector", @error)
EndFunc   ;==>_cveInputArrayIsUMatVector

Func _cveInputArrayIsUMatVectorMat($matObj)
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

Func _cveInputArrayIsMatx($obj)
    ; CVAPI(bool) cveInputArrayIsMatx(cv::_InputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsMatx", $sObjDllType, $obj), "cveInputArrayIsMatx", @error)
EndFunc   ;==>_cveInputArrayIsMatx

Func _cveInputArrayIsMatxMat($matObj)
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

Func _cveInputArrayKind($obj)
    ; CVAPI(int) cveInputArrayKind(cv::_InputArray* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayKind", $sObjDllType, $obj), "cveInputArrayKind", @error)
EndFunc   ;==>_cveInputArrayKind

Func _cveInputArrayKindMat($matObj)
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