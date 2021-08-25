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

Func _cveInputArrayIsMatTyped($typeOfObj, $obj)

    Local $iArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $iArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $iArrObj = Call("_cveInputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $iArrObj = Call("_cveInputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveInputArrayIsMat($iArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveInputArrayRelease($iArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayIsMatTyped

Func _cveInputArrayIsMatMat($obj)
    ; cveInputArrayIsMat using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayIsMatTyped("Mat", $obj)

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

Func _cveInputArrayIsUMatTyped($typeOfObj, $obj)

    Local $iArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $iArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $iArrObj = Call("_cveInputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $iArrObj = Call("_cveInputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveInputArrayIsUMat($iArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveInputArrayRelease($iArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayIsUMatTyped

Func _cveInputArrayIsUMatMat($obj)
    ; cveInputArrayIsUMat using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayIsUMatTyped("Mat", $obj)

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

Func _cveInputArrayIsMatVectorTyped($typeOfObj, $obj)

    Local $iArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $iArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $iArrObj = Call("_cveInputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $iArrObj = Call("_cveInputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveInputArrayIsMatVector($iArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveInputArrayRelease($iArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayIsMatVectorTyped

Func _cveInputArrayIsMatVectorMat($obj)
    ; cveInputArrayIsMatVector using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayIsMatVectorTyped("Mat", $obj)

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

Func _cveInputArrayIsUMatVectorTyped($typeOfObj, $obj)

    Local $iArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $iArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $iArrObj = Call("_cveInputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $iArrObj = Call("_cveInputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveInputArrayIsUMatVector($iArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveInputArrayRelease($iArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayIsUMatVectorTyped

Func _cveInputArrayIsUMatVectorMat($obj)
    ; cveInputArrayIsUMatVector using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayIsUMatVectorTyped("Mat", $obj)

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

Func _cveInputArrayIsMatxTyped($typeOfObj, $obj)

    Local $iArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $iArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $iArrObj = Call("_cveInputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $iArrObj = Call("_cveInputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveInputArrayIsMatx($iArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveInputArrayRelease($iArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayIsMatxTyped

Func _cveInputArrayIsMatxMat($obj)
    ; cveInputArrayIsMatx using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayIsMatxTyped("Mat", $obj)

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

Func _cveInputArrayKindTyped($typeOfObj, $obj)

    Local $iArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $iArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $iArrObj = Call("_cveInputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $iArrObj = Call("_cveInputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveInputArrayKind($iArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveInputArrayRelease($iArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayKindTyped

Func _cveInputArrayKindMat($obj)
    ; cveInputArrayKind using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayKindTyped("Mat", $obj)

    Return $retval
EndFunc   ;==>_cveInputArrayKindMat