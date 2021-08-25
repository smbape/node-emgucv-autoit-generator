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

Func _cveOutputArrayFixedSizeTyped($typeOfObj, $obj)

    Local $oArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $oArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $oArrObj = Call("_cveOutputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $oArrObj = Call("_cveOutputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveOutputArrayFixedSize($oArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveOutputArrayRelease($oArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFixedSizeTyped

Func _cveOutputArrayFixedSizeMat($obj)
    ; cveOutputArrayFixedSize using cv::Mat instead of _*Array
    Local $retval = _cveOutputArrayFixedSizeTyped("Mat", $obj)

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

Func _cveOutputArrayFixedTypeTyped($typeOfObj, $obj)

    Local $oArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $oArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $oArrObj = Call("_cveOutputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $oArrObj = Call("_cveOutputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveOutputArrayFixedType($oArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveOutputArrayRelease($oArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFixedTypeTyped

Func _cveOutputArrayFixedTypeMat($obj)
    ; cveOutputArrayFixedType using cv::Mat instead of _*Array
    Local $retval = _cveOutputArrayFixedTypeTyped("Mat", $obj)

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

Func _cveOutputArrayNeededTyped($typeOfObj, $obj)

    Local $oArrObj, $vectorObj, $iArrObjSize
    Local $bObjIsArray = IsArray($obj)
    Local $bObjCreate = IsDllStruct($obj) And $typeOfObj == "Scalar"

    If $typeOfObj == Default Then
        $oArrObj = $obj
    ElseIf $bObjIsArray Then
        $vectorObj = Call("_VectorOf" & $typeOfObj & "Create")

        $iArrObjSize = UBound($obj)
        For $i = 0 To $iArrObjSize - 1
            Call("_VectorOf" & $typeOfObj & "Push", $vectorObj, $obj[$i])
        Next

        $oArrObj = Call("_cveOutputArrayFromVectorOf" & $typeOfObj, $vectorObj)
    Else
        If $bObjCreate Then
            $obj = Call("_cve" & $typeOfObj & "Create", $obj)
        EndIf
        $oArrObj = Call("_cveOutputArrayFrom" & $typeOfObj, $obj)
    EndIf

    Local $retval = _cveOutputArrayNeeded($oArrObj)

    If $bObjIsArray Then
        Call("_VectorOf" & $typeOfObj & "Release", $vectorObj)
    EndIf

    If $typeOfObj <> Default Then
        _cveOutputArrayRelease($oArrObj)
        If $bObjCreate Then
            Call("_cve" & $typeOfObj & "Release", $obj)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayNeededTyped

Func _cveOutputArrayNeededMat($obj)
    ; cveOutputArrayNeeded using cv::Mat instead of _*Array
    Local $retval = _cveOutputArrayNeededTyped("Mat", $obj)

    Return $retval
EndFunc   ;==>_cveOutputArrayNeededMat