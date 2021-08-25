#include-once
#include "..\..\CVEUtils.au3"

Func _cveFtCreateKernel($A, $B, $kernel, $chn)
    ; CVAPI(void) cveFtCreateKernel(cv::_InputArray* A, cv::_InputArray* B, cv::_OutputArray* kernel, int chn);

    Local $sADllType
    If IsDllStruct($A) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($B) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtCreateKernel", $sADllType, $A, $sBDllType, $B, $sKernelDllType, $kernel, "int", $chn), "cveFtCreateKernel", @error)
EndFunc   ;==>_cveFtCreateKernel

Func _cveFtCreateKernelTyped($typeOfA, $A, $typeOfB, $B, $typeOfKernel, $kernel, $chn)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($A)
    Local $bACreate = IsDllStruct($A) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $A
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($A)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $A[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $A = Call("_cve" & $typeOfA & "Create", $A)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $A)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($B)
    Local $bBCreate = IsDllStruct($B) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $B
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($B)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $B[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $B = Call("_cve" & $typeOfB & "Create", $B)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $B)
    EndIf

    Local $oArrKernel, $vectorKernel, $iArrKernelSize
    Local $bKernelIsArray = IsArray($kernel)
    Local $bKernelCreate = IsDllStruct($kernel) And $typeOfKernel == "Scalar"

    If $typeOfKernel == Default Then
        $oArrKernel = $kernel
    ElseIf $bKernelIsArray Then
        $vectorKernel = Call("_VectorOf" & $typeOfKernel & "Create")

        $iArrKernelSize = UBound($kernel)
        For $i = 0 To $iArrKernelSize - 1
            Call("_VectorOf" & $typeOfKernel & "Push", $vectorKernel, $kernel[$i])
        Next

        $oArrKernel = Call("_cveOutputArrayFromVectorOf" & $typeOfKernel, $vectorKernel)
    Else
        If $bKernelCreate Then
            $kernel = Call("_cve" & $typeOfKernel & "Create", $kernel)
        EndIf
        $oArrKernel = Call("_cveOutputArrayFrom" & $typeOfKernel, $kernel)
    EndIf

    _cveFtCreateKernel($iArrA, $iArrB, $oArrKernel, $chn)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveOutputArrayRelease($oArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $B)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $A)
        EndIf
    EndIf
EndFunc   ;==>_cveFtCreateKernelTyped

Func _cveFtCreateKernelMat($A, $B, $kernel, $chn)
    ; cveFtCreateKernel using cv::Mat instead of _*Array
    _cveFtCreateKernelTyped("Mat", $A, "Mat", $B, "Mat", $kernel, $chn)
EndFunc   ;==>_cveFtCreateKernelMat

Func _cveFtcreateKernelFromFunction($function, $radius, $kernel, $chn)
    ; CVAPI(void) cveFtcreateKernelFromFunction(int function, int radius, cv::_OutputArray* kernel, int chn);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtcreateKernelFromFunction", "int", $function, "int", $radius, $sKernelDllType, $kernel, "int", $chn), "cveFtcreateKernelFromFunction", @error)
EndFunc   ;==>_cveFtcreateKernelFromFunction

Func _cveFtcreateKernelFromFunctionTyped($function, $radius, $typeOfKernel, $kernel, $chn)

    Local $oArrKernel, $vectorKernel, $iArrKernelSize
    Local $bKernelIsArray = IsArray($kernel)
    Local $bKernelCreate = IsDllStruct($kernel) And $typeOfKernel == "Scalar"

    If $typeOfKernel == Default Then
        $oArrKernel = $kernel
    ElseIf $bKernelIsArray Then
        $vectorKernel = Call("_VectorOf" & $typeOfKernel & "Create")

        $iArrKernelSize = UBound($kernel)
        For $i = 0 To $iArrKernelSize - 1
            Call("_VectorOf" & $typeOfKernel & "Push", $vectorKernel, $kernel[$i])
        Next

        $oArrKernel = Call("_cveOutputArrayFromVectorOf" & $typeOfKernel, $vectorKernel)
    Else
        If $bKernelCreate Then
            $kernel = Call("_cve" & $typeOfKernel & "Create", $kernel)
        EndIf
        $oArrKernel = Call("_cveOutputArrayFrom" & $typeOfKernel, $kernel)
    EndIf

    _cveFtcreateKernelFromFunction($function, $radius, $oArrKernel, $chn)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveOutputArrayRelease($oArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
        EndIf
    EndIf
EndFunc   ;==>_cveFtcreateKernelFromFunctionTyped

Func _cveFtcreateKernelFromFunctionMat($function, $radius, $kernel, $chn)
    ; cveFtcreateKernelFromFunction using cv::Mat instead of _*Array
    _cveFtcreateKernelFromFunctionTyped($function, $radius, "Mat", $kernel, $chn)
EndFunc   ;==>_cveFtcreateKernelFromFunctionMat

Func _cveFtInpaint($image, $mask, $output, $radius, $function, $algorithm)
    ; CVAPI(void) cveFtInpaint(cv::Mat* image, cv::Mat* mask, cv::Mat* output, int radius, int function, int algorithm);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtInpaint", $sImageDllType, $image, $sMaskDllType, $mask, $sOutputDllType, $output, "int", $radius, "int", $function, "int", $algorithm), "cveFtInpaint", @error)
EndFunc   ;==>_cveFtInpaint

Func _cveFtFilter($image, $kernel, $output)
    ; CVAPI(void) cveFtFilter(cv::Mat* image, cv::Mat* kernel, cv::Mat* output);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtFilter", $sImageDllType, $image, $sKernelDllType, $kernel, $sOutputDllType, $output), "cveFtFilter", @error)
EndFunc   ;==>_cveFtFilter