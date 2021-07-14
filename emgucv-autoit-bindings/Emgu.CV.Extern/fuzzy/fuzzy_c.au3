#include-once
#include "..\..\CVEUtils.au3"

Func _cveFtCreateKernel(ByRef $A, ByRef $B, ByRef $kernel, $chn)
    ; CVAPI(void) cveFtCreateKernel(cv::_InputArray* A, cv::_InputArray* B, cv::_OutputArray* kernel, int chn);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtCreateKernel", "ptr", $A, "ptr", $B, "ptr", $kernel, "int", $chn), "cveFtCreateKernel", @error)
EndFunc   ;==>_cveFtCreateKernel

Func _cveFtCreateKernelMat(ByRef $matA, ByRef $matB, ByRef $matKernel, $chn)
    ; cveFtCreateKernel using cv::Mat instead of _*Array

    Local $iArrA, $vectorOfMatA, $iArrASize
    Local $bAIsArray = VarGetType($matA) == "Array"

    If $bAIsArray Then
        $vectorOfMatA = _VectorOfMatCreate()

        $iArrASize = UBound($matA)
        For $i = 0 To $iArrASize - 1
            _VectorOfMatPush($vectorOfMatA, $matA[$i])
        Next

        $iArrA = _cveInputArrayFromVectorOfMat($vectorOfMatA)
    Else
        $iArrA = _cveInputArrayFromMat($matA)
    EndIf

    Local $iArrB, $vectorOfMatB, $iArrBSize
    Local $bBIsArray = VarGetType($matB) == "Array"

    If $bBIsArray Then
        $vectorOfMatB = _VectorOfMatCreate()

        $iArrBSize = UBound($matB)
        For $i = 0 To $iArrBSize - 1
            _VectorOfMatPush($vectorOfMatB, $matB[$i])
        Next

        $iArrB = _cveInputArrayFromVectorOfMat($vectorOfMatB)
    Else
        $iArrB = _cveInputArrayFromMat($matB)
    EndIf

    Local $oArrKernel, $vectorOfMatKernel, $iArrKernelSize
    Local $bKernelIsArray = VarGetType($matKernel) == "Array"

    If $bKernelIsArray Then
        $vectorOfMatKernel = _VectorOfMatCreate()

        $iArrKernelSize = UBound($matKernel)
        For $i = 0 To $iArrKernelSize - 1
            _VectorOfMatPush($vectorOfMatKernel, $matKernel[$i])
        Next

        $oArrKernel = _cveOutputArrayFromVectorOfMat($vectorOfMatKernel)
    Else
        $oArrKernel = _cveOutputArrayFromMat($matKernel)
    EndIf

    _cveFtCreateKernel($iArrA, $iArrB, $oArrKernel, $chn)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveOutputArrayRelease($oArrKernel)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cveFtCreateKernelMat

Func _cveFtcreateKernelFromFunction($function, $radius, ByRef $kernel, $chn)
    ; CVAPI(void) cveFtcreateKernelFromFunction(int function, int radius, cv::_OutputArray* kernel, int chn);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtcreateKernelFromFunction", "int", $function, "int", $radius, "ptr", $kernel, "int", $chn), "cveFtcreateKernelFromFunction", @error)
EndFunc   ;==>_cveFtcreateKernelFromFunction

Func _cveFtcreateKernelFromFunctionMat($function, $radius, ByRef $matKernel, $chn)
    ; cveFtcreateKernelFromFunction using cv::Mat instead of _*Array

    Local $oArrKernel, $vectorOfMatKernel, $iArrKernelSize
    Local $bKernelIsArray = VarGetType($matKernel) == "Array"

    If $bKernelIsArray Then
        $vectorOfMatKernel = _VectorOfMatCreate()

        $iArrKernelSize = UBound($matKernel)
        For $i = 0 To $iArrKernelSize - 1
            _VectorOfMatPush($vectorOfMatKernel, $matKernel[$i])
        Next

        $oArrKernel = _cveOutputArrayFromVectorOfMat($vectorOfMatKernel)
    Else
        $oArrKernel = _cveOutputArrayFromMat($matKernel)
    EndIf

    _cveFtcreateKernelFromFunction($function, $radius, $oArrKernel, $chn)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveOutputArrayRelease($oArrKernel)
EndFunc   ;==>_cveFtcreateKernelFromFunctionMat

Func _cveFtInpaint(ByRef $image, ByRef $mask, ByRef $output, $radius, $function, $algorithm)
    ; CVAPI(void) cveFtInpaint(cv::Mat* image, cv::Mat* mask, cv::Mat* output, int radius, int function, int algorithm);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtInpaint", "ptr", $image, "ptr", $mask, "ptr", $output, "int", $radius, "int", $function, "int", $algorithm), "cveFtInpaint", @error)
EndFunc   ;==>_cveFtInpaint

Func _cveFtFilter(ByRef $image, ByRef $kernel, ByRef $output)
    ; CVAPI(void) cveFtFilter(cv::Mat* image, cv::Mat* kernel, cv::Mat* output);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFtFilter", "ptr", $image, "ptr", $kernel, "ptr", $output), "cveFtFilter", @error)
EndFunc   ;==>_cveFtFilter