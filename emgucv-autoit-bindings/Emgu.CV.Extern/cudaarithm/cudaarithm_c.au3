#include-once
#include <..\..\CVEUtils.au3>

Func _cudaExp(ByRef $a, ByRef $b, ByRef $stream)
    ; CVAPI(void) cudaExp(cv::_InputArray* a, cv::_OutputArray* b, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaExp", "ptr", $a, "ptr", $b, "ptr", $stream), "cudaExp", @error)
EndFunc   ;==>_cudaExp

Func _cudaExpMat(ByRef $matA, ByRef $matB, ByRef $stream)
    ; cudaExp using cv::Mat instead of _*Array

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

    Local $oArrB, $vectorOfMatB, $iArrBSize
    Local $bBIsArray = VarGetType($matB) == "Array"

    If $bBIsArray Then
        $vectorOfMatB = _VectorOfMatCreate()

        $iArrBSize = UBound($matB)
        For $i = 0 To $iArrBSize - 1
            _VectorOfMatPush($vectorOfMatB, $matB[$i])
        Next

        $oArrB = _cveOutputArrayFromVectorOfMat($vectorOfMatB)
    Else
        $oArrB = _cveOutputArrayFromMat($matB)
    EndIf

    _cudaExp($iArrA, $oArrB, $stream)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveOutputArrayRelease($oArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaExpMat

Func _cudaPow(ByRef $src, $power, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaPow(cv::_InputArray* src, double power, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPow", "ptr", $src, "double", $power, "ptr", $dst, "ptr", $stream), "cudaPow", @error)
EndFunc   ;==>_cudaPow

Func _cudaPowMat(ByRef $matSrc, $power, ByRef $matDst, ByRef $stream)
    ; cudaPow using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaPow($iArrSrc, $power, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaPowMat

Func _cudaLog(ByRef $a, ByRef $b, ByRef $stream)
    ; CVAPI(void) cudaLog(cv::_InputArray* a, cv::_OutputArray* b, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLog", "ptr", $a, "ptr", $b, "ptr", $stream), "cudaLog", @error)
EndFunc   ;==>_cudaLog

Func _cudaLogMat(ByRef $matA, ByRef $matB, ByRef $stream)
    ; cudaLog using cv::Mat instead of _*Array

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

    Local $oArrB, $vectorOfMatB, $iArrBSize
    Local $bBIsArray = VarGetType($matB) == "Array"

    If $bBIsArray Then
        $vectorOfMatB = _VectorOfMatCreate()

        $iArrBSize = UBound($matB)
        For $i = 0 To $iArrBSize - 1
            _VectorOfMatPush($vectorOfMatB, $matB[$i])
        Next

        $oArrB = _cveOutputArrayFromVectorOfMat($vectorOfMatB)
    Else
        $oArrB = _cveOutputArrayFromMat($matB)
    EndIf

    _cudaLog($iArrA, $oArrB, $stream)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveOutputArrayRelease($oArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaLogMat

Func _cudaMagnitude(ByRef $x, ByRef $y, ByRef $magnitude, ByRef $stream)
    ; CVAPI(void) cudaMagnitude(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMagnitude", "ptr", $x, "ptr", $y, "ptr", $magnitude, "ptr", $stream), "cudaMagnitude", @error)
EndFunc   ;==>_cudaMagnitude

Func _cudaMagnitudeMat(ByRef $matX, ByRef $matY, ByRef $matMagnitude, ByRef $stream)
    ; cudaMagnitude using cv::Mat instead of _*Array

    Local $iArrX, $vectorOfMatX, $iArrXSize
    Local $bXIsArray = VarGetType($matX) == "Array"

    If $bXIsArray Then
        $vectorOfMatX = _VectorOfMatCreate()

        $iArrXSize = UBound($matX)
        For $i = 0 To $iArrXSize - 1
            _VectorOfMatPush($vectorOfMatX, $matX[$i])
        Next

        $iArrX = _cveInputArrayFromVectorOfMat($vectorOfMatX)
    Else
        $iArrX = _cveInputArrayFromMat($matX)
    EndIf

    Local $iArrY, $vectorOfMatY, $iArrYSize
    Local $bYIsArray = VarGetType($matY) == "Array"

    If $bYIsArray Then
        $vectorOfMatY = _VectorOfMatCreate()

        $iArrYSize = UBound($matY)
        For $i = 0 To $iArrYSize - 1
            _VectorOfMatPush($vectorOfMatY, $matY[$i])
        Next

        $iArrY = _cveInputArrayFromVectorOfMat($vectorOfMatY)
    Else
        $iArrY = _cveInputArrayFromMat($matY)
    EndIf

    Local $oArrMagnitude, $vectorOfMatMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = VarGetType($matMagnitude) == "Array"

    If $bMagnitudeIsArray Then
        $vectorOfMatMagnitude = _VectorOfMatCreate()

        $iArrMagnitudeSize = UBound($matMagnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            _VectorOfMatPush($vectorOfMatMagnitude, $matMagnitude[$i])
        Next

        $oArrMagnitude = _cveOutputArrayFromVectorOfMat($vectorOfMatMagnitude)
    Else
        $oArrMagnitude = _cveOutputArrayFromMat($matMagnitude)
    EndIf

    _cudaMagnitude($iArrX, $iArrY, $oArrMagnitude, $stream)

    If $bMagnitudeIsArray Then
        _VectorOfMatRelease($vectorOfMatMagnitude)
    EndIf

    _cveOutputArrayRelease($oArrMagnitude)

    If $bYIsArray Then
        _VectorOfMatRelease($vectorOfMatY)
    EndIf

    _cveInputArrayRelease($iArrY)

    If $bXIsArray Then
        _VectorOfMatRelease($vectorOfMatX)
    EndIf

    _cveInputArrayRelease($iArrX)
EndFunc   ;==>_cudaMagnitudeMat

Func _cudaMagnitudeSqr(ByRef $x, ByRef $y, ByRef $magnitude, ByRef $stream)
    ; CVAPI(void) cudaMagnitudeSqr(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMagnitudeSqr", "ptr", $x, "ptr", $y, "ptr", $magnitude, "ptr", $stream), "cudaMagnitudeSqr", @error)
EndFunc   ;==>_cudaMagnitudeSqr

Func _cudaMagnitudeSqrMat(ByRef $matX, ByRef $matY, ByRef $matMagnitude, ByRef $stream)
    ; cudaMagnitudeSqr using cv::Mat instead of _*Array

    Local $iArrX, $vectorOfMatX, $iArrXSize
    Local $bXIsArray = VarGetType($matX) == "Array"

    If $bXIsArray Then
        $vectorOfMatX = _VectorOfMatCreate()

        $iArrXSize = UBound($matX)
        For $i = 0 To $iArrXSize - 1
            _VectorOfMatPush($vectorOfMatX, $matX[$i])
        Next

        $iArrX = _cveInputArrayFromVectorOfMat($vectorOfMatX)
    Else
        $iArrX = _cveInputArrayFromMat($matX)
    EndIf

    Local $iArrY, $vectorOfMatY, $iArrYSize
    Local $bYIsArray = VarGetType($matY) == "Array"

    If $bYIsArray Then
        $vectorOfMatY = _VectorOfMatCreate()

        $iArrYSize = UBound($matY)
        For $i = 0 To $iArrYSize - 1
            _VectorOfMatPush($vectorOfMatY, $matY[$i])
        Next

        $iArrY = _cveInputArrayFromVectorOfMat($vectorOfMatY)
    Else
        $iArrY = _cveInputArrayFromMat($matY)
    EndIf

    Local $oArrMagnitude, $vectorOfMatMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = VarGetType($matMagnitude) == "Array"

    If $bMagnitudeIsArray Then
        $vectorOfMatMagnitude = _VectorOfMatCreate()

        $iArrMagnitudeSize = UBound($matMagnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            _VectorOfMatPush($vectorOfMatMagnitude, $matMagnitude[$i])
        Next

        $oArrMagnitude = _cveOutputArrayFromVectorOfMat($vectorOfMatMagnitude)
    Else
        $oArrMagnitude = _cveOutputArrayFromMat($matMagnitude)
    EndIf

    _cudaMagnitudeSqr($iArrX, $iArrY, $oArrMagnitude, $stream)

    If $bMagnitudeIsArray Then
        _VectorOfMatRelease($vectorOfMatMagnitude)
    EndIf

    _cveOutputArrayRelease($oArrMagnitude)

    If $bYIsArray Then
        _VectorOfMatRelease($vectorOfMatY)
    EndIf

    _cveInputArrayRelease($iArrY)

    If $bXIsArray Then
        _VectorOfMatRelease($vectorOfMatX)
    EndIf

    _cveInputArrayRelease($iArrX)
EndFunc   ;==>_cudaMagnitudeSqrMat

Func _cudaPhase(ByRef $x, ByRef $y, ByRef $angle, $angleInDegrees, ByRef $stream)
    ; CVAPI(void) cudaPhase(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* angle, bool angleInDegrees, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPhase", "ptr", $x, "ptr", $y, "ptr", $angle, "boolean", $angleInDegrees, "ptr", $stream), "cudaPhase", @error)
EndFunc   ;==>_cudaPhase

Func _cudaPhaseMat(ByRef $matX, ByRef $matY, ByRef $matAngle, $angleInDegrees, ByRef $stream)
    ; cudaPhase using cv::Mat instead of _*Array

    Local $iArrX, $vectorOfMatX, $iArrXSize
    Local $bXIsArray = VarGetType($matX) == "Array"

    If $bXIsArray Then
        $vectorOfMatX = _VectorOfMatCreate()

        $iArrXSize = UBound($matX)
        For $i = 0 To $iArrXSize - 1
            _VectorOfMatPush($vectorOfMatX, $matX[$i])
        Next

        $iArrX = _cveInputArrayFromVectorOfMat($vectorOfMatX)
    Else
        $iArrX = _cveInputArrayFromMat($matX)
    EndIf

    Local $iArrY, $vectorOfMatY, $iArrYSize
    Local $bYIsArray = VarGetType($matY) == "Array"

    If $bYIsArray Then
        $vectorOfMatY = _VectorOfMatCreate()

        $iArrYSize = UBound($matY)
        For $i = 0 To $iArrYSize - 1
            _VectorOfMatPush($vectorOfMatY, $matY[$i])
        Next

        $iArrY = _cveInputArrayFromVectorOfMat($vectorOfMatY)
    Else
        $iArrY = _cveInputArrayFromMat($matY)
    EndIf

    Local $oArrAngle, $vectorOfMatAngle, $iArrAngleSize
    Local $bAngleIsArray = VarGetType($matAngle) == "Array"

    If $bAngleIsArray Then
        $vectorOfMatAngle = _VectorOfMatCreate()

        $iArrAngleSize = UBound($matAngle)
        For $i = 0 To $iArrAngleSize - 1
            _VectorOfMatPush($vectorOfMatAngle, $matAngle[$i])
        Next

        $oArrAngle = _cveOutputArrayFromVectorOfMat($vectorOfMatAngle)
    Else
        $oArrAngle = _cveOutputArrayFromMat($matAngle)
    EndIf

    _cudaPhase($iArrX, $iArrY, $oArrAngle, $angleInDegrees, $stream)

    If $bAngleIsArray Then
        _VectorOfMatRelease($vectorOfMatAngle)
    EndIf

    _cveOutputArrayRelease($oArrAngle)

    If $bYIsArray Then
        _VectorOfMatRelease($vectorOfMatY)
    EndIf

    _cveInputArrayRelease($iArrY)

    If $bXIsArray Then
        _VectorOfMatRelease($vectorOfMatX)
    EndIf

    _cveInputArrayRelease($iArrX)
EndFunc   ;==>_cudaPhaseMat

Func _cudaCartToPolar(ByRef $x, ByRef $y, ByRef $magnitude, ByRef $angle, $angleInDegrees, ByRef $stream)
    ; CVAPI(void) cudaCartToPolar(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::_OutputArray* angle, bool angleInDegrees, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCartToPolar", "ptr", $x, "ptr", $y, "ptr", $magnitude, "ptr", $angle, "boolean", $angleInDegrees, "ptr", $stream), "cudaCartToPolar", @error)
EndFunc   ;==>_cudaCartToPolar

Func _cudaCartToPolarMat(ByRef $matX, ByRef $matY, ByRef $matMagnitude, ByRef $matAngle, $angleInDegrees, ByRef $stream)
    ; cudaCartToPolar using cv::Mat instead of _*Array

    Local $iArrX, $vectorOfMatX, $iArrXSize
    Local $bXIsArray = VarGetType($matX) == "Array"

    If $bXIsArray Then
        $vectorOfMatX = _VectorOfMatCreate()

        $iArrXSize = UBound($matX)
        For $i = 0 To $iArrXSize - 1
            _VectorOfMatPush($vectorOfMatX, $matX[$i])
        Next

        $iArrX = _cveInputArrayFromVectorOfMat($vectorOfMatX)
    Else
        $iArrX = _cveInputArrayFromMat($matX)
    EndIf

    Local $iArrY, $vectorOfMatY, $iArrYSize
    Local $bYIsArray = VarGetType($matY) == "Array"

    If $bYIsArray Then
        $vectorOfMatY = _VectorOfMatCreate()

        $iArrYSize = UBound($matY)
        For $i = 0 To $iArrYSize - 1
            _VectorOfMatPush($vectorOfMatY, $matY[$i])
        Next

        $iArrY = _cveInputArrayFromVectorOfMat($vectorOfMatY)
    Else
        $iArrY = _cveInputArrayFromMat($matY)
    EndIf

    Local $oArrMagnitude, $vectorOfMatMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = VarGetType($matMagnitude) == "Array"

    If $bMagnitudeIsArray Then
        $vectorOfMatMagnitude = _VectorOfMatCreate()

        $iArrMagnitudeSize = UBound($matMagnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            _VectorOfMatPush($vectorOfMatMagnitude, $matMagnitude[$i])
        Next

        $oArrMagnitude = _cveOutputArrayFromVectorOfMat($vectorOfMatMagnitude)
    Else
        $oArrMagnitude = _cveOutputArrayFromMat($matMagnitude)
    EndIf

    Local $oArrAngle, $vectorOfMatAngle, $iArrAngleSize
    Local $bAngleIsArray = VarGetType($matAngle) == "Array"

    If $bAngleIsArray Then
        $vectorOfMatAngle = _VectorOfMatCreate()

        $iArrAngleSize = UBound($matAngle)
        For $i = 0 To $iArrAngleSize - 1
            _VectorOfMatPush($vectorOfMatAngle, $matAngle[$i])
        Next

        $oArrAngle = _cveOutputArrayFromVectorOfMat($vectorOfMatAngle)
    Else
        $oArrAngle = _cveOutputArrayFromMat($matAngle)
    EndIf

    _cudaCartToPolar($iArrX, $iArrY, $oArrMagnitude, $oArrAngle, $angleInDegrees, $stream)

    If $bAngleIsArray Then
        _VectorOfMatRelease($vectorOfMatAngle)
    EndIf

    _cveOutputArrayRelease($oArrAngle)

    If $bMagnitudeIsArray Then
        _VectorOfMatRelease($vectorOfMatMagnitude)
    EndIf

    _cveOutputArrayRelease($oArrMagnitude)

    If $bYIsArray Then
        _VectorOfMatRelease($vectorOfMatY)
    EndIf

    _cveInputArrayRelease($iArrY)

    If $bXIsArray Then
        _VectorOfMatRelease($vectorOfMatX)
    EndIf

    _cveInputArrayRelease($iArrX)
EndFunc   ;==>_cudaCartToPolarMat

Func _cudaPolarToCart(ByRef $magnitude, ByRef $angle, ByRef $x, ByRef $y, $angleInDegrees, ByRef $stream)
    ; CVAPI(void) cudaPolarToCart(cv::_InputArray* magnitude, cv::_InputArray* angle, cv::_OutputArray* x, cv::_OutputArray* y, bool angleInDegrees, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPolarToCart", "ptr", $magnitude, "ptr", $angle, "ptr", $x, "ptr", $y, "boolean", $angleInDegrees, "ptr", $stream), "cudaPolarToCart", @error)
EndFunc   ;==>_cudaPolarToCart

Func _cudaPolarToCartMat(ByRef $matMagnitude, ByRef $matAngle, ByRef $matX, ByRef $matY, $angleInDegrees, ByRef $stream)
    ; cudaPolarToCart using cv::Mat instead of _*Array

    Local $iArrMagnitude, $vectorOfMatMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = VarGetType($matMagnitude) == "Array"

    If $bMagnitudeIsArray Then
        $vectorOfMatMagnitude = _VectorOfMatCreate()

        $iArrMagnitudeSize = UBound($matMagnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            _VectorOfMatPush($vectorOfMatMagnitude, $matMagnitude[$i])
        Next

        $iArrMagnitude = _cveInputArrayFromVectorOfMat($vectorOfMatMagnitude)
    Else
        $iArrMagnitude = _cveInputArrayFromMat($matMagnitude)
    EndIf

    Local $iArrAngle, $vectorOfMatAngle, $iArrAngleSize
    Local $bAngleIsArray = VarGetType($matAngle) == "Array"

    If $bAngleIsArray Then
        $vectorOfMatAngle = _VectorOfMatCreate()

        $iArrAngleSize = UBound($matAngle)
        For $i = 0 To $iArrAngleSize - 1
            _VectorOfMatPush($vectorOfMatAngle, $matAngle[$i])
        Next

        $iArrAngle = _cveInputArrayFromVectorOfMat($vectorOfMatAngle)
    Else
        $iArrAngle = _cveInputArrayFromMat($matAngle)
    EndIf

    Local $oArrX, $vectorOfMatX, $iArrXSize
    Local $bXIsArray = VarGetType($matX) == "Array"

    If $bXIsArray Then
        $vectorOfMatX = _VectorOfMatCreate()

        $iArrXSize = UBound($matX)
        For $i = 0 To $iArrXSize - 1
            _VectorOfMatPush($vectorOfMatX, $matX[$i])
        Next

        $oArrX = _cveOutputArrayFromVectorOfMat($vectorOfMatX)
    Else
        $oArrX = _cveOutputArrayFromMat($matX)
    EndIf

    Local $oArrY, $vectorOfMatY, $iArrYSize
    Local $bYIsArray = VarGetType($matY) == "Array"

    If $bYIsArray Then
        $vectorOfMatY = _VectorOfMatCreate()

        $iArrYSize = UBound($matY)
        For $i = 0 To $iArrYSize - 1
            _VectorOfMatPush($vectorOfMatY, $matY[$i])
        Next

        $oArrY = _cveOutputArrayFromVectorOfMat($vectorOfMatY)
    Else
        $oArrY = _cveOutputArrayFromMat($matY)
    EndIf

    _cudaPolarToCart($iArrMagnitude, $iArrAngle, $oArrX, $oArrY, $angleInDegrees, $stream)

    If $bYIsArray Then
        _VectorOfMatRelease($vectorOfMatY)
    EndIf

    _cveOutputArrayRelease($oArrY)

    If $bXIsArray Then
        _VectorOfMatRelease($vectorOfMatX)
    EndIf

    _cveOutputArrayRelease($oArrX)

    If $bAngleIsArray Then
        _VectorOfMatRelease($vectorOfMatAngle)
    EndIf

    _cveInputArrayRelease($iArrAngle)

    If $bMagnitudeIsArray Then
        _VectorOfMatRelease($vectorOfMatMagnitude)
    EndIf

    _cveInputArrayRelease($iArrMagnitude)
EndFunc   ;==>_cudaPolarToCartMat

Func _cudaMerge(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaMerge(std::vector< cv::cuda::GpuMat >* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $vecSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($src) == "Array"

    If $bSrcIsArray Then
        $vecSrc = _VectorOfGpuMatCreate()

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfGpuMatPush($vecSrc, $src[$i])
        Next
    Else
        $vecSrc = $src
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMerge", "ptr", $vecSrc, "ptr", $dst, "ptr", $stream), "cudaMerge", @error)

    If $bSrcIsArray Then
        _VectorOfGpuMatRelease($vecSrc)
    EndIf
EndFunc   ;==>_cudaMerge

Func _cudaMergeMat(ByRef $src, ByRef $matDst, ByRef $stream)
    ; cudaMerge using cv::Mat instead of _*Array

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMerge($src, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_cudaMergeMat

Func _cudaMeanStdDev(ByRef $mtx, ByRef $mean, ByRef $stddev)
    ; CVAPI(void) cudaMeanStdDev(cv::_InputArray* mtx, CvScalar* mean, CvScalar* stddev);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanStdDev", "ptr", $mtx, "struct*", $mean, "struct*", $stddev), "cudaMeanStdDev", @error)
EndFunc   ;==>_cudaMeanStdDev

Func _cudaMeanStdDevMat(ByRef $matMtx, ByRef $mean, ByRef $stddev)
    ; cudaMeanStdDev using cv::Mat instead of _*Array

    Local $iArrMtx, $vectorOfMatMtx, $iArrMtxSize
    Local $bMtxIsArray = VarGetType($matMtx) == "Array"

    If $bMtxIsArray Then
        $vectorOfMatMtx = _VectorOfMatCreate()

        $iArrMtxSize = UBound($matMtx)
        For $i = 0 To $iArrMtxSize - 1
            _VectorOfMatPush($vectorOfMatMtx, $matMtx[$i])
        Next

        $iArrMtx = _cveInputArrayFromVectorOfMat($vectorOfMatMtx)
    Else
        $iArrMtx = _cveInputArrayFromMat($matMtx)
    EndIf

    _cudaMeanStdDev($iArrMtx, $mean, $stddev)

    If $bMtxIsArray Then
        _VectorOfMatRelease($vectorOfMatMtx)
    EndIf

    _cveInputArrayRelease($iArrMtx)
EndFunc   ;==>_cudaMeanStdDevMat

Func _cudaNorm1(ByRef $src1, $normType, ByRef $mask)
    ; CVAPI(double) cudaNorm1(cv::_InputArray* src1, int normType, cv::_InputArray* mask);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cudaNorm1", "ptr", $src1, "int", $normType, "ptr", $mask), "cudaNorm1", @error)
EndFunc   ;==>_cudaNorm1

Func _cudaNorm1Mat(ByRef $matSrc1, $normType, ByRef $matMask)
    ; cudaNorm1 using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    Local $retval = _cudaNorm1($iArrSrc1, $normType, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)

    Return $retval
EndFunc   ;==>_cudaNorm1Mat

Func _cudaNorm2(ByRef $src1, ByRef $src2, $normType)
    ; CVAPI(double) cudaNorm2(cv::_InputArray* src1, cv::_InputArray* src2, int normType);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cudaNorm2", "ptr", $src1, "ptr", $src2, "int", $normType), "cudaNorm2", @error)
EndFunc   ;==>_cudaNorm2

Func _cudaNorm2Mat(ByRef $matSrc1, ByRef $matSrc2, $normType)
    ; cudaNorm2 using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $retval = _cudaNorm2($iArrSrc1, $iArrSrc2, $normType)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)

    Return $retval
EndFunc   ;==>_cudaNorm2Mat

Func _cudaCalcNorm(ByRef $src, ByRef $dst, $normType, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaCalcNorm(cv::_InputArray* src, cv::_OutputArray* dst, int normType, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcNorm", "ptr", $src, "ptr", $dst, "int", $normType, "ptr", $mask, "ptr", $stream), "cudaCalcNorm", @error)
EndFunc   ;==>_cudaCalcNorm

Func _cudaCalcNormMat(ByRef $matSrc, ByRef $matDst, $normType, ByRef $matMask, ByRef $stream)
    ; cudaCalcNorm using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaCalcNorm($iArrSrc, $oArrDst, $normType, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCalcNormMat

Func _cudaCalcNormDiff(ByRef $src1, ByRef $src2, ByRef $dst, $normType, ByRef $stream)
    ; CVAPI(void) cudaCalcNormDiff(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int normType, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcNormDiff", "ptr", $src1, "ptr", $src2, "ptr", $dst, "int", $normType, "ptr", $stream), "cudaCalcNormDiff", @error)
EndFunc   ;==>_cudaCalcNormDiff

Func _cudaCalcNormDiffMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, $normType, ByRef $stream)
    ; cudaCalcNormDiff using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaCalcNormDiff($iArrSrc1, $iArrSrc2, $oArrDst, $normType, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaCalcNormDiffMat

Func _cudaAbsSum(ByRef $src, ByRef $sum, ByRef $mask)
    ; CVAPI(void) cudaAbsSum(cv::_InputArray* src, CvScalar* sum, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAbsSum", "ptr", $src, "struct*", $sum, "ptr", $mask), "cudaAbsSum", @error)
EndFunc   ;==>_cudaAbsSum

Func _cudaAbsSumMat(ByRef $matSrc, ByRef $sum, ByRef $matMask)
    ; cudaAbsSum using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaAbsSum($iArrSrc, $sum, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaAbsSumMat

Func _cudaCalcAbsSum(ByRef $src, ByRef $dst, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaCalcAbsSum(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcAbsSum", "ptr", $src, "ptr", $dst, "ptr", $mask, "ptr", $stream), "cudaCalcAbsSum", @error)
EndFunc   ;==>_cudaCalcAbsSum

Func _cudaCalcAbsSumMat(ByRef $matSrc, ByRef $matDst, ByRef $matMask, ByRef $stream)
    ; cudaCalcAbsSum using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaCalcAbsSum($iArrSrc, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCalcAbsSumMat

Func _cudaSqrSum(ByRef $src, ByRef $sqrSum, ByRef $mask)
    ; CVAPI(void) cudaSqrSum(cv::_InputArray* src, CvScalar* sqrSum, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqrSum", "ptr", $src, "struct*", $sqrSum, "ptr", $mask), "cudaSqrSum", @error)
EndFunc   ;==>_cudaSqrSum

Func _cudaSqrSumMat(ByRef $matSrc, ByRef $sqrSum, ByRef $matMask)
    ; cudaSqrSum using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaSqrSum($iArrSrc, $sqrSum, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaSqrSumMat

Func _cudaCalcSqrSum(ByRef $src, ByRef $dst, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaCalcSqrSum(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcSqrSum", "ptr", $src, "ptr", $dst, "ptr", $mask, "ptr", $stream), "cudaCalcSqrSum", @error)
EndFunc   ;==>_cudaCalcSqrSum

Func _cudaCalcSqrSumMat(ByRef $matSrc, ByRef $matDst, ByRef $matMask, ByRef $stream)
    ; cudaCalcSqrSum using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaCalcSqrSum($iArrSrc, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCalcSqrSumMat

Func _cudaMinMaxLoc(ByRef $src, ByRef $minVal, ByRef $maxVal, ByRef $minLoc, ByRef $maxLoc, ByRef $mask)
    ; CVAPI(void) cudaMinMaxLoc(cv::_InputArray* src, double* minVal, double* maxVal, CvPoint* minLoc, CvPoint* maxLoc, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMinMaxLoc", "ptr", $src, "struct*", $minVal, "struct*", $maxVal, "struct*", $minLoc, "struct*", $maxLoc, "ptr", $mask), "cudaMinMaxLoc", @error)
EndFunc   ;==>_cudaMinMaxLoc

Func _cudaMinMaxLocMat(ByRef $matSrc, ByRef $minVal, ByRef $maxVal, ByRef $minLoc, ByRef $maxLoc, ByRef $matMask)
    ; cudaMinMaxLoc using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaMinMaxLoc($iArrSrc, $minVal, $maxVal, $minLoc, $maxLoc, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaMinMaxLocMat

Func _cudaFindMinMaxLoc(ByRef $src, ByRef $minMaxVals, ByRef $loc, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaFindMinMaxLoc(cv::_InputArray* src, cv::_OutputArray* minMaxVals, cv::_OutputArray* loc, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFindMinMaxLoc", "ptr", $src, "ptr", $minMaxVals, "ptr", $loc, "ptr", $mask, "ptr", $stream), "cudaFindMinMaxLoc", @error)
EndFunc   ;==>_cudaFindMinMaxLoc

Func _cudaFindMinMaxLocMat(ByRef $matSrc, ByRef $matMinMaxVals, ByRef $matLoc, ByRef $matMask, ByRef $stream)
    ; cudaFindMinMaxLoc using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrMinMaxVals, $vectorOfMatMinMaxVals, $iArrMinMaxValsSize
    Local $bMinMaxValsIsArray = VarGetType($matMinMaxVals) == "Array"

    If $bMinMaxValsIsArray Then
        $vectorOfMatMinMaxVals = _VectorOfMatCreate()

        $iArrMinMaxValsSize = UBound($matMinMaxVals)
        For $i = 0 To $iArrMinMaxValsSize - 1
            _VectorOfMatPush($vectorOfMatMinMaxVals, $matMinMaxVals[$i])
        Next

        $oArrMinMaxVals = _cveOutputArrayFromVectorOfMat($vectorOfMatMinMaxVals)
    Else
        $oArrMinMaxVals = _cveOutputArrayFromMat($matMinMaxVals)
    EndIf

    Local $oArrLoc, $vectorOfMatLoc, $iArrLocSize
    Local $bLocIsArray = VarGetType($matLoc) == "Array"

    If $bLocIsArray Then
        $vectorOfMatLoc = _VectorOfMatCreate()

        $iArrLocSize = UBound($matLoc)
        For $i = 0 To $iArrLocSize - 1
            _VectorOfMatPush($vectorOfMatLoc, $matLoc[$i])
        Next

        $oArrLoc = _cveOutputArrayFromVectorOfMat($vectorOfMatLoc)
    Else
        $oArrLoc = _cveOutputArrayFromMat($matLoc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaFindMinMaxLoc($iArrSrc, $oArrMinMaxVals, $oArrLoc, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bLocIsArray Then
        _VectorOfMatRelease($vectorOfMatLoc)
    EndIf

    _cveOutputArrayRelease($oArrLoc)

    If $bMinMaxValsIsArray Then
        _VectorOfMatRelease($vectorOfMatMinMaxVals)
    EndIf

    _cveOutputArrayRelease($oArrMinMaxVals)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaFindMinMaxLocMat

Func _cudaCountNonZero1(ByRef $src)
    ; CVAPI(int) cudaCountNonZero1(cv::_InputArray* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaCountNonZero1", "ptr", $src), "cudaCountNonZero1", @error)
EndFunc   ;==>_cudaCountNonZero1

Func _cudaCountNonZero1Mat(ByRef $matSrc)
    ; cudaCountNonZero1 using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $retval = _cudaCountNonZero1($iArrSrc)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    Return $retval
EndFunc   ;==>_cudaCountNonZero1Mat

Func _cudaCountNonZero2(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaCountNonZero2(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCountNonZero2", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaCountNonZero2", @error)
EndFunc   ;==>_cudaCountNonZero2

Func _cudaCountNonZero2Mat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaCountNonZero2 using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaCountNonZero2($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCountNonZero2Mat

Func _cudaReduce(ByRef $mtx, ByRef $vec, $dim, $reduceOp, $dType, ByRef $stream)
    ; CVAPI(void) cudaReduce(cv::_InputArray* mtx, cv::_OutputArray* vec, int dim, int reduceOp, int dType, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaReduce", "ptr", $mtx, "ptr", $vec, "int", $dim, "int", $reduceOp, "int", $dType, "ptr", $stream), "cudaReduce", @error)
EndFunc   ;==>_cudaReduce

Func _cudaReduceMat(ByRef $matMtx, ByRef $matVec, $dim, $reduceOp, $dType, ByRef $stream)
    ; cudaReduce using cv::Mat instead of _*Array

    Local $iArrMtx, $vectorOfMatMtx, $iArrMtxSize
    Local $bMtxIsArray = VarGetType($matMtx) == "Array"

    If $bMtxIsArray Then
        $vectorOfMatMtx = _VectorOfMatCreate()

        $iArrMtxSize = UBound($matMtx)
        For $i = 0 To $iArrMtxSize - 1
            _VectorOfMatPush($vectorOfMatMtx, $matMtx[$i])
        Next

        $iArrMtx = _cveInputArrayFromVectorOfMat($vectorOfMatMtx)
    Else
        $iArrMtx = _cveInputArrayFromMat($matMtx)
    EndIf

    Local $oArrVec, $vectorOfMatVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($matVec) == "Array"

    If $bVecIsArray Then
        $vectorOfMatVec = _VectorOfMatCreate()

        $iArrVecSize = UBound($matVec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfMatPush($vectorOfMatVec, $matVec[$i])
        Next

        $oArrVec = _cveOutputArrayFromVectorOfMat($vectorOfMatVec)
    Else
        $oArrVec = _cveOutputArrayFromMat($matVec)
    EndIf

    _cudaReduce($iArrMtx, $oArrVec, $dim, $reduceOp, $dType, $stream)

    If $bVecIsArray Then
        _VectorOfMatRelease($vectorOfMatVec)
    EndIf

    _cveOutputArrayRelease($oArrVec)

    If $bMtxIsArray Then
        _VectorOfMatRelease($vectorOfMatMtx)
    EndIf

    _cveInputArrayRelease($iArrMtx)
EndFunc   ;==>_cudaReduceMat

Func _cudaBitwiseNot(ByRef $src, ByRef $dst, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaBitwiseNot(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseNot", "ptr", $src, "ptr", $dst, "ptr", $mask, "ptr", $stream), "cudaBitwiseNot", @error)
EndFunc   ;==>_cudaBitwiseNot

Func _cudaBitwiseNotMat(ByRef $matSrc, ByRef $matDst, ByRef $matMask, ByRef $stream)
    ; cudaBitwiseNot using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaBitwiseNot($iArrSrc, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaBitwiseNotMat

Func _cudaBitwiseAnd(ByRef $src1, ByRef $src2, ByRef $dst, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaBitwiseAnd(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseAnd", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask, "ptr", $stream), "cudaBitwiseAnd", @error)
EndFunc   ;==>_cudaBitwiseAnd

Func _cudaBitwiseAndMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, ByRef $matMask, ByRef $stream)
    ; cudaBitwiseAnd using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaBitwiseAnd($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaBitwiseAndMat

Func _cudaBitwiseOr(ByRef $src1, ByRef $src2, ByRef $dst, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaBitwiseOr(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseOr", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask, "ptr", $stream), "cudaBitwiseOr", @error)
EndFunc   ;==>_cudaBitwiseOr

Func _cudaBitwiseOrMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, ByRef $matMask, ByRef $stream)
    ; cudaBitwiseOr using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaBitwiseOr($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaBitwiseOrMat

Func _cudaBitwiseXor(ByRef $src1, ByRef $src2, ByRef $dst, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaBitwiseXor(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseXor", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask, "ptr", $stream), "cudaBitwiseXor", @error)
EndFunc   ;==>_cudaBitwiseXor

Func _cudaBitwiseXorMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, ByRef $matMask, ByRef $stream)
    ; cudaBitwiseXor using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaBitwiseXor($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaBitwiseXorMat

Func _cudaMin(ByRef $src1, ByRef $src2, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaMin(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMin", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $stream), "cudaMin", @error)
EndFunc   ;==>_cudaMin

Func _cudaMinMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, ByRef $stream)
    ; cudaMin using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMin($iArrSrc1, $iArrSrc2, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaMinMat

Func _cudaMax(ByRef $src1, ByRef $src2, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaMax(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMax", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $stream), "cudaMax", @error)
EndFunc   ;==>_cudaMax

Func _cudaMaxMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, ByRef $stream)
    ; cudaMax using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMax($iArrSrc1, $iArrSrc2, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaMaxMat

Func _cudaGemm(ByRef $src1, ByRef $src2, $alpha, ByRef $src3, $beta, ByRef $dst, $flags, ByRef $stream)
    ; CVAPI(void) cudaGemm(cv::_InputArray* src1, cv::_InputArray* src2, double alpha, cv::_InputArray* src3, double beta, cv::_OutputArray* dst, int flags, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaGemm", "ptr", $src1, "ptr", $src2, "double", $alpha, "ptr", $src3, "double", $beta, "ptr", $dst, "int", $flags, "ptr", $stream), "cudaGemm", @error)
EndFunc   ;==>_cudaGemm

Func _cudaGemmMat(ByRef $matSrc1, ByRef $matSrc2, $alpha, ByRef $matSrc3, $beta, ByRef $matDst, $flags, ByRef $stream)
    ; cudaGemm using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $iArrSrc3, $vectorOfMatSrc3, $iArrSrc3Size
    Local $bSrc3IsArray = VarGetType($matSrc3) == "Array"

    If $bSrc3IsArray Then
        $vectorOfMatSrc3 = _VectorOfMatCreate()

        $iArrSrc3Size = UBound($matSrc3)
        For $i = 0 To $iArrSrc3Size - 1
            _VectorOfMatPush($vectorOfMatSrc3, $matSrc3[$i])
        Next

        $iArrSrc3 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc3)
    Else
        $iArrSrc3 = _cveInputArrayFromMat($matSrc3)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaGemm($iArrSrc1, $iArrSrc2, $alpha, $iArrSrc3, $beta, $oArrDst, $flags, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc3IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc3)
    EndIf

    _cveInputArrayRelease($iArrSrc3)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaGemmMat

Func _cudaLShift(ByRef $a, ByRef $scale, ByRef $c, ByRef $stream)
    ; CVAPI(void) cudaLShift(cv::_InputArray* a, CvScalar* scale, cv::_OutputArray* c, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLShift", "ptr", $a, "struct*", $scale, "ptr", $c, "ptr", $stream), "cudaLShift", @error)
EndFunc   ;==>_cudaLShift

Func _cudaLShiftMat(ByRef $matA, ByRef $scale, ByRef $matC, ByRef $stream)
    ; cudaLShift using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    _cudaLShift($iArrA, $scale, $oArrC, $stream)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaLShiftMat

Func _cudaRShift(ByRef $a, ByRef $scale, ByRef $c, ByRef $stream)
    ; CVAPI(void) cudaRShift(cv::_InputArray* a, CvScalar* scale, cv::_OutputArray* c, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaRShift", "ptr", $a, "struct*", $scale, "ptr", $c, "ptr", $stream), "cudaRShift", @error)
EndFunc   ;==>_cudaRShift

Func _cudaRShiftMat(ByRef $matA, ByRef $scale, ByRef $matC, ByRef $stream)
    ; cudaRShift using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    _cudaRShift($iArrA, $scale, $oArrC, $stream)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaRShiftMat

Func _cudaAdd(ByRef $a, ByRef $b, ByRef $c, ByRef $mask, $dtype, ByRef $stream)
    ; CVAPI(void) cudaAdd(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, cv::_InputArray* mask, int dtype, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAdd", "ptr", $a, "ptr", $b, "ptr", $c, "ptr", $mask, "int", $dtype, "ptr", $stream), "cudaAdd", @error)
EndFunc   ;==>_cudaAdd

Func _cudaAddMat(ByRef $matA, ByRef $matB, ByRef $matC, ByRef $matMask, $dtype, ByRef $stream)
    ; cudaAdd using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaAdd($iArrA, $iArrB, $oArrC, $iArrMask, $dtype, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaAddMat

Func _cudaSubtract(ByRef $a, ByRef $b, ByRef $c, ByRef $mask, $dtype, ByRef $stream)
    ; CVAPI(void) cudaSubtract(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, cv::_InputArray* mask, int dtype, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSubtract", "ptr", $a, "ptr", $b, "ptr", $c, "ptr", $mask, "int", $dtype, "ptr", $stream), "cudaSubtract", @error)
EndFunc   ;==>_cudaSubtract

Func _cudaSubtractMat(ByRef $matA, ByRef $matB, ByRef $matC, ByRef $matMask, $dtype, ByRef $stream)
    ; cudaSubtract using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaSubtract($iArrA, $iArrB, $oArrC, $iArrMask, $dtype, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaSubtractMat

Func _cudaMultiply(ByRef $a, ByRef $b, ByRef $c, $scale, $dtype, ByRef $stream)
    ; CVAPI(void) cudaMultiply(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, double scale, int dtype, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMultiply", "ptr", $a, "ptr", $b, "ptr", $c, "double", $scale, "int", $dtype, "ptr", $stream), "cudaMultiply", @error)
EndFunc   ;==>_cudaMultiply

Func _cudaMultiplyMat(ByRef $matA, ByRef $matB, ByRef $matC, $scale, $dtype, ByRef $stream)
    ; cudaMultiply using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    _cudaMultiply($iArrA, $iArrB, $oArrC, $scale, $dtype, $stream)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaMultiplyMat

Func _cudaDivide(ByRef $a, ByRef $b, ByRef $c, $scale, $dtype, ByRef $stream)
    ; CVAPI(void) cudaDivide(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, double scale, int dtype, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDivide", "ptr", $a, "ptr", $b, "ptr", $c, "double", $scale, "int", $dtype, "ptr", $stream), "cudaDivide", @error)
EndFunc   ;==>_cudaDivide

Func _cudaDivideMat(ByRef $matA, ByRef $matB, ByRef $matC, $scale, $dtype, ByRef $stream)
    ; cudaDivide using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    _cudaDivide($iArrA, $iArrB, $oArrC, $scale, $dtype, $stream)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaDivideMat

Func _cudaAddWeighted(ByRef $src1, $alpha, ByRef $src2, $beta, $gamma, ByRef $dst, $dtype, ByRef $stream)
    ; CVAPI(void) cudaAddWeighted(cv::_InputArray* src1, double alpha, cv::_InputArray* src2, double beta, double gamma, cv::_OutputArray* dst, int dtype, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAddWeighted", "ptr", $src1, "double", $alpha, "ptr", $src2, "double", $beta, "double", $gamma, "ptr", $dst, "int", $dtype, "ptr", $stream), "cudaAddWeighted", @error)
EndFunc   ;==>_cudaAddWeighted

Func _cudaAddWeightedMat(ByRef $matSrc1, $alpha, ByRef $matSrc2, $beta, $gamma, ByRef $matDst, $dtype, ByRef $stream)
    ; cudaAddWeighted using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaAddWeighted($iArrSrc1, $alpha, $iArrSrc2, $beta, $gamma, $oArrDst, $dtype, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaAddWeightedMat

Func _cudaAbsdiff(ByRef $a, ByRef $b, ByRef $c, ByRef $stream)
    ; CVAPI(void) cudaAbsdiff(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAbsdiff", "ptr", $a, "ptr", $b, "ptr", $c, "ptr", $stream), "cudaAbsdiff", @error)
EndFunc   ;==>_cudaAbsdiff

Func _cudaAbsdiffMat(ByRef $matA, ByRef $matB, ByRef $matC, ByRef $stream)
    ; cudaAbsdiff using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    _cudaAbsdiff($iArrA, $iArrB, $oArrC, $stream)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaAbsdiffMat

Func _cudaAbs(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaAbs(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAbs", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaAbs", @error)
EndFunc   ;==>_cudaAbs

Func _cudaAbsMat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaAbs using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaAbs($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaAbsMat

Func _cudaSqr(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaSqr(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqr", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaSqr", @error)
EndFunc   ;==>_cudaSqr

Func _cudaSqrMat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaSqr using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaSqr($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaSqrMat

Func _cudaSqrt(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaSqrt(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqrt", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaSqrt", @error)
EndFunc   ;==>_cudaSqrt

Func _cudaSqrtMat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaSqrt using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaSqrt($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaSqrtMat

Func _cudaCompare(ByRef $a, ByRef $b, ByRef $c, $cmpop, ByRef $stream)
    ; CVAPI(void) cudaCompare(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, int cmpop, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCompare", "ptr", $a, "ptr", $b, "ptr", $c, "int", $cmpop, "ptr", $stream), "cudaCompare", @error)
EndFunc   ;==>_cudaCompare

Func _cudaCompareMat(ByRef $matA, ByRef $matB, ByRef $matC, $cmpop, ByRef $stream)
    ; cudaCompare using cv::Mat instead of _*Array

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

    Local $oArrC, $vectorOfMatC, $iArrCSize
    Local $bCIsArray = VarGetType($matC) == "Array"

    If $bCIsArray Then
        $vectorOfMatC = _VectorOfMatCreate()

        $iArrCSize = UBound($matC)
        For $i = 0 To $iArrCSize - 1
            _VectorOfMatPush($vectorOfMatC, $matC[$i])
        Next

        $oArrC = _cveOutputArrayFromVectorOfMat($vectorOfMatC)
    Else
        $oArrC = _cveOutputArrayFromMat($matC)
    EndIf

    _cudaCompare($iArrA, $iArrB, $oArrC, $cmpop, $stream)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)
EndFunc   ;==>_cudaCompareMat

Func _cudaThreshold(ByRef $src, ByRef $dst, $thresh, $maxval, $type, ByRef $stream)
    ; CVAPI(double) cudaThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double thresh, double maxval, int type, cv::cuda::Stream* stream);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cudaThreshold", "ptr", $src, "ptr", $dst, "double", $thresh, "double", $maxval, "int", $type, "ptr", $stream), "cudaThreshold", @error)
EndFunc   ;==>_cudaThreshold

Func _cudaThresholdMat(ByRef $matSrc, ByRef $matDst, $thresh, $maxval, $type, ByRef $stream)
    ; cudaThreshold using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $retval = _cudaThreshold($iArrSrc, $oArrDst, $thresh, $maxval, $type, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    Return $retval
EndFunc   ;==>_cudaThresholdMat

Func _cudaCopyMakeBorder(ByRef $src, ByRef $dst, $top, $bottom, $left, $right, $gpuBorderType, $value, ByRef $stream)
    ; CVAPI(void) cudaCopyMakeBorder(cv::_InputArray* src, cv::_OutputArray* dst, int top, int bottom, int left, int right, int gpuBorderType, const CvScalar* value, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCopyMakeBorder", "ptr", $src, "ptr", $dst, "int", $top, "int", $bottom, "int", $left, "int", $right, "int", $gpuBorderType, "ptr", $value, "ptr", $stream), "cudaCopyMakeBorder", @error)
EndFunc   ;==>_cudaCopyMakeBorder

Func _cudaCopyMakeBorderMat(ByRef $matSrc, ByRef $matDst, $top, $bottom, $left, $right, $gpuBorderType, $value, ByRef $stream)
    ; cudaCopyMakeBorder using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaCopyMakeBorder($iArrSrc, $oArrDst, $top, $bottom, $left, $right, $gpuBorderType, $value, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCopyMakeBorderMat

Func _cudaIntegral(ByRef $src, ByRef $sum, ByRef $stream)
    ; CVAPI(void) cudaIntegral(cv::_InputArray* src, cv::_OutputArray* sum, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaIntegral", "ptr", $src, "ptr", $sum, "ptr", $stream), "cudaIntegral", @error)
EndFunc   ;==>_cudaIntegral

Func _cudaIntegralMat(ByRef $matSrc, ByRef $matSum, ByRef $stream)
    ; cudaIntegral using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrSum, $vectorOfMatSum, $iArrSumSize
    Local $bSumIsArray = VarGetType($matSum) == "Array"

    If $bSumIsArray Then
        $vectorOfMatSum = _VectorOfMatCreate()

        $iArrSumSize = UBound($matSum)
        For $i = 0 To $iArrSumSize - 1
            _VectorOfMatPush($vectorOfMatSum, $matSum[$i])
        Next

        $oArrSum = _cveOutputArrayFromVectorOfMat($vectorOfMatSum)
    Else
        $oArrSum = _cveOutputArrayFromMat($matSum)
    EndIf

    _cudaIntegral($iArrSrc, $oArrSum, $stream)

    If $bSumIsArray Then
        _VectorOfMatRelease($vectorOfMatSum)
    EndIf

    _cveOutputArrayRelease($oArrSum)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaIntegralMat

Func _cudaSqrIntegral(ByRef $src, ByRef $sqrSum, ByRef $stream)
    ; CVAPI(void) cudaSqrIntegral(cv::_InputArray* src, cv::_OutputArray* sqrSum, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqrIntegral", "ptr", $src, "ptr", $sqrSum, "ptr", $stream), "cudaSqrIntegral", @error)
EndFunc   ;==>_cudaSqrIntegral

Func _cudaSqrIntegralMat(ByRef $matSrc, ByRef $matSqrSum, ByRef $stream)
    ; cudaSqrIntegral using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrSqrSum, $vectorOfMatSqrSum, $iArrSqrSumSize
    Local $bSqrSumIsArray = VarGetType($matSqrSum) == "Array"

    If $bSqrSumIsArray Then
        $vectorOfMatSqrSum = _VectorOfMatCreate()

        $iArrSqrSumSize = UBound($matSqrSum)
        For $i = 0 To $iArrSqrSumSize - 1
            _VectorOfMatPush($vectorOfMatSqrSum, $matSqrSum[$i])
        Next

        $oArrSqrSum = _cveOutputArrayFromVectorOfMat($vectorOfMatSqrSum)
    Else
        $oArrSqrSum = _cveOutputArrayFromMat($matSqrSum)
    EndIf

    _cudaSqrIntegral($iArrSrc, $oArrSqrSum, $stream)

    If $bSqrSumIsArray Then
        _VectorOfMatRelease($vectorOfMatSqrSum)
    EndIf

    _cveOutputArrayRelease($oArrSqrSum)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaSqrIntegralMat

Func _cudaDft(ByRef $src, ByRef $dst, ByRef $dftSize, $flags, ByRef $stream)
    ; CVAPI(void) cudaDft(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dftSize, int flags, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDft", "ptr", $src, "ptr", $dst, "struct*", $dftSize, "int", $flags, "ptr", $stream), "cudaDft", @error)
EndFunc   ;==>_cudaDft

Func _cudaDftMat(ByRef $matSrc, ByRef $matDst, ByRef $dftSize, $flags, ByRef $stream)
    ; cudaDft using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaDft($iArrSrc, $oArrDst, $dftSize, $flags, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaDftMat

Func _cudaMulAndScaleSpectrums(ByRef $src1, ByRef $src2, ByRef $dst, $flags, $scale, $conjB, ByRef $stream)
    ; CVAPI(void) cudaMulAndScaleSpectrums(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int flags, float scale, bool conjB, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMulAndScaleSpectrums", "ptr", $src1, "ptr", $src2, "ptr", $dst, "int", $flags, "float", $scale, "boolean", $conjB, "ptr", $stream), "cudaMulAndScaleSpectrums", @error)
EndFunc   ;==>_cudaMulAndScaleSpectrums

Func _cudaMulAndScaleSpectrumsMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, $flags, $scale, $conjB, ByRef $stream)
    ; cudaMulAndScaleSpectrums using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMulAndScaleSpectrums($iArrSrc1, $iArrSrc2, $oArrDst, $flags, $scale, $conjB, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaMulAndScaleSpectrumsMat

Func _cudaMulSpectrums(ByRef $src1, ByRef $src2, ByRef $dst, $flags, $conjB, ByRef $stream)
    ; CVAPI(void) cudaMulSpectrums(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int flags, bool conjB, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMulSpectrums", "ptr", $src1, "ptr", $src2, "ptr", $dst, "int", $flags, "boolean", $conjB, "ptr", $stream), "cudaMulSpectrums", @error)
EndFunc   ;==>_cudaMulSpectrums

Func _cudaMulSpectrumsMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, $flags, $conjB, ByRef $stream)
    ; cudaMulSpectrums using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMulSpectrums($iArrSrc1, $iArrSrc2, $oArrDst, $flags, $conjB, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaMulSpectrumsMat

Func _cudaFlip(ByRef $src, ByRef $dst, $flipcode, ByRef $stream)
    ; CVAPI(void) cudaFlip(cv::_InputArray* src, cv::_OutputArray* dst, int flipcode, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFlip", "ptr", $src, "ptr", $dst, "int", $flipcode, "ptr", $stream), "cudaFlip", @error)
EndFunc   ;==>_cudaFlip

Func _cudaFlipMat(ByRef $matSrc, ByRef $matDst, $flipcode, ByRef $stream)
    ; cudaFlip using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaFlip($iArrSrc, $oArrDst, $flipcode, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaFlipMat

Func _cudaSplit(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaSplit(cv::_InputArray* src, std::vector< cv::cuda::GpuMat >* dst, cv::cuda::Stream* stream);

    Local $vecDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($dst) == "Array"

    If $bDstIsArray Then
        $vecDst = _VectorOfGpuMatCreate()

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfGpuMatPush($vecDst, $dst[$i])
        Next
    Else
        $vecDst = $dst
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSplit", "ptr", $src, "ptr", $vecDst, "ptr", $stream), "cudaSplit", @error)

    If $bDstIsArray Then
        _VectorOfGpuMatRelease($vecDst)
    EndIf
EndFunc   ;==>_cudaSplit

Func _cudaSplitMat(ByRef $matSrc, ByRef $dst, ByRef $stream)
    ; cudaSplit using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    _cudaSplit($iArrSrc, $dst, $stream)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaSplitMat

Func _cudaLookUpTableCreate(ByRef $lut, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::LookUpTable*) cudaLookUpTableCreate(cv::_InputArray* lut, cv::Ptr<cv::cuda::LookUpTable>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaLookUpTableCreate", "ptr", $lut, "ptr*", $sharedPtr), "cudaLookUpTableCreate", @error)
EndFunc   ;==>_cudaLookUpTableCreate

Func _cudaLookUpTableCreateMat(ByRef $matLut, ByRef $sharedPtr)
    ; cudaLookUpTableCreate using cv::Mat instead of _*Array

    Local $iArrLut, $vectorOfMatLut, $iArrLutSize
    Local $bLutIsArray = VarGetType($matLut) == "Array"

    If $bLutIsArray Then
        $vectorOfMatLut = _VectorOfMatCreate()

        $iArrLutSize = UBound($matLut)
        For $i = 0 To $iArrLutSize - 1
            _VectorOfMatPush($vectorOfMatLut, $matLut[$i])
        Next

        $iArrLut = _cveInputArrayFromVectorOfMat($vectorOfMatLut)
    Else
        $iArrLut = _cveInputArrayFromMat($matLut)
    EndIf

    Local $retval = _cudaLookUpTableCreate($iArrLut, $sharedPtr)

    If $bLutIsArray Then
        _VectorOfMatRelease($vectorOfMatLut)
    EndIf

    _cveInputArrayRelease($iArrLut)

    Return $retval
EndFunc   ;==>_cudaLookUpTableCreateMat

Func _cudaLookUpTableTransform(ByRef $lut, ByRef $image, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaLookUpTableTransform(cv::cuda::LookUpTable* lut, cv::_InputArray* image, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLookUpTableTransform", "ptr", $lut, "ptr", $image, "ptr", $dst, "ptr", $stream), "cudaLookUpTableTransform", @error)
EndFunc   ;==>_cudaLookUpTableTransform

Func _cudaLookUpTableTransformMat(ByRef $lut, ByRef $matImage, ByRef $matDst, ByRef $stream)
    ; cudaLookUpTableTransform using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaLookUpTableTransform($lut, $iArrImage, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cudaLookUpTableTransformMat

Func _cudaLookUpTableRelease(ByRef $lut)
    ; CVAPI(void) cudaLookUpTableRelease(cv::Ptr<cv::cuda::LookUpTable>** lut);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLookUpTableRelease", "ptr*", $lut), "cudaLookUpTableRelease", @error)
EndFunc   ;==>_cudaLookUpTableRelease

Func _cudaTranspose(ByRef $src1, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaTranspose(cv::_InputArray* src1, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaTranspose", "ptr", $src1, "ptr", $dst, "ptr", $stream), "cudaTranspose", @error)
EndFunc   ;==>_cudaTranspose

Func _cudaTransposeMat(ByRef $matSrc1, ByRef $matDst, ByRef $stream)
    ; cudaTranspose using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaTranspose($iArrSrc1, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cudaTransposeMat

Func _cudaNormalize(ByRef $src, ByRef $dst, $alpha, $beta, $norm_type, $dtype, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaNormalize(cv::_InputArray* src, cv::_OutputArray* dst, double alpha, double beta, int norm_type, int dtype, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNormalize", "ptr", $src, "ptr", $dst, "double", $alpha, "double", $beta, "int", $norm_type, "int", $dtype, "ptr", $mask, "ptr", $stream), "cudaNormalize", @error)
EndFunc   ;==>_cudaNormalize

Func _cudaNormalizeMat(ByRef $matSrc, ByRef $matDst, $alpha, $beta, $norm_type, $dtype, ByRef $matMask, ByRef $stream)
    ; cudaNormalize using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaNormalize($iArrSrc, $oArrDst, $alpha, $beta, $norm_type, $dtype, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaNormalizeMat

Func _cudaConvolutionCreate(ByRef $userBlockSize, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Convolution*) cudaConvolutionCreate(CvSize* userBlockSize, cv::Ptr<cv::cuda::Convolution>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaConvolutionCreate", "struct*", $userBlockSize, "ptr*", $sharedPtr), "cudaConvolutionCreate", @error)
EndFunc   ;==>_cudaConvolutionCreate

Func _cudaConvolutionConvolve(ByRef $convolution, ByRef $image, ByRef $templ, ByRef $result, $ccorr, ByRef $stream)
    ; CVAPI(void) cudaConvolutionConvolve(cv::cuda::Convolution* convolution, cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, bool ccorr, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvolutionConvolve", "ptr", $convolution, "ptr", $image, "ptr", $templ, "ptr", $result, "boolean", $ccorr, "ptr", $stream), "cudaConvolutionConvolve", @error)
EndFunc   ;==>_cudaConvolutionConvolve

Func _cudaConvolutionConvolveMat(ByRef $convolution, ByRef $matImage, ByRef $matTempl, ByRef $matResult, $ccorr, ByRef $stream)
    ; cudaConvolutionConvolve using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $iArrTempl, $vectorOfMatTempl, $iArrTemplSize
    Local $bTemplIsArray = VarGetType($matTempl) == "Array"

    If $bTemplIsArray Then
        $vectorOfMatTempl = _VectorOfMatCreate()

        $iArrTemplSize = UBound($matTempl)
        For $i = 0 To $iArrTemplSize - 1
            _VectorOfMatPush($vectorOfMatTempl, $matTempl[$i])
        Next

        $iArrTempl = _cveInputArrayFromVectorOfMat($vectorOfMatTempl)
    Else
        $iArrTempl = _cveInputArrayFromMat($matTempl)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cudaConvolutionConvolve($convolution, $iArrImage, $iArrTempl, $oArrResult, $ccorr, $stream)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bTemplIsArray Then
        _VectorOfMatRelease($vectorOfMatTempl)
    EndIf

    _cveInputArrayRelease($iArrTempl)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cudaConvolutionConvolveMat

Func _cudaConvolutionRelease(ByRef $convolution)
    ; CVAPI(void) cudaConvolutionRelease(cv::Ptr<cv::cuda::Convolution>** convolution);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvolutionRelease", "ptr*", $convolution), "cudaConvolutionRelease", @error)
EndFunc   ;==>_cudaConvolutionRelease

Func _cudaInRange(ByRef $src, ByRef $lowerb, ByRef $upperb, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaInRange(cv::_InputArray* src, CvScalar* lowerb, CvScalar* upperb, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaInRange", "ptr", $src, "struct*", $lowerb, "struct*", $upperb, "ptr", $dst, "ptr", $stream), "cudaInRange", @error)
EndFunc   ;==>_cudaInRange

Func _cudaInRangeMat(ByRef $matSrc, ByRef $lowerb, ByRef $upperb, ByRef $matDst, ByRef $stream)
    ; cudaInRange using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaInRange($iArrSrc, $lowerb, $upperb, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaInRangeMat

Func _cudaSetGlDevice($device)
    ; CVAPI(void) cudaSetGlDevice(int device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSetGlDevice", "int", $device), "cudaSetGlDevice", @error)
EndFunc   ;==>_cudaSetGlDevice