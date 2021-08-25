#include-once
#include "..\..\CVEUtils.au3"

Func _cudaExp($a, $b, $stream)
    ; CVAPI(void) cudaExp(cv::_InputArray* a, cv::_OutputArray* b, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaExp", $sADllType, $a, $sBDllType, $b, $sStreamDllType, $stream), "cudaExp", @error)
EndFunc   ;==>_cudaExp

Func _cudaExpTyped($typeOfA, $a, $typeOfB, $b, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $oArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $oArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $oArrB = Call("_cveOutputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $oArrB = Call("_cveOutputArrayFrom" & $typeOfB, $b)
    EndIf

    _cudaExp($iArrA, $oArrB, $stream)

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveOutputArrayRelease($oArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaExpTyped

Func _cudaExpMat($a, $b, $stream)
    ; cudaExp using cv::Mat instead of _*Array
    _cudaExpTyped("Mat", $a, "Mat", $b, $stream)
EndFunc   ;==>_cudaExpMat

Func _cudaPow($src, $power, $dst, $stream)
    ; CVAPI(void) cudaPow(cv::_InputArray* src, double power, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPow", $sSrcDllType, $src, "double", $power, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaPow", @error)
EndFunc   ;==>_cudaPow

Func _cudaPowTyped($typeOfSrc, $src, $power, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaPow($iArrSrc, $power, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaPowTyped

Func _cudaPowMat($src, $power, $dst, $stream)
    ; cudaPow using cv::Mat instead of _*Array
    _cudaPowTyped("Mat", $src, $power, "Mat", $dst, $stream)
EndFunc   ;==>_cudaPowMat

Func _cudaLog($a, $b, $stream)
    ; CVAPI(void) cudaLog(cv::_InputArray* a, cv::_OutputArray* b, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLog", $sADllType, $a, $sBDllType, $b, $sStreamDllType, $stream), "cudaLog", @error)
EndFunc   ;==>_cudaLog

Func _cudaLogTyped($typeOfA, $a, $typeOfB, $b, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $oArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $oArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $oArrB = Call("_cveOutputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $oArrB = Call("_cveOutputArrayFrom" & $typeOfB, $b)
    EndIf

    _cudaLog($iArrA, $oArrB, $stream)

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveOutputArrayRelease($oArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaLogTyped

Func _cudaLogMat($a, $b, $stream)
    ; cudaLog using cv::Mat instead of _*Array
    _cudaLogTyped("Mat", $a, "Mat", $b, $stream)
EndFunc   ;==>_cudaLogMat

Func _cudaMagnitude($x, $y, $magnitude, $stream)
    ; CVAPI(void) cudaMagnitude(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::cuda::Stream* stream);

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf

    Local $sMagnitudeDllType
    If IsDllStruct($magnitude) Then
        $sMagnitudeDllType = "struct*"
    Else
        $sMagnitudeDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMagnitude", $sXDllType, $x, $sYDllType, $y, $sMagnitudeDllType, $magnitude, $sStreamDllType, $stream), "cudaMagnitude", @error)
EndFunc   ;==>_cudaMagnitude

Func _cudaMagnitudeTyped($typeOfX, $x, $typeOfY, $y, $typeOfMagnitude, $magnitude, $stream)

    Local $iArrX, $vectorX, $iArrXSize
    Local $bXIsArray = IsArray($x)
    Local $bXCreate = IsDllStruct($x) And $typeOfX == "Scalar"

    If $typeOfX == Default Then
        $iArrX = $x
    ElseIf $bXIsArray Then
        $vectorX = Call("_VectorOf" & $typeOfX & "Create")

        $iArrXSize = UBound($x)
        For $i = 0 To $iArrXSize - 1
            Call("_VectorOf" & $typeOfX & "Push", $vectorX, $x[$i])
        Next

        $iArrX = Call("_cveInputArrayFromVectorOf" & $typeOfX, $vectorX)
    Else
        If $bXCreate Then
            $x = Call("_cve" & $typeOfX & "Create", $x)
        EndIf
        $iArrX = Call("_cveInputArrayFrom" & $typeOfX, $x)
    EndIf

    Local $iArrY, $vectorY, $iArrYSize
    Local $bYIsArray = IsArray($y)
    Local $bYCreate = IsDllStruct($y) And $typeOfY == "Scalar"

    If $typeOfY == Default Then
        $iArrY = $y
    ElseIf $bYIsArray Then
        $vectorY = Call("_VectorOf" & $typeOfY & "Create")

        $iArrYSize = UBound($y)
        For $i = 0 To $iArrYSize - 1
            Call("_VectorOf" & $typeOfY & "Push", $vectorY, $y[$i])
        Next

        $iArrY = Call("_cveInputArrayFromVectorOf" & $typeOfY, $vectorY)
    Else
        If $bYCreate Then
            $y = Call("_cve" & $typeOfY & "Create", $y)
        EndIf
        $iArrY = Call("_cveInputArrayFrom" & $typeOfY, $y)
    EndIf

    Local $oArrMagnitude, $vectorMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = IsArray($magnitude)
    Local $bMagnitudeCreate = IsDllStruct($magnitude) And $typeOfMagnitude == "Scalar"

    If $typeOfMagnitude == Default Then
        $oArrMagnitude = $magnitude
    ElseIf $bMagnitudeIsArray Then
        $vectorMagnitude = Call("_VectorOf" & $typeOfMagnitude & "Create")

        $iArrMagnitudeSize = UBound($magnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            Call("_VectorOf" & $typeOfMagnitude & "Push", $vectorMagnitude, $magnitude[$i])
        Next

        $oArrMagnitude = Call("_cveOutputArrayFromVectorOf" & $typeOfMagnitude, $vectorMagnitude)
    Else
        If $bMagnitudeCreate Then
            $magnitude = Call("_cve" & $typeOfMagnitude & "Create", $magnitude)
        EndIf
        $oArrMagnitude = Call("_cveOutputArrayFrom" & $typeOfMagnitude, $magnitude)
    EndIf

    _cudaMagnitude($iArrX, $iArrY, $oArrMagnitude, $stream)

    If $bMagnitudeIsArray Then
        Call("_VectorOf" & $typeOfMagnitude & "Release", $vectorMagnitude)
    EndIf

    If $typeOfMagnitude <> Default Then
        _cveOutputArrayRelease($oArrMagnitude)
        If $bMagnitudeCreate Then
            Call("_cve" & $typeOfMagnitude & "Release", $magnitude)
        EndIf
    EndIf

    If $bYIsArray Then
        Call("_VectorOf" & $typeOfY & "Release", $vectorY)
    EndIf

    If $typeOfY <> Default Then
        _cveInputArrayRelease($iArrY)
        If $bYCreate Then
            Call("_cve" & $typeOfY & "Release", $y)
        EndIf
    EndIf

    If $bXIsArray Then
        Call("_VectorOf" & $typeOfX & "Release", $vectorX)
    EndIf

    If $typeOfX <> Default Then
        _cveInputArrayRelease($iArrX)
        If $bXCreate Then
            Call("_cve" & $typeOfX & "Release", $x)
        EndIf
    EndIf
EndFunc   ;==>_cudaMagnitudeTyped

Func _cudaMagnitudeMat($x, $y, $magnitude, $stream)
    ; cudaMagnitude using cv::Mat instead of _*Array
    _cudaMagnitudeTyped("Mat", $x, "Mat", $y, "Mat", $magnitude, $stream)
EndFunc   ;==>_cudaMagnitudeMat

Func _cudaMagnitudeSqr($x, $y, $magnitude, $stream)
    ; CVAPI(void) cudaMagnitudeSqr(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::cuda::Stream* stream);

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf

    Local $sMagnitudeDllType
    If IsDllStruct($magnitude) Then
        $sMagnitudeDllType = "struct*"
    Else
        $sMagnitudeDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMagnitudeSqr", $sXDllType, $x, $sYDllType, $y, $sMagnitudeDllType, $magnitude, $sStreamDllType, $stream), "cudaMagnitudeSqr", @error)
EndFunc   ;==>_cudaMagnitudeSqr

Func _cudaMagnitudeSqrTyped($typeOfX, $x, $typeOfY, $y, $typeOfMagnitude, $magnitude, $stream)

    Local $iArrX, $vectorX, $iArrXSize
    Local $bXIsArray = IsArray($x)
    Local $bXCreate = IsDllStruct($x) And $typeOfX == "Scalar"

    If $typeOfX == Default Then
        $iArrX = $x
    ElseIf $bXIsArray Then
        $vectorX = Call("_VectorOf" & $typeOfX & "Create")

        $iArrXSize = UBound($x)
        For $i = 0 To $iArrXSize - 1
            Call("_VectorOf" & $typeOfX & "Push", $vectorX, $x[$i])
        Next

        $iArrX = Call("_cveInputArrayFromVectorOf" & $typeOfX, $vectorX)
    Else
        If $bXCreate Then
            $x = Call("_cve" & $typeOfX & "Create", $x)
        EndIf
        $iArrX = Call("_cveInputArrayFrom" & $typeOfX, $x)
    EndIf

    Local $iArrY, $vectorY, $iArrYSize
    Local $bYIsArray = IsArray($y)
    Local $bYCreate = IsDllStruct($y) And $typeOfY == "Scalar"

    If $typeOfY == Default Then
        $iArrY = $y
    ElseIf $bYIsArray Then
        $vectorY = Call("_VectorOf" & $typeOfY & "Create")

        $iArrYSize = UBound($y)
        For $i = 0 To $iArrYSize - 1
            Call("_VectorOf" & $typeOfY & "Push", $vectorY, $y[$i])
        Next

        $iArrY = Call("_cveInputArrayFromVectorOf" & $typeOfY, $vectorY)
    Else
        If $bYCreate Then
            $y = Call("_cve" & $typeOfY & "Create", $y)
        EndIf
        $iArrY = Call("_cveInputArrayFrom" & $typeOfY, $y)
    EndIf

    Local $oArrMagnitude, $vectorMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = IsArray($magnitude)
    Local $bMagnitudeCreate = IsDllStruct($magnitude) And $typeOfMagnitude == "Scalar"

    If $typeOfMagnitude == Default Then
        $oArrMagnitude = $magnitude
    ElseIf $bMagnitudeIsArray Then
        $vectorMagnitude = Call("_VectorOf" & $typeOfMagnitude & "Create")

        $iArrMagnitudeSize = UBound($magnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            Call("_VectorOf" & $typeOfMagnitude & "Push", $vectorMagnitude, $magnitude[$i])
        Next

        $oArrMagnitude = Call("_cveOutputArrayFromVectorOf" & $typeOfMagnitude, $vectorMagnitude)
    Else
        If $bMagnitudeCreate Then
            $magnitude = Call("_cve" & $typeOfMagnitude & "Create", $magnitude)
        EndIf
        $oArrMagnitude = Call("_cveOutputArrayFrom" & $typeOfMagnitude, $magnitude)
    EndIf

    _cudaMagnitudeSqr($iArrX, $iArrY, $oArrMagnitude, $stream)

    If $bMagnitudeIsArray Then
        Call("_VectorOf" & $typeOfMagnitude & "Release", $vectorMagnitude)
    EndIf

    If $typeOfMagnitude <> Default Then
        _cveOutputArrayRelease($oArrMagnitude)
        If $bMagnitudeCreate Then
            Call("_cve" & $typeOfMagnitude & "Release", $magnitude)
        EndIf
    EndIf

    If $bYIsArray Then
        Call("_VectorOf" & $typeOfY & "Release", $vectorY)
    EndIf

    If $typeOfY <> Default Then
        _cveInputArrayRelease($iArrY)
        If $bYCreate Then
            Call("_cve" & $typeOfY & "Release", $y)
        EndIf
    EndIf

    If $bXIsArray Then
        Call("_VectorOf" & $typeOfX & "Release", $vectorX)
    EndIf

    If $typeOfX <> Default Then
        _cveInputArrayRelease($iArrX)
        If $bXCreate Then
            Call("_cve" & $typeOfX & "Release", $x)
        EndIf
    EndIf
EndFunc   ;==>_cudaMagnitudeSqrTyped

Func _cudaMagnitudeSqrMat($x, $y, $magnitude, $stream)
    ; cudaMagnitudeSqr using cv::Mat instead of _*Array
    _cudaMagnitudeSqrTyped("Mat", $x, "Mat", $y, "Mat", $magnitude, $stream)
EndFunc   ;==>_cudaMagnitudeSqrMat

Func _cudaPhase($x, $y, $angle, $angleInDegrees, $stream)
    ; CVAPI(void) cudaPhase(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* angle, bool angleInDegrees, cv::cuda::Stream* stream);

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf

    Local $sAngleDllType
    If IsDllStruct($angle) Then
        $sAngleDllType = "struct*"
    Else
        $sAngleDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPhase", $sXDllType, $x, $sYDllType, $y, $sAngleDllType, $angle, "boolean", $angleInDegrees, $sStreamDllType, $stream), "cudaPhase", @error)
EndFunc   ;==>_cudaPhase

Func _cudaPhaseTyped($typeOfX, $x, $typeOfY, $y, $typeOfAngle, $angle, $angleInDegrees, $stream)

    Local $iArrX, $vectorX, $iArrXSize
    Local $bXIsArray = IsArray($x)
    Local $bXCreate = IsDllStruct($x) And $typeOfX == "Scalar"

    If $typeOfX == Default Then
        $iArrX = $x
    ElseIf $bXIsArray Then
        $vectorX = Call("_VectorOf" & $typeOfX & "Create")

        $iArrXSize = UBound($x)
        For $i = 0 To $iArrXSize - 1
            Call("_VectorOf" & $typeOfX & "Push", $vectorX, $x[$i])
        Next

        $iArrX = Call("_cveInputArrayFromVectorOf" & $typeOfX, $vectorX)
    Else
        If $bXCreate Then
            $x = Call("_cve" & $typeOfX & "Create", $x)
        EndIf
        $iArrX = Call("_cveInputArrayFrom" & $typeOfX, $x)
    EndIf

    Local $iArrY, $vectorY, $iArrYSize
    Local $bYIsArray = IsArray($y)
    Local $bYCreate = IsDllStruct($y) And $typeOfY == "Scalar"

    If $typeOfY == Default Then
        $iArrY = $y
    ElseIf $bYIsArray Then
        $vectorY = Call("_VectorOf" & $typeOfY & "Create")

        $iArrYSize = UBound($y)
        For $i = 0 To $iArrYSize - 1
            Call("_VectorOf" & $typeOfY & "Push", $vectorY, $y[$i])
        Next

        $iArrY = Call("_cveInputArrayFromVectorOf" & $typeOfY, $vectorY)
    Else
        If $bYCreate Then
            $y = Call("_cve" & $typeOfY & "Create", $y)
        EndIf
        $iArrY = Call("_cveInputArrayFrom" & $typeOfY, $y)
    EndIf

    Local $oArrAngle, $vectorAngle, $iArrAngleSize
    Local $bAngleIsArray = IsArray($angle)
    Local $bAngleCreate = IsDllStruct($angle) And $typeOfAngle == "Scalar"

    If $typeOfAngle == Default Then
        $oArrAngle = $angle
    ElseIf $bAngleIsArray Then
        $vectorAngle = Call("_VectorOf" & $typeOfAngle & "Create")

        $iArrAngleSize = UBound($angle)
        For $i = 0 To $iArrAngleSize - 1
            Call("_VectorOf" & $typeOfAngle & "Push", $vectorAngle, $angle[$i])
        Next

        $oArrAngle = Call("_cveOutputArrayFromVectorOf" & $typeOfAngle, $vectorAngle)
    Else
        If $bAngleCreate Then
            $angle = Call("_cve" & $typeOfAngle & "Create", $angle)
        EndIf
        $oArrAngle = Call("_cveOutputArrayFrom" & $typeOfAngle, $angle)
    EndIf

    _cudaPhase($iArrX, $iArrY, $oArrAngle, $angleInDegrees, $stream)

    If $bAngleIsArray Then
        Call("_VectorOf" & $typeOfAngle & "Release", $vectorAngle)
    EndIf

    If $typeOfAngle <> Default Then
        _cveOutputArrayRelease($oArrAngle)
        If $bAngleCreate Then
            Call("_cve" & $typeOfAngle & "Release", $angle)
        EndIf
    EndIf

    If $bYIsArray Then
        Call("_VectorOf" & $typeOfY & "Release", $vectorY)
    EndIf

    If $typeOfY <> Default Then
        _cveInputArrayRelease($iArrY)
        If $bYCreate Then
            Call("_cve" & $typeOfY & "Release", $y)
        EndIf
    EndIf

    If $bXIsArray Then
        Call("_VectorOf" & $typeOfX & "Release", $vectorX)
    EndIf

    If $typeOfX <> Default Then
        _cveInputArrayRelease($iArrX)
        If $bXCreate Then
            Call("_cve" & $typeOfX & "Release", $x)
        EndIf
    EndIf
EndFunc   ;==>_cudaPhaseTyped

Func _cudaPhaseMat($x, $y, $angle, $angleInDegrees, $stream)
    ; cudaPhase using cv::Mat instead of _*Array
    _cudaPhaseTyped("Mat", $x, "Mat", $y, "Mat", $angle, $angleInDegrees, $stream)
EndFunc   ;==>_cudaPhaseMat

Func _cudaCartToPolar($x, $y, $magnitude, $angle, $angleInDegrees, $stream)
    ; CVAPI(void) cudaCartToPolar(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::_OutputArray* angle, bool angleInDegrees, cv::cuda::Stream* stream);

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf

    Local $sMagnitudeDllType
    If IsDllStruct($magnitude) Then
        $sMagnitudeDllType = "struct*"
    Else
        $sMagnitudeDllType = "ptr"
    EndIf

    Local $sAngleDllType
    If IsDllStruct($angle) Then
        $sAngleDllType = "struct*"
    Else
        $sAngleDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCartToPolar", $sXDllType, $x, $sYDllType, $y, $sMagnitudeDllType, $magnitude, $sAngleDllType, $angle, "boolean", $angleInDegrees, $sStreamDllType, $stream), "cudaCartToPolar", @error)
EndFunc   ;==>_cudaCartToPolar

Func _cudaCartToPolarTyped($typeOfX, $x, $typeOfY, $y, $typeOfMagnitude, $magnitude, $typeOfAngle, $angle, $angleInDegrees, $stream)

    Local $iArrX, $vectorX, $iArrXSize
    Local $bXIsArray = IsArray($x)
    Local $bXCreate = IsDllStruct($x) And $typeOfX == "Scalar"

    If $typeOfX == Default Then
        $iArrX = $x
    ElseIf $bXIsArray Then
        $vectorX = Call("_VectorOf" & $typeOfX & "Create")

        $iArrXSize = UBound($x)
        For $i = 0 To $iArrXSize - 1
            Call("_VectorOf" & $typeOfX & "Push", $vectorX, $x[$i])
        Next

        $iArrX = Call("_cveInputArrayFromVectorOf" & $typeOfX, $vectorX)
    Else
        If $bXCreate Then
            $x = Call("_cve" & $typeOfX & "Create", $x)
        EndIf
        $iArrX = Call("_cveInputArrayFrom" & $typeOfX, $x)
    EndIf

    Local $iArrY, $vectorY, $iArrYSize
    Local $bYIsArray = IsArray($y)
    Local $bYCreate = IsDllStruct($y) And $typeOfY == "Scalar"

    If $typeOfY == Default Then
        $iArrY = $y
    ElseIf $bYIsArray Then
        $vectorY = Call("_VectorOf" & $typeOfY & "Create")

        $iArrYSize = UBound($y)
        For $i = 0 To $iArrYSize - 1
            Call("_VectorOf" & $typeOfY & "Push", $vectorY, $y[$i])
        Next

        $iArrY = Call("_cveInputArrayFromVectorOf" & $typeOfY, $vectorY)
    Else
        If $bYCreate Then
            $y = Call("_cve" & $typeOfY & "Create", $y)
        EndIf
        $iArrY = Call("_cveInputArrayFrom" & $typeOfY, $y)
    EndIf

    Local $oArrMagnitude, $vectorMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = IsArray($magnitude)
    Local $bMagnitudeCreate = IsDllStruct($magnitude) And $typeOfMagnitude == "Scalar"

    If $typeOfMagnitude == Default Then
        $oArrMagnitude = $magnitude
    ElseIf $bMagnitudeIsArray Then
        $vectorMagnitude = Call("_VectorOf" & $typeOfMagnitude & "Create")

        $iArrMagnitudeSize = UBound($magnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            Call("_VectorOf" & $typeOfMagnitude & "Push", $vectorMagnitude, $magnitude[$i])
        Next

        $oArrMagnitude = Call("_cveOutputArrayFromVectorOf" & $typeOfMagnitude, $vectorMagnitude)
    Else
        If $bMagnitudeCreate Then
            $magnitude = Call("_cve" & $typeOfMagnitude & "Create", $magnitude)
        EndIf
        $oArrMagnitude = Call("_cveOutputArrayFrom" & $typeOfMagnitude, $magnitude)
    EndIf

    Local $oArrAngle, $vectorAngle, $iArrAngleSize
    Local $bAngleIsArray = IsArray($angle)
    Local $bAngleCreate = IsDllStruct($angle) And $typeOfAngle == "Scalar"

    If $typeOfAngle == Default Then
        $oArrAngle = $angle
    ElseIf $bAngleIsArray Then
        $vectorAngle = Call("_VectorOf" & $typeOfAngle & "Create")

        $iArrAngleSize = UBound($angle)
        For $i = 0 To $iArrAngleSize - 1
            Call("_VectorOf" & $typeOfAngle & "Push", $vectorAngle, $angle[$i])
        Next

        $oArrAngle = Call("_cveOutputArrayFromVectorOf" & $typeOfAngle, $vectorAngle)
    Else
        If $bAngleCreate Then
            $angle = Call("_cve" & $typeOfAngle & "Create", $angle)
        EndIf
        $oArrAngle = Call("_cveOutputArrayFrom" & $typeOfAngle, $angle)
    EndIf

    _cudaCartToPolar($iArrX, $iArrY, $oArrMagnitude, $oArrAngle, $angleInDegrees, $stream)

    If $bAngleIsArray Then
        Call("_VectorOf" & $typeOfAngle & "Release", $vectorAngle)
    EndIf

    If $typeOfAngle <> Default Then
        _cveOutputArrayRelease($oArrAngle)
        If $bAngleCreate Then
            Call("_cve" & $typeOfAngle & "Release", $angle)
        EndIf
    EndIf

    If $bMagnitudeIsArray Then
        Call("_VectorOf" & $typeOfMagnitude & "Release", $vectorMagnitude)
    EndIf

    If $typeOfMagnitude <> Default Then
        _cveOutputArrayRelease($oArrMagnitude)
        If $bMagnitudeCreate Then
            Call("_cve" & $typeOfMagnitude & "Release", $magnitude)
        EndIf
    EndIf

    If $bYIsArray Then
        Call("_VectorOf" & $typeOfY & "Release", $vectorY)
    EndIf

    If $typeOfY <> Default Then
        _cveInputArrayRelease($iArrY)
        If $bYCreate Then
            Call("_cve" & $typeOfY & "Release", $y)
        EndIf
    EndIf

    If $bXIsArray Then
        Call("_VectorOf" & $typeOfX & "Release", $vectorX)
    EndIf

    If $typeOfX <> Default Then
        _cveInputArrayRelease($iArrX)
        If $bXCreate Then
            Call("_cve" & $typeOfX & "Release", $x)
        EndIf
    EndIf
EndFunc   ;==>_cudaCartToPolarTyped

Func _cudaCartToPolarMat($x, $y, $magnitude, $angle, $angleInDegrees, $stream)
    ; cudaCartToPolar using cv::Mat instead of _*Array
    _cudaCartToPolarTyped("Mat", $x, "Mat", $y, "Mat", $magnitude, "Mat", $angle, $angleInDegrees, $stream)
EndFunc   ;==>_cudaCartToPolarMat

Func _cudaPolarToCart($magnitude, $angle, $x, $y, $angleInDegrees, $stream)
    ; CVAPI(void) cudaPolarToCart(cv::_InputArray* magnitude, cv::_InputArray* angle, cv::_OutputArray* x, cv::_OutputArray* y, bool angleInDegrees, cv::cuda::Stream* stream);

    Local $sMagnitudeDllType
    If IsDllStruct($magnitude) Then
        $sMagnitudeDllType = "struct*"
    Else
        $sMagnitudeDllType = "ptr"
    EndIf

    Local $sAngleDllType
    If IsDllStruct($angle) Then
        $sAngleDllType = "struct*"
    Else
        $sAngleDllType = "ptr"
    EndIf

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPolarToCart", $sMagnitudeDllType, $magnitude, $sAngleDllType, $angle, $sXDllType, $x, $sYDllType, $y, "boolean", $angleInDegrees, $sStreamDllType, $stream), "cudaPolarToCart", @error)
EndFunc   ;==>_cudaPolarToCart

Func _cudaPolarToCartTyped($typeOfMagnitude, $magnitude, $typeOfAngle, $angle, $typeOfX, $x, $typeOfY, $y, $angleInDegrees, $stream)

    Local $iArrMagnitude, $vectorMagnitude, $iArrMagnitudeSize
    Local $bMagnitudeIsArray = IsArray($magnitude)
    Local $bMagnitudeCreate = IsDllStruct($magnitude) And $typeOfMagnitude == "Scalar"

    If $typeOfMagnitude == Default Then
        $iArrMagnitude = $magnitude
    ElseIf $bMagnitudeIsArray Then
        $vectorMagnitude = Call("_VectorOf" & $typeOfMagnitude & "Create")

        $iArrMagnitudeSize = UBound($magnitude)
        For $i = 0 To $iArrMagnitudeSize - 1
            Call("_VectorOf" & $typeOfMagnitude & "Push", $vectorMagnitude, $magnitude[$i])
        Next

        $iArrMagnitude = Call("_cveInputArrayFromVectorOf" & $typeOfMagnitude, $vectorMagnitude)
    Else
        If $bMagnitudeCreate Then
            $magnitude = Call("_cve" & $typeOfMagnitude & "Create", $magnitude)
        EndIf
        $iArrMagnitude = Call("_cveInputArrayFrom" & $typeOfMagnitude, $magnitude)
    EndIf

    Local $iArrAngle, $vectorAngle, $iArrAngleSize
    Local $bAngleIsArray = IsArray($angle)
    Local $bAngleCreate = IsDllStruct($angle) And $typeOfAngle == "Scalar"

    If $typeOfAngle == Default Then
        $iArrAngle = $angle
    ElseIf $bAngleIsArray Then
        $vectorAngle = Call("_VectorOf" & $typeOfAngle & "Create")

        $iArrAngleSize = UBound($angle)
        For $i = 0 To $iArrAngleSize - 1
            Call("_VectorOf" & $typeOfAngle & "Push", $vectorAngle, $angle[$i])
        Next

        $iArrAngle = Call("_cveInputArrayFromVectorOf" & $typeOfAngle, $vectorAngle)
    Else
        If $bAngleCreate Then
            $angle = Call("_cve" & $typeOfAngle & "Create", $angle)
        EndIf
        $iArrAngle = Call("_cveInputArrayFrom" & $typeOfAngle, $angle)
    EndIf

    Local $oArrX, $vectorX, $iArrXSize
    Local $bXIsArray = IsArray($x)
    Local $bXCreate = IsDllStruct($x) And $typeOfX == "Scalar"

    If $typeOfX == Default Then
        $oArrX = $x
    ElseIf $bXIsArray Then
        $vectorX = Call("_VectorOf" & $typeOfX & "Create")

        $iArrXSize = UBound($x)
        For $i = 0 To $iArrXSize - 1
            Call("_VectorOf" & $typeOfX & "Push", $vectorX, $x[$i])
        Next

        $oArrX = Call("_cveOutputArrayFromVectorOf" & $typeOfX, $vectorX)
    Else
        If $bXCreate Then
            $x = Call("_cve" & $typeOfX & "Create", $x)
        EndIf
        $oArrX = Call("_cveOutputArrayFrom" & $typeOfX, $x)
    EndIf

    Local $oArrY, $vectorY, $iArrYSize
    Local $bYIsArray = IsArray($y)
    Local $bYCreate = IsDllStruct($y) And $typeOfY == "Scalar"

    If $typeOfY == Default Then
        $oArrY = $y
    ElseIf $bYIsArray Then
        $vectorY = Call("_VectorOf" & $typeOfY & "Create")

        $iArrYSize = UBound($y)
        For $i = 0 To $iArrYSize - 1
            Call("_VectorOf" & $typeOfY & "Push", $vectorY, $y[$i])
        Next

        $oArrY = Call("_cveOutputArrayFromVectorOf" & $typeOfY, $vectorY)
    Else
        If $bYCreate Then
            $y = Call("_cve" & $typeOfY & "Create", $y)
        EndIf
        $oArrY = Call("_cveOutputArrayFrom" & $typeOfY, $y)
    EndIf

    _cudaPolarToCart($iArrMagnitude, $iArrAngle, $oArrX, $oArrY, $angleInDegrees, $stream)

    If $bYIsArray Then
        Call("_VectorOf" & $typeOfY & "Release", $vectorY)
    EndIf

    If $typeOfY <> Default Then
        _cveOutputArrayRelease($oArrY)
        If $bYCreate Then
            Call("_cve" & $typeOfY & "Release", $y)
        EndIf
    EndIf

    If $bXIsArray Then
        Call("_VectorOf" & $typeOfX & "Release", $vectorX)
    EndIf

    If $typeOfX <> Default Then
        _cveOutputArrayRelease($oArrX)
        If $bXCreate Then
            Call("_cve" & $typeOfX & "Release", $x)
        EndIf
    EndIf

    If $bAngleIsArray Then
        Call("_VectorOf" & $typeOfAngle & "Release", $vectorAngle)
    EndIf

    If $typeOfAngle <> Default Then
        _cveInputArrayRelease($iArrAngle)
        If $bAngleCreate Then
            Call("_cve" & $typeOfAngle & "Release", $angle)
        EndIf
    EndIf

    If $bMagnitudeIsArray Then
        Call("_VectorOf" & $typeOfMagnitude & "Release", $vectorMagnitude)
    EndIf

    If $typeOfMagnitude <> Default Then
        _cveInputArrayRelease($iArrMagnitude)
        If $bMagnitudeCreate Then
            Call("_cve" & $typeOfMagnitude & "Release", $magnitude)
        EndIf
    EndIf
EndFunc   ;==>_cudaPolarToCartTyped

Func _cudaPolarToCartMat($magnitude, $angle, $x, $y, $angleInDegrees, $stream)
    ; cudaPolarToCart using cv::Mat instead of _*Array
    _cudaPolarToCartTyped("Mat", $magnitude, "Mat", $angle, "Mat", $x, "Mat", $y, $angleInDegrees, $stream)
EndFunc   ;==>_cudaPolarToCartMat

Func _cudaMerge($src, $dst, $stream)
    ; CVAPI(void) cudaMerge(std::vector<cv::cuda::GpuMat>* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $vecSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)

    If $bSrcIsArray Then
        $vecSrc = _VectorOfGpuMatCreate()

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfGpuMatPush($vecSrc, $src[$i])
        Next
    Else
        $vecSrc = $src
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMerge", $sSrcDllType, $vecSrc, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaMerge", @error)

    If $bSrcIsArray Then
        _VectorOfGpuMatRelease($vecSrc)
    EndIf
EndFunc   ;==>_cudaMerge

Func _cudaMergeTyped($src, $typeOfDst, $dst, $stream)

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaMerge($src, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cudaMergeTyped

Func _cudaMergeMat($src, $dst, $stream)
    ; cudaMerge using cv::Mat instead of _*Array
    _cudaMergeTyped($src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaMergeMat

Func _cudaMeanStdDev($mtx, $mean, $stddev)
    ; CVAPI(void) cudaMeanStdDev(cv::_InputArray* mtx, CvScalar* mean, CvScalar* stddev);

    Local $sMtxDllType
    If IsDllStruct($mtx) Then
        $sMtxDllType = "struct*"
    Else
        $sMtxDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    Local $sStddevDllType
    If IsDllStruct($stddev) Then
        $sStddevDllType = "struct*"
    Else
        $sStddevDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanStdDev", $sMtxDllType, $mtx, $sMeanDllType, $mean, $sStddevDllType, $stddev), "cudaMeanStdDev", @error)
EndFunc   ;==>_cudaMeanStdDev

Func _cudaMeanStdDevTyped($typeOfMtx, $mtx, $mean, $stddev)

    Local $iArrMtx, $vectorMtx, $iArrMtxSize
    Local $bMtxIsArray = IsArray($mtx)
    Local $bMtxCreate = IsDllStruct($mtx) And $typeOfMtx == "Scalar"

    If $typeOfMtx == Default Then
        $iArrMtx = $mtx
    ElseIf $bMtxIsArray Then
        $vectorMtx = Call("_VectorOf" & $typeOfMtx & "Create")

        $iArrMtxSize = UBound($mtx)
        For $i = 0 To $iArrMtxSize - 1
            Call("_VectorOf" & $typeOfMtx & "Push", $vectorMtx, $mtx[$i])
        Next

        $iArrMtx = Call("_cveInputArrayFromVectorOf" & $typeOfMtx, $vectorMtx)
    Else
        If $bMtxCreate Then
            $mtx = Call("_cve" & $typeOfMtx & "Create", $mtx)
        EndIf
        $iArrMtx = Call("_cveInputArrayFrom" & $typeOfMtx, $mtx)
    EndIf

    _cudaMeanStdDev($iArrMtx, $mean, $stddev)

    If $bMtxIsArray Then
        Call("_VectorOf" & $typeOfMtx & "Release", $vectorMtx)
    EndIf

    If $typeOfMtx <> Default Then
        _cveInputArrayRelease($iArrMtx)
        If $bMtxCreate Then
            Call("_cve" & $typeOfMtx & "Release", $mtx)
        EndIf
    EndIf
EndFunc   ;==>_cudaMeanStdDevTyped

Func _cudaMeanStdDevMat($mtx, $mean, $stddev)
    ; cudaMeanStdDev using cv::Mat instead of _*Array
    _cudaMeanStdDevTyped("Mat", $mtx, $mean, $stddev)
EndFunc   ;==>_cudaMeanStdDevMat

Func _cudaNorm1($src1, $normType, $mask)
    ; CVAPI(double) cudaNorm1(cv::_InputArray* src1, int normType, cv::_InputArray* mask);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cudaNorm1", $sSrc1DllType, $src1, "int", $normType, $sMaskDllType, $mask), "cudaNorm1", @error)
EndFunc   ;==>_cudaNorm1

Func _cudaNorm1Typed($typeOfSrc1, $src1, $normType, $typeOfMask, $mask)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    Local $retval = _cudaNorm1($iArrSrc1, $normType, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaNorm1Typed

Func _cudaNorm1Mat($src1, $normType, $mask)
    ; cudaNorm1 using cv::Mat instead of _*Array
    Local $retval = _cudaNorm1Typed("Mat", $src1, $normType, "Mat", $mask)

    Return $retval
EndFunc   ;==>_cudaNorm1Mat

Func _cudaNorm2($src1, $src2, $normType)
    ; CVAPI(double) cudaNorm2(cv::_InputArray* src1, cv::_InputArray* src2, int normType);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cudaNorm2", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "int", $normType), "cudaNorm2", @error)
EndFunc   ;==>_cudaNorm2

Func _cudaNorm2Typed($typeOfSrc1, $src1, $typeOfSrc2, $src2, $normType)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $retval = _cudaNorm2($iArrSrc1, $iArrSrc2, $normType)

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaNorm2Typed

Func _cudaNorm2Mat($src1, $src2, $normType)
    ; cudaNorm2 using cv::Mat instead of _*Array
    Local $retval = _cudaNorm2Typed("Mat", $src1, "Mat", $src2, $normType)

    Return $retval
EndFunc   ;==>_cudaNorm2Mat

Func _cudaCalcNorm($src, $dst, $normType, $mask, $stream)
    ; CVAPI(void) cudaCalcNorm(cv::_InputArray* src, cv::_OutputArray* dst, int normType, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcNorm", $sSrcDllType, $src, $sDstDllType, $dst, "int", $normType, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaCalcNorm", @error)
EndFunc   ;==>_cudaCalcNorm

Func _cudaCalcNormTyped($typeOfSrc, $src, $typeOfDst, $dst, $normType, $typeOfMask, $mask, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaCalcNorm($iArrSrc, $oArrDst, $normType, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCalcNormTyped

Func _cudaCalcNormMat($src, $dst, $normType, $mask, $stream)
    ; cudaCalcNorm using cv::Mat instead of _*Array
    _cudaCalcNormTyped("Mat", $src, "Mat", $dst, $normType, "Mat", $mask, $stream)
EndFunc   ;==>_cudaCalcNormMat

Func _cudaCalcNormDiff($src1, $src2, $dst, $normType, $stream)
    ; CVAPI(void) cudaCalcNormDiff(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int normType, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcNormDiff", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "int", $normType, $sStreamDllType, $stream), "cudaCalcNormDiff", @error)
EndFunc   ;==>_cudaCalcNormDiff

Func _cudaCalcNormDiffTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $normType, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaCalcNormDiff($iArrSrc1, $iArrSrc2, $oArrDst, $normType, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaCalcNormDiffTyped

Func _cudaCalcNormDiffMat($src1, $src2, $dst, $normType, $stream)
    ; cudaCalcNormDiff using cv::Mat instead of _*Array
    _cudaCalcNormDiffTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $normType, $stream)
EndFunc   ;==>_cudaCalcNormDiffMat

Func _cudaAbsSum($src, $sum, $mask)
    ; CVAPI(void) cudaAbsSum(cv::_InputArray* src, CvScalar* sum, cv::_InputArray* mask);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sSumDllType
    If IsDllStruct($sum) Then
        $sSumDllType = "struct*"
    Else
        $sSumDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAbsSum", $sSrcDllType, $src, $sSumDllType, $sum, $sMaskDllType, $mask), "cudaAbsSum", @error)
EndFunc   ;==>_cudaAbsSum

Func _cudaAbsSumTyped($typeOfSrc, $src, $sum, $typeOfMask, $mask)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaAbsSum($iArrSrc, $sum, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaAbsSumTyped

Func _cudaAbsSumMat($src, $sum, $mask)
    ; cudaAbsSum using cv::Mat instead of _*Array
    _cudaAbsSumTyped("Mat", $src, $sum, "Mat", $mask)
EndFunc   ;==>_cudaAbsSumMat

Func _cudaCalcAbsSum($src, $dst, $mask, $stream)
    ; CVAPI(void) cudaCalcAbsSum(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcAbsSum", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaCalcAbsSum", @error)
EndFunc   ;==>_cudaCalcAbsSum

Func _cudaCalcAbsSumTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaCalcAbsSum($iArrSrc, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCalcAbsSumTyped

Func _cudaCalcAbsSumMat($src, $dst, $mask, $stream)
    ; cudaCalcAbsSum using cv::Mat instead of _*Array
    _cudaCalcAbsSumTyped("Mat", $src, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_cudaCalcAbsSumMat

Func _cudaSqrSum($src, $sqrSum, $mask)
    ; CVAPI(void) cudaSqrSum(cv::_InputArray* src, CvScalar* sqrSum, cv::_InputArray* mask);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sSqrSumDllType
    If IsDllStruct($sqrSum) Then
        $sSqrSumDllType = "struct*"
    Else
        $sSqrSumDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqrSum", $sSrcDllType, $src, $sSqrSumDllType, $sqrSum, $sMaskDllType, $mask), "cudaSqrSum", @error)
EndFunc   ;==>_cudaSqrSum

Func _cudaSqrSumTyped($typeOfSrc, $src, $sqrSum, $typeOfMask, $mask)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaSqrSum($iArrSrc, $sqrSum, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaSqrSumTyped

Func _cudaSqrSumMat($src, $sqrSum, $mask)
    ; cudaSqrSum using cv::Mat instead of _*Array
    _cudaSqrSumTyped("Mat", $src, $sqrSum, "Mat", $mask)
EndFunc   ;==>_cudaSqrSumMat

Func _cudaCalcSqrSum($src, $dst, $mask, $stream)
    ; CVAPI(void) cudaCalcSqrSum(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcSqrSum", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaCalcSqrSum", @error)
EndFunc   ;==>_cudaCalcSqrSum

Func _cudaCalcSqrSumTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaCalcSqrSum($iArrSrc, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCalcSqrSumTyped

Func _cudaCalcSqrSumMat($src, $dst, $mask, $stream)
    ; cudaCalcSqrSum using cv::Mat instead of _*Array
    _cudaCalcSqrSumTyped("Mat", $src, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_cudaCalcSqrSumMat

Func _cudaMinMaxLoc($src, $minVal, $maxVal, $minLoc, $maxLoc, $mask)
    ; CVAPI(void) cudaMinMaxLoc(cv::_InputArray* src, double* minVal, double* maxVal, CvPoint* minLoc, CvPoint* maxLoc, cv::_InputArray* mask);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMinValDllType
    If IsDllStruct($minVal) Then
        $sMinValDllType = "struct*"
    Else
        $sMinValDllType = "double*"
    EndIf

    Local $sMaxValDllType
    If IsDllStruct($maxVal) Then
        $sMaxValDllType = "struct*"
    Else
        $sMaxValDllType = "double*"
    EndIf

    Local $sMinLocDllType
    If IsDllStruct($minLoc) Then
        $sMinLocDllType = "struct*"
    Else
        $sMinLocDllType = "ptr"
    EndIf

    Local $sMaxLocDllType
    If IsDllStruct($maxLoc) Then
        $sMaxLocDllType = "struct*"
    Else
        $sMaxLocDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMinMaxLoc", $sSrcDllType, $src, $sMinValDllType, $minVal, $sMaxValDllType, $maxVal, $sMinLocDllType, $minLoc, $sMaxLocDllType, $maxLoc, $sMaskDllType, $mask), "cudaMinMaxLoc", @error)
EndFunc   ;==>_cudaMinMaxLoc

Func _cudaMinMaxLocTyped($typeOfSrc, $src, $minVal, $maxVal, $minLoc, $maxLoc, $typeOfMask, $mask)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaMinMaxLoc($iArrSrc, $minVal, $maxVal, $minLoc, $maxLoc, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaMinMaxLocTyped

Func _cudaMinMaxLocMat($src, $minVal, $maxVal, $minLoc, $maxLoc, $mask)
    ; cudaMinMaxLoc using cv::Mat instead of _*Array
    _cudaMinMaxLocTyped("Mat", $src, $minVal, $maxVal, $minLoc, $maxLoc, "Mat", $mask)
EndFunc   ;==>_cudaMinMaxLocMat

Func _cudaFindMinMaxLoc($src, $minMaxVals, $loc, $mask, $stream)
    ; CVAPI(void) cudaFindMinMaxLoc(cv::_InputArray* src, cv::_OutputArray* minMaxVals, cv::_OutputArray* loc, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMinMaxValsDllType
    If IsDllStruct($minMaxVals) Then
        $sMinMaxValsDllType = "struct*"
    Else
        $sMinMaxValsDllType = "ptr"
    EndIf

    Local $sLocDllType
    If IsDllStruct($loc) Then
        $sLocDllType = "struct*"
    Else
        $sLocDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFindMinMaxLoc", $sSrcDllType, $src, $sMinMaxValsDllType, $minMaxVals, $sLocDllType, $loc, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaFindMinMaxLoc", @error)
EndFunc   ;==>_cudaFindMinMaxLoc

Func _cudaFindMinMaxLocTyped($typeOfSrc, $src, $typeOfMinMaxVals, $minMaxVals, $typeOfLoc, $loc, $typeOfMask, $mask, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrMinMaxVals, $vectorMinMaxVals, $iArrMinMaxValsSize
    Local $bMinMaxValsIsArray = IsArray($minMaxVals)
    Local $bMinMaxValsCreate = IsDllStruct($minMaxVals) And $typeOfMinMaxVals == "Scalar"

    If $typeOfMinMaxVals == Default Then
        $oArrMinMaxVals = $minMaxVals
    ElseIf $bMinMaxValsIsArray Then
        $vectorMinMaxVals = Call("_VectorOf" & $typeOfMinMaxVals & "Create")

        $iArrMinMaxValsSize = UBound($minMaxVals)
        For $i = 0 To $iArrMinMaxValsSize - 1
            Call("_VectorOf" & $typeOfMinMaxVals & "Push", $vectorMinMaxVals, $minMaxVals[$i])
        Next

        $oArrMinMaxVals = Call("_cveOutputArrayFromVectorOf" & $typeOfMinMaxVals, $vectorMinMaxVals)
    Else
        If $bMinMaxValsCreate Then
            $minMaxVals = Call("_cve" & $typeOfMinMaxVals & "Create", $minMaxVals)
        EndIf
        $oArrMinMaxVals = Call("_cveOutputArrayFrom" & $typeOfMinMaxVals, $minMaxVals)
    EndIf

    Local $oArrLoc, $vectorLoc, $iArrLocSize
    Local $bLocIsArray = IsArray($loc)
    Local $bLocCreate = IsDllStruct($loc) And $typeOfLoc == "Scalar"

    If $typeOfLoc == Default Then
        $oArrLoc = $loc
    ElseIf $bLocIsArray Then
        $vectorLoc = Call("_VectorOf" & $typeOfLoc & "Create")

        $iArrLocSize = UBound($loc)
        For $i = 0 To $iArrLocSize - 1
            Call("_VectorOf" & $typeOfLoc & "Push", $vectorLoc, $loc[$i])
        Next

        $oArrLoc = Call("_cveOutputArrayFromVectorOf" & $typeOfLoc, $vectorLoc)
    Else
        If $bLocCreate Then
            $loc = Call("_cve" & $typeOfLoc & "Create", $loc)
        EndIf
        $oArrLoc = Call("_cveOutputArrayFrom" & $typeOfLoc, $loc)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaFindMinMaxLoc($iArrSrc, $oArrMinMaxVals, $oArrLoc, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bLocIsArray Then
        Call("_VectorOf" & $typeOfLoc & "Release", $vectorLoc)
    EndIf

    If $typeOfLoc <> Default Then
        _cveOutputArrayRelease($oArrLoc)
        If $bLocCreate Then
            Call("_cve" & $typeOfLoc & "Release", $loc)
        EndIf
    EndIf

    If $bMinMaxValsIsArray Then
        Call("_VectorOf" & $typeOfMinMaxVals & "Release", $vectorMinMaxVals)
    EndIf

    If $typeOfMinMaxVals <> Default Then
        _cveOutputArrayRelease($oArrMinMaxVals)
        If $bMinMaxValsCreate Then
            Call("_cve" & $typeOfMinMaxVals & "Release", $minMaxVals)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaFindMinMaxLocTyped

Func _cudaFindMinMaxLocMat($src, $minMaxVals, $loc, $mask, $stream)
    ; cudaFindMinMaxLoc using cv::Mat instead of _*Array
    _cudaFindMinMaxLocTyped("Mat", $src, "Mat", $minMaxVals, "Mat", $loc, "Mat", $mask, $stream)
EndFunc   ;==>_cudaFindMinMaxLocMat

Func _cudaCountNonZero1($src)
    ; CVAPI(int) cudaCountNonZero1(cv::_InputArray* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaCountNonZero1", $sSrcDllType, $src), "cudaCountNonZero1", @error)
EndFunc   ;==>_cudaCountNonZero1

Func _cudaCountNonZero1Typed($typeOfSrc, $src)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $retval = _cudaCountNonZero1($iArrSrc)

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaCountNonZero1Typed

Func _cudaCountNonZero1Mat($src)
    ; cudaCountNonZero1 using cv::Mat instead of _*Array
    Local $retval = _cudaCountNonZero1Typed("Mat", $src)

    Return $retval
EndFunc   ;==>_cudaCountNonZero1Mat

Func _cudaCountNonZero2($src, $dst, $stream)
    ; CVAPI(void) cudaCountNonZero2(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCountNonZero2", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaCountNonZero2", @error)
EndFunc   ;==>_cudaCountNonZero2

Func _cudaCountNonZero2Typed($typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaCountNonZero2($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCountNonZero2Typed

Func _cudaCountNonZero2Mat($src, $dst, $stream)
    ; cudaCountNonZero2 using cv::Mat instead of _*Array
    _cudaCountNonZero2Typed("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaCountNonZero2Mat

Func _cudaReduce($mtx, $vec, $dim, $reduceOp, $dType, $stream)
    ; CVAPI(void) cudaReduce(cv::_InputArray* mtx, cv::_OutputArray* vec, int dim, int reduceOp, int dType, cv::cuda::Stream* stream);

    Local $sMtxDllType
    If IsDllStruct($mtx) Then
        $sMtxDllType = "struct*"
    Else
        $sMtxDllType = "ptr"
    EndIf

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaReduce", $sMtxDllType, $mtx, $sVecDllType, $vec, "int", $dim, "int", $reduceOp, "int", $dType, $sStreamDllType, $stream), "cudaReduce", @error)
EndFunc   ;==>_cudaReduce

Func _cudaReduceTyped($typeOfMtx, $mtx, $typeOfVec, $vec, $dim, $reduceOp, $dType, $stream)

    Local $iArrMtx, $vectorMtx, $iArrMtxSize
    Local $bMtxIsArray = IsArray($mtx)
    Local $bMtxCreate = IsDllStruct($mtx) And $typeOfMtx == "Scalar"

    If $typeOfMtx == Default Then
        $iArrMtx = $mtx
    ElseIf $bMtxIsArray Then
        $vectorMtx = Call("_VectorOf" & $typeOfMtx & "Create")

        $iArrMtxSize = UBound($mtx)
        For $i = 0 To $iArrMtxSize - 1
            Call("_VectorOf" & $typeOfMtx & "Push", $vectorMtx, $mtx[$i])
        Next

        $iArrMtx = Call("_cveInputArrayFromVectorOf" & $typeOfMtx, $vectorMtx)
    Else
        If $bMtxCreate Then
            $mtx = Call("_cve" & $typeOfMtx & "Create", $mtx)
        EndIf
        $iArrMtx = Call("_cveInputArrayFrom" & $typeOfMtx, $mtx)
    EndIf

    Local $oArrVec, $vectorVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)
    Local $bVecCreate = IsDllStruct($vec) And $typeOfVec == "Scalar"

    If $typeOfVec == Default Then
        $oArrVec = $vec
    ElseIf $bVecIsArray Then
        $vectorVec = Call("_VectorOf" & $typeOfVec & "Create")

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            Call("_VectorOf" & $typeOfVec & "Push", $vectorVec, $vec[$i])
        Next

        $oArrVec = Call("_cveOutputArrayFromVectorOf" & $typeOfVec, $vectorVec)
    Else
        If $bVecCreate Then
            $vec = Call("_cve" & $typeOfVec & "Create", $vec)
        EndIf
        $oArrVec = Call("_cveOutputArrayFrom" & $typeOfVec, $vec)
    EndIf

    _cudaReduce($iArrMtx, $oArrVec, $dim, $reduceOp, $dType, $stream)

    If $bVecIsArray Then
        Call("_VectorOf" & $typeOfVec & "Release", $vectorVec)
    EndIf

    If $typeOfVec <> Default Then
        _cveOutputArrayRelease($oArrVec)
        If $bVecCreate Then
            Call("_cve" & $typeOfVec & "Release", $vec)
        EndIf
    EndIf

    If $bMtxIsArray Then
        Call("_VectorOf" & $typeOfMtx & "Release", $vectorMtx)
    EndIf

    If $typeOfMtx <> Default Then
        _cveInputArrayRelease($iArrMtx)
        If $bMtxCreate Then
            Call("_cve" & $typeOfMtx & "Release", $mtx)
        EndIf
    EndIf
EndFunc   ;==>_cudaReduceTyped

Func _cudaReduceMat($mtx, $vec, $dim, $reduceOp, $dType, $stream)
    ; cudaReduce using cv::Mat instead of _*Array
    _cudaReduceTyped("Mat", $mtx, "Mat", $vec, $dim, $reduceOp, $dType, $stream)
EndFunc   ;==>_cudaReduceMat

Func _cudaBitwiseNot($src, $dst, $mask, $stream)
    ; CVAPI(void) cudaBitwiseNot(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseNot", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaBitwiseNot", @error)
EndFunc   ;==>_cudaBitwiseNot

Func _cudaBitwiseNotTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaBitwiseNot($iArrSrc, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaBitwiseNotTyped

Func _cudaBitwiseNotMat($src, $dst, $mask, $stream)
    ; cudaBitwiseNot using cv::Mat instead of _*Array
    _cudaBitwiseNotTyped("Mat", $src, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_cudaBitwiseNotMat

Func _cudaBitwiseAnd($src1, $src2, $dst, $mask, $stream)
    ; CVAPI(void) cudaBitwiseAnd(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseAnd", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaBitwiseAnd", @error)
EndFunc   ;==>_cudaBitwiseAnd

Func _cudaBitwiseAndTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaBitwiseAnd($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaBitwiseAndTyped

Func _cudaBitwiseAndMat($src1, $src2, $dst, $mask, $stream)
    ; cudaBitwiseAnd using cv::Mat instead of _*Array
    _cudaBitwiseAndTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_cudaBitwiseAndMat

Func _cudaBitwiseOr($src1, $src2, $dst, $mask, $stream)
    ; CVAPI(void) cudaBitwiseOr(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseOr", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaBitwiseOr", @error)
EndFunc   ;==>_cudaBitwiseOr

Func _cudaBitwiseOrTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaBitwiseOr($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaBitwiseOrTyped

Func _cudaBitwiseOrMat($src1, $src2, $dst, $mask, $stream)
    ; cudaBitwiseOr using cv::Mat instead of _*Array
    _cudaBitwiseOrTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_cudaBitwiseOrMat

Func _cudaBitwiseXor($src1, $src2, $dst, $mask, $stream)
    ; CVAPI(void) cudaBitwiseXor(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBitwiseXor", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaBitwiseXor", @error)
EndFunc   ;==>_cudaBitwiseXor

Func _cudaBitwiseXorTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaBitwiseXor($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaBitwiseXorTyped

Func _cudaBitwiseXorMat($src1, $src2, $dst, $mask, $stream)
    ; cudaBitwiseXor using cv::Mat instead of _*Array
    _cudaBitwiseXorTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_cudaBitwiseXorMat

Func _cudaMin($src1, $src2, $dst, $stream)
    ; CVAPI(void) cudaMin(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMin", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaMin", @error)
EndFunc   ;==>_cudaMin

Func _cudaMinTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaMin($iArrSrc1, $iArrSrc2, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaMinTyped

Func _cudaMinMat($src1, $src2, $dst, $stream)
    ; cudaMin using cv::Mat instead of _*Array
    _cudaMinTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $stream)
EndFunc   ;==>_cudaMinMat

Func _cudaMax($src1, $src2, $dst, $stream)
    ; CVAPI(void) cudaMax(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMax", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaMax", @error)
EndFunc   ;==>_cudaMax

Func _cudaMaxTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaMax($iArrSrc1, $iArrSrc2, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaMaxTyped

Func _cudaMaxMat($src1, $src2, $dst, $stream)
    ; cudaMax using cv::Mat instead of _*Array
    _cudaMaxTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $stream)
EndFunc   ;==>_cudaMaxMat

Func _cudaGemm($src1, $src2, $alpha, $src3, $beta, $dst, $flags, $stream)
    ; CVAPI(void) cudaGemm(cv::_InputArray* src1, cv::_InputArray* src2, double alpha, cv::_InputArray* src3, double beta, cv::_OutputArray* dst, int flags, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sSrc3DllType
    If IsDllStruct($src3) Then
        $sSrc3DllType = "struct*"
    Else
        $sSrc3DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaGemm", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "double", $alpha, $sSrc3DllType, $src3, "double", $beta, $sDstDllType, $dst, "int", $flags, $sStreamDllType, $stream), "cudaGemm", @error)
EndFunc   ;==>_cudaGemm

Func _cudaGemmTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $alpha, $typeOfSrc3, $src3, $beta, $typeOfDst, $dst, $flags, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $iArrSrc3, $vectorSrc3, $iArrSrc3Size
    Local $bSrc3IsArray = IsArray($src3)
    Local $bSrc3Create = IsDllStruct($src3) And $typeOfSrc3 == "Scalar"

    If $typeOfSrc3 == Default Then
        $iArrSrc3 = $src3
    ElseIf $bSrc3IsArray Then
        $vectorSrc3 = Call("_VectorOf" & $typeOfSrc3 & "Create")

        $iArrSrc3Size = UBound($src3)
        For $i = 0 To $iArrSrc3Size - 1
            Call("_VectorOf" & $typeOfSrc3 & "Push", $vectorSrc3, $src3[$i])
        Next

        $iArrSrc3 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc3, $vectorSrc3)
    Else
        If $bSrc3Create Then
            $src3 = Call("_cve" & $typeOfSrc3 & "Create", $src3)
        EndIf
        $iArrSrc3 = Call("_cveInputArrayFrom" & $typeOfSrc3, $src3)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaGemm($iArrSrc1, $iArrSrc2, $alpha, $iArrSrc3, $beta, $oArrDst, $flags, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc3IsArray Then
        Call("_VectorOf" & $typeOfSrc3 & "Release", $vectorSrc3)
    EndIf

    If $typeOfSrc3 <> Default Then
        _cveInputArrayRelease($iArrSrc3)
        If $bSrc3Create Then
            Call("_cve" & $typeOfSrc3 & "Release", $src3)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaGemmTyped

Func _cudaGemmMat($src1, $src2, $alpha, $src3, $beta, $dst, $flags, $stream)
    ; cudaGemm using cv::Mat instead of _*Array
    _cudaGemmTyped("Mat", $src1, "Mat", $src2, $alpha, "Mat", $src3, $beta, "Mat", $dst, $flags, $stream)
EndFunc   ;==>_cudaGemmMat

Func _cudaLShift($a, $scale, $c, $stream)
    ; CVAPI(void) cudaLShift(cv::_InputArray* a, CvScalar* scale, cv::_OutputArray* c, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sScaleDllType
    If IsDllStruct($scale) Then
        $sScaleDllType = "struct*"
    Else
        $sScaleDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLShift", $sADllType, $a, $sScaleDllType, $scale, $sCDllType, $c, $sStreamDllType, $stream), "cudaLShift", @error)
EndFunc   ;==>_cudaLShift

Func _cudaLShiftTyped($typeOfA, $a, $scale, $typeOfC, $c, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    _cudaLShift($iArrA, $scale, $oArrC, $stream)

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaLShiftTyped

Func _cudaLShiftMat($a, $scale, $c, $stream)
    ; cudaLShift using cv::Mat instead of _*Array
    _cudaLShiftTyped("Mat", $a, $scale, "Mat", $c, $stream)
EndFunc   ;==>_cudaLShiftMat

Func _cudaRShift($a, $scale, $c, $stream)
    ; CVAPI(void) cudaRShift(cv::_InputArray* a, CvScalar* scale, cv::_OutputArray* c, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sScaleDllType
    If IsDllStruct($scale) Then
        $sScaleDllType = "struct*"
    Else
        $sScaleDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaRShift", $sADllType, $a, $sScaleDllType, $scale, $sCDllType, $c, $sStreamDllType, $stream), "cudaRShift", @error)
EndFunc   ;==>_cudaRShift

Func _cudaRShiftTyped($typeOfA, $a, $scale, $typeOfC, $c, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    _cudaRShift($iArrA, $scale, $oArrC, $stream)

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaRShiftTyped

Func _cudaRShiftMat($a, $scale, $c, $stream)
    ; cudaRShift using cv::Mat instead of _*Array
    _cudaRShiftTyped("Mat", $a, $scale, "Mat", $c, $stream)
EndFunc   ;==>_cudaRShiftMat

Func _cudaAdd($a, $b, $c, $mask, $dtype, $stream)
    ; CVAPI(void) cudaAdd(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, cv::_InputArray* mask, int dtype, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAdd", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, $sMaskDllType, $mask, "int", $dtype, $sStreamDllType, $stream), "cudaAdd", @error)
EndFunc   ;==>_cudaAdd

Func _cudaAddTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $typeOfMask, $mask, $dtype, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $b)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaAdd($iArrA, $iArrB, $oArrC, $iArrMask, $dtype, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaAddTyped

Func _cudaAddMat($a, $b, $c, $mask, $dtype, $stream)
    ; cudaAdd using cv::Mat instead of _*Array
    _cudaAddTyped("Mat", $a, "Mat", $b, "Mat", $c, "Mat", $mask, $dtype, $stream)
EndFunc   ;==>_cudaAddMat

Func _cudaSubtract($a, $b, $c, $mask, $dtype, $stream)
    ; CVAPI(void) cudaSubtract(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, cv::_InputArray* mask, int dtype, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSubtract", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, $sMaskDllType, $mask, "int", $dtype, $sStreamDllType, $stream), "cudaSubtract", @error)
EndFunc   ;==>_cudaSubtract

Func _cudaSubtractTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $typeOfMask, $mask, $dtype, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $b)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaSubtract($iArrA, $iArrB, $oArrC, $iArrMask, $dtype, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaSubtractTyped

Func _cudaSubtractMat($a, $b, $c, $mask, $dtype, $stream)
    ; cudaSubtract using cv::Mat instead of _*Array
    _cudaSubtractTyped("Mat", $a, "Mat", $b, "Mat", $c, "Mat", $mask, $dtype, $stream)
EndFunc   ;==>_cudaSubtractMat

Func _cudaMultiply($a, $b, $c, $scale, $dtype, $stream)
    ; CVAPI(void) cudaMultiply(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, double scale, int dtype, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMultiply", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, "double", $scale, "int", $dtype, $sStreamDllType, $stream), "cudaMultiply", @error)
EndFunc   ;==>_cudaMultiply

Func _cudaMultiplyTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $scale, $dtype, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $b)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    _cudaMultiply($iArrA, $iArrB, $oArrC, $scale, $dtype, $stream)

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaMultiplyTyped

Func _cudaMultiplyMat($a, $b, $c, $scale, $dtype, $stream)
    ; cudaMultiply using cv::Mat instead of _*Array
    _cudaMultiplyTyped("Mat", $a, "Mat", $b, "Mat", $c, $scale, $dtype, $stream)
EndFunc   ;==>_cudaMultiplyMat

Func _cudaDivide($a, $b, $c, $scale, $dtype, $stream)
    ; CVAPI(void) cudaDivide(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, double scale, int dtype, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDivide", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, "double", $scale, "int", $dtype, $sStreamDllType, $stream), "cudaDivide", @error)
EndFunc   ;==>_cudaDivide

Func _cudaDivideTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $scale, $dtype, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $b)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    _cudaDivide($iArrA, $iArrB, $oArrC, $scale, $dtype, $stream)

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaDivideTyped

Func _cudaDivideMat($a, $b, $c, $scale, $dtype, $stream)
    ; cudaDivide using cv::Mat instead of _*Array
    _cudaDivideTyped("Mat", $a, "Mat", $b, "Mat", $c, $scale, $dtype, $stream)
EndFunc   ;==>_cudaDivideMat

Func _cudaAddWeighted($src1, $alpha, $src2, $beta, $gamma, $dst, $dtype, $stream)
    ; CVAPI(void) cudaAddWeighted(cv::_InputArray* src1, double alpha, cv::_InputArray* src2, double beta, double gamma, cv::_OutputArray* dst, int dtype, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAddWeighted", $sSrc1DllType, $src1, "double", $alpha, $sSrc2DllType, $src2, "double", $beta, "double", $gamma, $sDstDllType, $dst, "int", $dtype, $sStreamDllType, $stream), "cudaAddWeighted", @error)
EndFunc   ;==>_cudaAddWeighted

Func _cudaAddWeightedTyped($typeOfSrc1, $src1, $alpha, $typeOfSrc2, $src2, $beta, $gamma, $typeOfDst, $dst, $dtype, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaAddWeighted($iArrSrc1, $alpha, $iArrSrc2, $beta, $gamma, $oArrDst, $dtype, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaAddWeightedTyped

Func _cudaAddWeightedMat($src1, $alpha, $src2, $beta, $gamma, $dst, $dtype, $stream)
    ; cudaAddWeighted using cv::Mat instead of _*Array
    _cudaAddWeightedTyped("Mat", $src1, $alpha, "Mat", $src2, $beta, $gamma, "Mat", $dst, $dtype, $stream)
EndFunc   ;==>_cudaAddWeightedMat

Func _cudaAbsdiff($a, $b, $c, $stream)
    ; CVAPI(void) cudaAbsdiff(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAbsdiff", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, $sStreamDllType, $stream), "cudaAbsdiff", @error)
EndFunc   ;==>_cudaAbsdiff

Func _cudaAbsdiffTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $b)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    _cudaAbsdiff($iArrA, $iArrB, $oArrC, $stream)

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaAbsdiffTyped

Func _cudaAbsdiffMat($a, $b, $c, $stream)
    ; cudaAbsdiff using cv::Mat instead of _*Array
    _cudaAbsdiffTyped("Mat", $a, "Mat", $b, "Mat", $c, $stream)
EndFunc   ;==>_cudaAbsdiffMat

Func _cudaAbs($src, $dst, $stream)
    ; CVAPI(void) cudaAbs(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAbs", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaAbs", @error)
EndFunc   ;==>_cudaAbs

Func _cudaAbsTyped($typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaAbs($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaAbsTyped

Func _cudaAbsMat($src, $dst, $stream)
    ; cudaAbs using cv::Mat instead of _*Array
    _cudaAbsTyped("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaAbsMat

Func _cudaSqr($src, $dst, $stream)
    ; CVAPI(void) cudaSqr(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqr", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaSqr", @error)
EndFunc   ;==>_cudaSqr

Func _cudaSqrTyped($typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaSqr($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaSqrTyped

Func _cudaSqrMat($src, $dst, $stream)
    ; cudaSqr using cv::Mat instead of _*Array
    _cudaSqrTyped("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaSqrMat

Func _cudaSqrt($src, $dst, $stream)
    ; CVAPI(void) cudaSqrt(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqrt", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaSqrt", @error)
EndFunc   ;==>_cudaSqrt

Func _cudaSqrtTyped($typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaSqrt($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaSqrtTyped

Func _cudaSqrtMat($src, $dst, $stream)
    ; cudaSqrt using cv::Mat instead of _*Array
    _cudaSqrtTyped("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaSqrtMat

Func _cudaCompare($a, $b, $c, $cmpop, $stream)
    ; CVAPI(void) cudaCompare(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, int cmpop, cv::cuda::Stream* stream);

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCompare", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, "int", $cmpop, $sStreamDllType, $stream), "cudaCompare", @error)
EndFunc   ;==>_cudaCompare

Func _cudaCompareTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $cmpop, $stream)

    Local $iArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $iArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $iArrA = Call("_cveInputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $iArrA = Call("_cveInputArrayFrom" & $typeOfA, $a)
    EndIf

    Local $iArrB, $vectorB, $iArrBSize
    Local $bBIsArray = IsArray($b)
    Local $bBCreate = IsDllStruct($b) And $typeOfB == "Scalar"

    If $typeOfB == Default Then
        $iArrB = $b
    ElseIf $bBIsArray Then
        $vectorB = Call("_VectorOf" & $typeOfB & "Create")

        $iArrBSize = UBound($b)
        For $i = 0 To $iArrBSize - 1
            Call("_VectorOf" & $typeOfB & "Push", $vectorB, $b[$i])
        Next

        $iArrB = Call("_cveInputArrayFromVectorOf" & $typeOfB, $vectorB)
    Else
        If $bBCreate Then
            $b = Call("_cve" & $typeOfB & "Create", $b)
        EndIf
        $iArrB = Call("_cveInputArrayFrom" & $typeOfB, $b)
    EndIf

    Local $oArrC, $vectorC, $iArrCSize
    Local $bCIsArray = IsArray($c)
    Local $bCCreate = IsDllStruct($c) And $typeOfC == "Scalar"

    If $typeOfC == Default Then
        $oArrC = $c
    ElseIf $bCIsArray Then
        $vectorC = Call("_VectorOf" & $typeOfC & "Create")

        $iArrCSize = UBound($c)
        For $i = 0 To $iArrCSize - 1
            Call("_VectorOf" & $typeOfC & "Push", $vectorC, $c[$i])
        Next

        $oArrC = Call("_cveOutputArrayFromVectorOf" & $typeOfC, $vectorC)
    Else
        If $bCCreate Then
            $c = Call("_cve" & $typeOfC & "Create", $c)
        EndIf
        $oArrC = Call("_cveOutputArrayFrom" & $typeOfC, $c)
    EndIf

    _cudaCompare($iArrA, $iArrB, $oArrC, $cmpop, $stream)

    If $bCIsArray Then
        Call("_VectorOf" & $typeOfC & "Release", $vectorC)
    EndIf

    If $typeOfC <> Default Then
        _cveOutputArrayRelease($oArrC)
        If $bCCreate Then
            Call("_cve" & $typeOfC & "Release", $c)
        EndIf
    EndIf

    If $bBIsArray Then
        Call("_VectorOf" & $typeOfB & "Release", $vectorB)
    EndIf

    If $typeOfB <> Default Then
        _cveInputArrayRelease($iArrB)
        If $bBCreate Then
            Call("_cve" & $typeOfB & "Release", $b)
        EndIf
    EndIf

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputArrayRelease($iArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cudaCompareTyped

Func _cudaCompareMat($a, $b, $c, $cmpop, $stream)
    ; cudaCompare using cv::Mat instead of _*Array
    _cudaCompareTyped("Mat", $a, "Mat", $b, "Mat", $c, $cmpop, $stream)
EndFunc   ;==>_cudaCompareMat

Func _cudaThreshold($src, $dst, $thresh, $maxval, $type, $stream)
    ; CVAPI(double) cudaThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double thresh, double maxval, int type, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cudaThreshold", $sSrcDllType, $src, $sDstDllType, $dst, "double", $thresh, "double", $maxval, "int", $type, $sStreamDllType, $stream), "cudaThreshold", @error)
EndFunc   ;==>_cudaThreshold

Func _cudaThresholdTyped($typeOfSrc, $src, $typeOfDst, $dst, $thresh, $maxval, $type, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $retval = _cudaThreshold($iArrSrc, $oArrDst, $thresh, $maxval, $type, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaThresholdTyped

Func _cudaThresholdMat($src, $dst, $thresh, $maxval, $type, $stream)
    ; cudaThreshold using cv::Mat instead of _*Array
    Local $retval = _cudaThresholdTyped("Mat", $src, "Mat", $dst, $thresh, $maxval, $type, $stream)

    Return $retval
EndFunc   ;==>_cudaThresholdMat

Func _cudaCopyMakeBorder($src, $dst, $top, $bottom, $left, $right, $gpuBorderType, $value, $stream)
    ; CVAPI(void) cudaCopyMakeBorder(cv::_InputArray* src, cv::_OutputArray* dst, int top, int bottom, int left, int right, int gpuBorderType, const CvScalar* value, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCopyMakeBorder", $sSrcDllType, $src, $sDstDllType, $dst, "int", $top, "int", $bottom, "int", $left, "int", $right, "int", $gpuBorderType, $sValueDllType, $value, $sStreamDllType, $stream), "cudaCopyMakeBorder", @error)
EndFunc   ;==>_cudaCopyMakeBorder

Func _cudaCopyMakeBorderTyped($typeOfSrc, $src, $typeOfDst, $dst, $top, $bottom, $left, $right, $gpuBorderType, $value, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaCopyMakeBorder($iArrSrc, $oArrDst, $top, $bottom, $left, $right, $gpuBorderType, $value, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCopyMakeBorderTyped

Func _cudaCopyMakeBorderMat($src, $dst, $top, $bottom, $left, $right, $gpuBorderType, $value, $stream)
    ; cudaCopyMakeBorder using cv::Mat instead of _*Array
    _cudaCopyMakeBorderTyped("Mat", $src, "Mat", $dst, $top, $bottom, $left, $right, $gpuBorderType, $value, $stream)
EndFunc   ;==>_cudaCopyMakeBorderMat

Func _cudaIntegral($src, $sum, $stream)
    ; CVAPI(void) cudaIntegral(cv::_InputArray* src, cv::_OutputArray* sum, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sSumDllType
    If IsDllStruct($sum) Then
        $sSumDllType = "struct*"
    Else
        $sSumDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaIntegral", $sSrcDllType, $src, $sSumDllType, $sum, $sStreamDllType, $stream), "cudaIntegral", @error)
EndFunc   ;==>_cudaIntegral

Func _cudaIntegralTyped($typeOfSrc, $src, $typeOfSum, $sum, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrSum, $vectorSum, $iArrSumSize
    Local $bSumIsArray = IsArray($sum)
    Local $bSumCreate = IsDllStruct($sum) And $typeOfSum == "Scalar"

    If $typeOfSum == Default Then
        $oArrSum = $sum
    ElseIf $bSumIsArray Then
        $vectorSum = Call("_VectorOf" & $typeOfSum & "Create")

        $iArrSumSize = UBound($sum)
        For $i = 0 To $iArrSumSize - 1
            Call("_VectorOf" & $typeOfSum & "Push", $vectorSum, $sum[$i])
        Next

        $oArrSum = Call("_cveOutputArrayFromVectorOf" & $typeOfSum, $vectorSum)
    Else
        If $bSumCreate Then
            $sum = Call("_cve" & $typeOfSum & "Create", $sum)
        EndIf
        $oArrSum = Call("_cveOutputArrayFrom" & $typeOfSum, $sum)
    EndIf

    _cudaIntegral($iArrSrc, $oArrSum, $stream)

    If $bSumIsArray Then
        Call("_VectorOf" & $typeOfSum & "Release", $vectorSum)
    EndIf

    If $typeOfSum <> Default Then
        _cveOutputArrayRelease($oArrSum)
        If $bSumCreate Then
            Call("_cve" & $typeOfSum & "Release", $sum)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaIntegralTyped

Func _cudaIntegralMat($src, $sum, $stream)
    ; cudaIntegral using cv::Mat instead of _*Array
    _cudaIntegralTyped("Mat", $src, "Mat", $sum, $stream)
EndFunc   ;==>_cudaIntegralMat

Func _cudaSqrIntegral($src, $sqrSum, $stream)
    ; CVAPI(void) cudaSqrIntegral(cv::_InputArray* src, cv::_OutputArray* sqrSum, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sSqrSumDllType
    If IsDllStruct($sqrSum) Then
        $sSqrSumDllType = "struct*"
    Else
        $sSqrSumDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSqrIntegral", $sSrcDllType, $src, $sSqrSumDllType, $sqrSum, $sStreamDllType, $stream), "cudaSqrIntegral", @error)
EndFunc   ;==>_cudaSqrIntegral

Func _cudaSqrIntegralTyped($typeOfSrc, $src, $typeOfSqrSum, $sqrSum, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrSqrSum, $vectorSqrSum, $iArrSqrSumSize
    Local $bSqrSumIsArray = IsArray($sqrSum)
    Local $bSqrSumCreate = IsDllStruct($sqrSum) And $typeOfSqrSum == "Scalar"

    If $typeOfSqrSum == Default Then
        $oArrSqrSum = $sqrSum
    ElseIf $bSqrSumIsArray Then
        $vectorSqrSum = Call("_VectorOf" & $typeOfSqrSum & "Create")

        $iArrSqrSumSize = UBound($sqrSum)
        For $i = 0 To $iArrSqrSumSize - 1
            Call("_VectorOf" & $typeOfSqrSum & "Push", $vectorSqrSum, $sqrSum[$i])
        Next

        $oArrSqrSum = Call("_cveOutputArrayFromVectorOf" & $typeOfSqrSum, $vectorSqrSum)
    Else
        If $bSqrSumCreate Then
            $sqrSum = Call("_cve" & $typeOfSqrSum & "Create", $sqrSum)
        EndIf
        $oArrSqrSum = Call("_cveOutputArrayFrom" & $typeOfSqrSum, $sqrSum)
    EndIf

    _cudaSqrIntegral($iArrSrc, $oArrSqrSum, $stream)

    If $bSqrSumIsArray Then
        Call("_VectorOf" & $typeOfSqrSum & "Release", $vectorSqrSum)
    EndIf

    If $typeOfSqrSum <> Default Then
        _cveOutputArrayRelease($oArrSqrSum)
        If $bSqrSumCreate Then
            Call("_cve" & $typeOfSqrSum & "Release", $sqrSum)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaSqrIntegralTyped

Func _cudaSqrIntegralMat($src, $sqrSum, $stream)
    ; cudaSqrIntegral using cv::Mat instead of _*Array
    _cudaSqrIntegralTyped("Mat", $src, "Mat", $sqrSum, $stream)
EndFunc   ;==>_cudaSqrIntegralMat

Func _cudaDft($src, $dst, $dftSize, $flags, $stream)
    ; CVAPI(void) cudaDft(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dftSize, int flags, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sDftSizeDllType
    If IsDllStruct($dftSize) Then
        $sDftSizeDllType = "struct*"
    Else
        $sDftSizeDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDft", $sSrcDllType, $src, $sDstDllType, $dst, $sDftSizeDllType, $dftSize, "int", $flags, $sStreamDllType, $stream), "cudaDft", @error)
EndFunc   ;==>_cudaDft

Func _cudaDftTyped($typeOfSrc, $src, $typeOfDst, $dst, $dftSize, $flags, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaDft($iArrSrc, $oArrDst, $dftSize, $flags, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaDftTyped

Func _cudaDftMat($src, $dst, $dftSize, $flags, $stream)
    ; cudaDft using cv::Mat instead of _*Array
    _cudaDftTyped("Mat", $src, "Mat", $dst, $dftSize, $flags, $stream)
EndFunc   ;==>_cudaDftMat

Func _cudaMulAndScaleSpectrums($src1, $src2, $dst, $flags, $scale, $conjB, $stream)
    ; CVAPI(void) cudaMulAndScaleSpectrums(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int flags, float scale, bool conjB, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMulAndScaleSpectrums", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "int", $flags, "float", $scale, "boolean", $conjB, $sStreamDllType, $stream), "cudaMulAndScaleSpectrums", @error)
EndFunc   ;==>_cudaMulAndScaleSpectrums

Func _cudaMulAndScaleSpectrumsTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $flags, $scale, $conjB, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaMulAndScaleSpectrums($iArrSrc1, $iArrSrc2, $oArrDst, $flags, $scale, $conjB, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaMulAndScaleSpectrumsTyped

Func _cudaMulAndScaleSpectrumsMat($src1, $src2, $dst, $flags, $scale, $conjB, $stream)
    ; cudaMulAndScaleSpectrums using cv::Mat instead of _*Array
    _cudaMulAndScaleSpectrumsTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $flags, $scale, $conjB, $stream)
EndFunc   ;==>_cudaMulAndScaleSpectrumsMat

Func _cudaMulSpectrums($src1, $src2, $dst, $flags, $conjB, $stream)
    ; CVAPI(void) cudaMulSpectrums(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int flags, bool conjB, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMulSpectrums", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "int", $flags, "boolean", $conjB, $sStreamDllType, $stream), "cudaMulSpectrums", @error)
EndFunc   ;==>_cudaMulSpectrums

Func _cudaMulSpectrumsTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $flags, $conjB, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaMulSpectrums($iArrSrc1, $iArrSrc2, $oArrDst, $flags, $conjB, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaMulSpectrumsTyped

Func _cudaMulSpectrumsMat($src1, $src2, $dst, $flags, $conjB, $stream)
    ; cudaMulSpectrums using cv::Mat instead of _*Array
    _cudaMulSpectrumsTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $flags, $conjB, $stream)
EndFunc   ;==>_cudaMulSpectrumsMat

Func _cudaFlip($src, $dst, $flipcode, $stream)
    ; CVAPI(void) cudaFlip(cv::_InputArray* src, cv::_OutputArray* dst, int flipcode, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFlip", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flipcode, $sStreamDllType, $stream), "cudaFlip", @error)
EndFunc   ;==>_cudaFlip

Func _cudaFlipTyped($typeOfSrc, $src, $typeOfDst, $dst, $flipcode, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaFlip($iArrSrc, $oArrDst, $flipcode, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaFlipTyped

Func _cudaFlipMat($src, $dst, $flipcode, $stream)
    ; cudaFlip using cv::Mat instead of _*Array
    _cudaFlipTyped("Mat", $src, "Mat", $dst, $flipcode, $stream)
EndFunc   ;==>_cudaFlipMat

Func _cudaSplit($src, $dst, $stream)
    ; CVAPI(void) cudaSplit(cv::_InputArray* src, std::vector<cv::cuda::GpuMat>* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $vecDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)

    If $bDstIsArray Then
        $vecDst = _VectorOfGpuMatCreate()

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfGpuMatPush($vecDst, $dst[$i])
        Next
    Else
        $vecDst = $dst
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSplit", $sSrcDllType, $src, $sDstDllType, $vecDst, $sStreamDllType, $stream), "cudaSplit", @error)

    If $bDstIsArray Then
        _VectorOfGpuMatRelease($vecDst)
    EndIf
EndFunc   ;==>_cudaSplit

Func _cudaSplitTyped($typeOfSrc, $src, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    _cudaSplit($iArrSrc, $dst, $stream)

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaSplitTyped

Func _cudaSplitMat($src, $dst, $stream)
    ; cudaSplit using cv::Mat instead of _*Array
    _cudaSplitTyped("Mat", $src, $dst, $stream)
EndFunc   ;==>_cudaSplitMat

Func _cudaLookUpTableCreate($lut, $sharedPtr)
    ; CVAPI(cv::cuda::LookUpTable*) cudaLookUpTableCreate(cv::_InputArray* lut, cv::Ptr<cv::cuda::LookUpTable>** sharedPtr);

    Local $sLutDllType
    If IsDllStruct($lut) Then
        $sLutDllType = "struct*"
    Else
        $sLutDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaLookUpTableCreate", $sLutDllType, $lut, $sSharedPtrDllType, $sharedPtr), "cudaLookUpTableCreate", @error)
EndFunc   ;==>_cudaLookUpTableCreate

Func _cudaLookUpTableCreateTyped($typeOfLut, $lut, $sharedPtr)

    Local $iArrLut, $vectorLut, $iArrLutSize
    Local $bLutIsArray = IsArray($lut)
    Local $bLutCreate = IsDllStruct($lut) And $typeOfLut == "Scalar"

    If $typeOfLut == Default Then
        $iArrLut = $lut
    ElseIf $bLutIsArray Then
        $vectorLut = Call("_VectorOf" & $typeOfLut & "Create")

        $iArrLutSize = UBound($lut)
        For $i = 0 To $iArrLutSize - 1
            Call("_VectorOf" & $typeOfLut & "Push", $vectorLut, $lut[$i])
        Next

        $iArrLut = Call("_cveInputArrayFromVectorOf" & $typeOfLut, $vectorLut)
    Else
        If $bLutCreate Then
            $lut = Call("_cve" & $typeOfLut & "Create", $lut)
        EndIf
        $iArrLut = Call("_cveInputArrayFrom" & $typeOfLut, $lut)
    EndIf

    Local $retval = _cudaLookUpTableCreate($iArrLut, $sharedPtr)

    If $bLutIsArray Then
        Call("_VectorOf" & $typeOfLut & "Release", $vectorLut)
    EndIf

    If $typeOfLut <> Default Then
        _cveInputArrayRelease($iArrLut)
        If $bLutCreate Then
            Call("_cve" & $typeOfLut & "Release", $lut)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaLookUpTableCreateTyped

Func _cudaLookUpTableCreateMat($lut, $sharedPtr)
    ; cudaLookUpTableCreate using cv::Mat instead of _*Array
    Local $retval = _cudaLookUpTableCreateTyped("Mat", $lut, $sharedPtr)

    Return $retval
EndFunc   ;==>_cudaLookUpTableCreateMat

Func _cudaLookUpTableTransform($lut, $image, $dst, $stream)
    ; CVAPI(void) cudaLookUpTableTransform(cv::cuda::LookUpTable* lut, cv::_InputArray* image, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sLutDllType
    If IsDllStruct($lut) Then
        $sLutDllType = "struct*"
    Else
        $sLutDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLookUpTableTransform", $sLutDllType, $lut, $sImageDllType, $image, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaLookUpTableTransform", @error)
EndFunc   ;==>_cudaLookUpTableTransform

Func _cudaLookUpTableTransformTyped($lut, $typeOfImage, $image, $typeOfDst, $dst, $stream)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaLookUpTableTransform($lut, $iArrImage, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cudaLookUpTableTransformTyped

Func _cudaLookUpTableTransformMat($lut, $image, $dst, $stream)
    ; cudaLookUpTableTransform using cv::Mat instead of _*Array
    _cudaLookUpTableTransformTyped($lut, "Mat", $image, "Mat", $dst, $stream)
EndFunc   ;==>_cudaLookUpTableTransformMat

Func _cudaLookUpTableRelease($lut)
    ; CVAPI(void) cudaLookUpTableRelease(cv::Ptr<cv::cuda::LookUpTable>** lut);

    Local $sLutDllType
    If IsDllStruct($lut) Then
        $sLutDllType = "struct*"
    ElseIf $lut == Null Then
        $sLutDllType = "ptr"
    Else
        $sLutDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaLookUpTableRelease", $sLutDllType, $lut), "cudaLookUpTableRelease", @error)
EndFunc   ;==>_cudaLookUpTableRelease

Func _cudaTranspose($src1, $dst, $stream)
    ; CVAPI(void) cudaTranspose(cv::_InputArray* src1, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaTranspose", $sSrc1DllType, $src1, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaTranspose", @error)
EndFunc   ;==>_cudaTranspose

Func _cudaTransposeTyped($typeOfSrc1, $src1, $typeOfDst, $dst, $stream)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaTranspose($iArrSrc1, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cudaTransposeTyped

Func _cudaTransposeMat($src1, $dst, $stream)
    ; cudaTranspose using cv::Mat instead of _*Array
    _cudaTransposeTyped("Mat", $src1, "Mat", $dst, $stream)
EndFunc   ;==>_cudaTransposeMat

Func _cudaNormalize($src, $dst, $alpha, $beta, $norm_type, $dtype, $mask, $stream)
    ; CVAPI(void) cudaNormalize(cv::_InputArray* src, cv::_OutputArray* dst, double alpha, double beta, int norm_type, int dtype, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNormalize", $sSrcDllType, $src, $sDstDllType, $dst, "double", $alpha, "double", $beta, "int", $norm_type, "int", $dtype, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaNormalize", @error)
EndFunc   ;==>_cudaNormalize

Func _cudaNormalizeTyped($typeOfSrc, $src, $typeOfDst, $dst, $alpha, $beta, $norm_type, $dtype, $typeOfMask, $mask, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaNormalize($iArrSrc, $oArrDst, $alpha, $beta, $norm_type, $dtype, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaNormalizeTyped

Func _cudaNormalizeMat($src, $dst, $alpha, $beta, $norm_type, $dtype, $mask, $stream)
    ; cudaNormalize using cv::Mat instead of _*Array
    _cudaNormalizeTyped("Mat", $src, "Mat", $dst, $alpha, $beta, $norm_type, $dtype, "Mat", $mask, $stream)
EndFunc   ;==>_cudaNormalizeMat

Func _cudaConvolutionCreate($userBlockSize, $sharedPtr)
    ; CVAPI(cv::cuda::Convolution*) cudaConvolutionCreate(CvSize* userBlockSize, cv::Ptr<cv::cuda::Convolution>** sharedPtr);

    Local $sUserBlockSizeDllType
    If IsDllStruct($userBlockSize) Then
        $sUserBlockSizeDllType = "struct*"
    Else
        $sUserBlockSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaConvolutionCreate", $sUserBlockSizeDllType, $userBlockSize, $sSharedPtrDllType, $sharedPtr), "cudaConvolutionCreate", @error)
EndFunc   ;==>_cudaConvolutionCreate

Func _cudaConvolutionConvolve($convolution, $image, $templ, $result, $ccorr, $stream)
    ; CVAPI(void) cudaConvolutionConvolve(cv::cuda::Convolution* convolution, cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, bool ccorr, cv::cuda::Stream* stream);

    Local $sConvolutionDllType
    If IsDllStruct($convolution) Then
        $sConvolutionDllType = "struct*"
    Else
        $sConvolutionDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sTemplDllType
    If IsDllStruct($templ) Then
        $sTemplDllType = "struct*"
    Else
        $sTemplDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvolutionConvolve", $sConvolutionDllType, $convolution, $sImageDllType, $image, $sTemplDllType, $templ, $sResultDllType, $result, "boolean", $ccorr, $sStreamDllType, $stream), "cudaConvolutionConvolve", @error)
EndFunc   ;==>_cudaConvolutionConvolve

Func _cudaConvolutionConvolveTyped($convolution, $typeOfImage, $image, $typeOfTempl, $templ, $typeOfResult, $result, $ccorr, $stream)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrTempl, $vectorTempl, $iArrTemplSize
    Local $bTemplIsArray = IsArray($templ)
    Local $bTemplCreate = IsDllStruct($templ) And $typeOfTempl == "Scalar"

    If $typeOfTempl == Default Then
        $iArrTempl = $templ
    ElseIf $bTemplIsArray Then
        $vectorTempl = Call("_VectorOf" & $typeOfTempl & "Create")

        $iArrTemplSize = UBound($templ)
        For $i = 0 To $iArrTemplSize - 1
            Call("_VectorOf" & $typeOfTempl & "Push", $vectorTempl, $templ[$i])
        Next

        $iArrTempl = Call("_cveInputArrayFromVectorOf" & $typeOfTempl, $vectorTempl)
    Else
        If $bTemplCreate Then
            $templ = Call("_cve" & $typeOfTempl & "Create", $templ)
        EndIf
        $iArrTempl = Call("_cveInputArrayFrom" & $typeOfTempl, $templ)
    EndIf

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cudaConvolutionConvolve($convolution, $iArrImage, $iArrTempl, $oArrResult, $ccorr, $stream)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bTemplIsArray Then
        Call("_VectorOf" & $typeOfTempl & "Release", $vectorTempl)
    EndIf

    If $typeOfTempl <> Default Then
        _cveInputArrayRelease($iArrTempl)
        If $bTemplCreate Then
            Call("_cve" & $typeOfTempl & "Release", $templ)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cudaConvolutionConvolveTyped

Func _cudaConvolutionConvolveMat($convolution, $image, $templ, $result, $ccorr, $stream)
    ; cudaConvolutionConvolve using cv::Mat instead of _*Array
    _cudaConvolutionConvolveTyped($convolution, "Mat", $image, "Mat", $templ, "Mat", $result, $ccorr, $stream)
EndFunc   ;==>_cudaConvolutionConvolveMat

Func _cudaConvolutionRelease($convolution)
    ; CVAPI(void) cudaConvolutionRelease(cv::Ptr<cv::cuda::Convolution>** convolution);

    Local $sConvolutionDllType
    If IsDllStruct($convolution) Then
        $sConvolutionDllType = "struct*"
    ElseIf $convolution == Null Then
        $sConvolutionDllType = "ptr"
    Else
        $sConvolutionDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvolutionRelease", $sConvolutionDllType, $convolution), "cudaConvolutionRelease", @error)
EndFunc   ;==>_cudaConvolutionRelease

Func _cudaInRange($src, $lowerb, $upperb, $dst, $stream)
    ; CVAPI(void) cudaInRange(cv::_InputArray* src, CvScalar* lowerb, CvScalar* upperb, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sLowerbDllType
    If IsDllStruct($lowerb) Then
        $sLowerbDllType = "struct*"
    Else
        $sLowerbDllType = "ptr"
    EndIf

    Local $sUpperbDllType
    If IsDllStruct($upperb) Then
        $sUpperbDllType = "struct*"
    Else
        $sUpperbDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaInRange", $sSrcDllType, $src, $sLowerbDllType, $lowerb, $sUpperbDllType, $upperb, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaInRange", @error)
EndFunc   ;==>_cudaInRange

Func _cudaInRangeTyped($typeOfSrc, $src, $lowerb, $upperb, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaInRange($iArrSrc, $lowerb, $upperb, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaInRangeTyped

Func _cudaInRangeMat($src, $lowerb, $upperb, $dst, $stream)
    ; cudaInRange using cv::Mat instead of _*Array
    _cudaInRangeTyped("Mat", $src, $lowerb, $upperb, "Mat", $dst, $stream)
EndFunc   ;==>_cudaInRangeMat

Func _cudaSetGlDevice($device)
    ; CVAPI(void) cudaSetGlDevice(int device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSetGlDevice", "int", $device), "cudaSetGlDevice", @error)
EndFunc   ;==>_cudaSetGlDevice