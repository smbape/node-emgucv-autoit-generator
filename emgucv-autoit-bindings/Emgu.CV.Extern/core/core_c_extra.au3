#include-once
#include "..\..\CVEUtils.au3"

Func _cveRedirectError($error_handler, $userdata, $prev_userdata)
    ; CVAPI(CvErrorCallback) cveRedirectError(CvErrorCallback error_handler, void* userdata, void** prev_userdata);

    Local $bPrev_userdataDllType
    If VarGetType($prev_userdata) == "DLLStruct" Then
        $bPrev_userdataDllType = "struct*"
    Else
        $bPrev_userdataDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "CvErrorCallback:cdecl", "cveRedirectError", "CvErrorCallback", $error_handler, "struct*", $userdata, $bPrev_userdataDllType, $prev_userdata), "cveRedirectError", @error)
EndFunc   ;==>_cveRedirectError

Func _cveGetErrMode()
    ; CVAPI(int) cveGetErrMode();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetErrMode"), "cveGetErrMode", @error)
EndFunc   ;==>_cveGetErrMode

Func _cveSetErrMode($mode)
    ; CVAPI(int) cveSetErrMode(int mode);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSetErrMode", "int", $mode), "cveSetErrMode", @error)
EndFunc   ;==>_cveSetErrMode

Func _cveGetErrStatus()
    ; CVAPI(int) cveGetErrStatus();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetErrStatus"), "cveGetErrStatus", @error)
EndFunc   ;==>_cveGetErrStatus

Func _cveSetErrStatus($status)
    ; CVAPI(void) cveSetErrStatus(int status);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetErrStatus", "int", $status), "cveSetErrStatus", @error)
EndFunc   ;==>_cveSetErrStatus

Func _cveErrorStr($status)
    ; CVAPI(const char*) cveErrorStr(int status);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveErrorStr", "int", $status), "cveErrorStr", @error)
EndFunc   ;==>_cveErrorStr

Func _cveSetLogLevel($logLevel)
    ; CVAPI(int) cveSetLogLevel(int logLevel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSetLogLevel", "int", $logLevel), "cveSetLogLevel", @error)
EndFunc   ;==>_cveSetLogLevel

Func _cveGetLogLevel()
    ; CVAPI(int) cveGetLogLevel();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetLogLevel"), "cveGetLogLevel", @error)
EndFunc   ;==>_cveGetLogLevel

Func _cveGetNumThreads()
    ; CVAPI(int) cveGetNumThreads();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetNumThreads"), "cveGetNumThreads", @error)
EndFunc   ;==>_cveGetNumThreads

Func _cveSetNumThreads($nthreads)
    ; CVAPI(void) cveSetNumThreads(int nthreads);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetNumThreads", "int", $nthreads), "cveSetNumThreads", @error)
EndFunc   ;==>_cveSetNumThreads

Func _cveGetThreadNum()
    ; CVAPI(int) cveGetThreadNum();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetThreadNum"), "cveGetThreadNum", @error)
EndFunc   ;==>_cveGetThreadNum

Func _cveGetNumberOfCPUs()
    ; CVAPI(int) cveGetNumberOfCPUs();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetNumberOfCPUs"), "cveGetNumberOfCPUs", @error)
EndFunc   ;==>_cveGetNumberOfCPUs

Func _cveSetParallelForBackend($backendName, $propagateNumThreads = true)
    ; CVAPI(bool) cveSetParallelForBackend(cv::String* backendName, bool propagateNumThreads);

    Local $bBackendNameIsString = VarGetType($backendName) == "String"
    If $bBackendNameIsString Then
        $backendName = _cveStringCreateFromStr($backendName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSetParallelForBackend", "ptr", $backendName, "boolean", $propagateNumThreads), "cveSetParallelForBackend", @error)

    If $bBackendNameIsString Then
        _cveStringRelease($backendName)
    EndIf

    Return $retval
EndFunc   ;==>_cveSetParallelForBackend

Func _cveGetParallelBackends($backendNames)
    ; CVAPI(void) cveGetParallelBackends(std::vector< cv::String >* backendNames);

    Local $vecBackendNames, $iArrBackendNamesSize
    Local $bBackendNamesIsArray = VarGetType($backendNames) == "Array"

    If $bBackendNamesIsArray Then
        $vecBackendNames = _VectorOfCvStringCreate()

        $iArrBackendNamesSize = UBound($backendNames)
        For $i = 0 To $iArrBackendNamesSize - 1
            _VectorOfCvStringPush($vecBackendNames, $backendNames[$i])
        Next
    Else
        $vecBackendNames = $backendNames
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetParallelBackends", "ptr", $vecBackendNames), "cveGetParallelBackends", @error)

    If $bBackendNamesIsArray Then
        _VectorOfCvStringRelease($vecBackendNames)
    EndIf
EndFunc   ;==>_cveGetParallelBackends

Func _cveStringCreate()
    ; CVAPI(cv::String*) cveStringCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStringCreate"), "cveStringCreate", @error)
EndFunc   ;==>_cveStringCreate

Func _cveStringCreateFromStr($c)
    ; CVAPI(cv::String*) cveStringCreateFromStr(const char* c);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStringCreateFromStr", "str", $c), "cveStringCreateFromStr", @error)
EndFunc   ;==>_cveStringCreateFromStr

Func _cveStringGetCStr($string, $c, $size)
    ; CVAPI(void) cveStringGetCStr(cv::String* string, const char** c, int* size);

    Local $bStringIsString = VarGetType($string) == "String"
    If $bStringIsString Then
        $string = _cveStringCreateFromStr($string)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStringGetCStr", "ptr", $string, "struct*", $c, "struct*", $size), "cveStringGetCStr", @error)

    If $bStringIsString Then
        _cveStringRelease($string)
    EndIf
EndFunc   ;==>_cveStringGetCStr

Func _cveStringGetLength($string)
    ; CVAPI(int) cveStringGetLength(cv::String* string);

    Local $bStringIsString = VarGetType($string) == "String"
    If $bStringIsString Then
        $string = _cveStringCreateFromStr($string)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStringGetLength", "ptr", $string), "cveStringGetLength", @error)

    If $bStringIsString Then
        _cveStringRelease($string)
    EndIf

    Return $retval
EndFunc   ;==>_cveStringGetLength

Func _cveStringRelease($string)
    ; CVAPI(void) cveStringRelease(cv::String** string);

    Local $bStringDllType
    If VarGetType($string) == "DLLStruct" Then
        $bStringDllType = "struct*"
    Else
        $bStringDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStringRelease", $bStringDllType, $string), "cveStringRelease", @error)
EndFunc   ;==>_cveStringRelease

Func _cveInputArrayFromDouble($scalar)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromDouble(double* scalar);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromDouble", "struct*", $scalar), "cveInputArrayFromDouble", @error)
EndFunc   ;==>_cveInputArrayFromDouble

Func _cveInputArrayFromScalar($scalar)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromScalar(cv::Scalar* scalar);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromScalar", "ptr", $scalar), "cveInputArrayFromScalar", @error)
EndFunc   ;==>_cveInputArrayFromScalar

Func _cveInputArrayFromMat($mat)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromMat(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromMat", "ptr", $mat), "cveInputArrayFromMat", @error)
EndFunc   ;==>_cveInputArrayFromMat

Func _cveInputArrayFromGpuMat($mat)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromGpuMat(cv::cuda::GpuMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromGpuMat", "ptr", $mat), "cveInputArrayFromGpuMat", @error)
EndFunc   ;==>_cveInputArrayFromGpuMat

Func _cveInputArrayFromUMat($mat)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromUMat(cv::UMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromUMat", "ptr", $mat), "cveInputArrayFromUMat", @error)
EndFunc   ;==>_cveInputArrayFromUMat

Func _cveInputArrayGetDims($ia, $i)
    ; CVAPI(int) cveInputArrayGetDims(cv::_InputArray* ia, int i);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayGetDims", "ptr", $ia, "int", $i), "cveInputArrayGetDims", @error)
EndFunc   ;==>_cveInputArrayGetDims

Func _cveInputArrayGetDimsMat($matIa, $i)
    ; cveInputArrayGetDims using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    Local $retval = _cveInputArrayGetDims($iArrIa, $i)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)

    Return $retval
EndFunc   ;==>_cveInputArrayGetDimsMat

Func _cveInputArrayGetSize($ia, $size, $idx)
    ; CVAPI(void) cveInputArrayGetSize(cv::_InputArray* ia, CvSize* size, int idx);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetSize", "ptr", $ia, "struct*", $size, "int", $idx), "cveInputArrayGetSize", @error)
EndFunc   ;==>_cveInputArrayGetSize

Func _cveInputArrayGetSizeMat($matIa, $size, $idx)
    ; cveInputArrayGetSize using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    _cveInputArrayGetSize($iArrIa, $size, $idx)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)
EndFunc   ;==>_cveInputArrayGetSizeMat

Func _cveInputArrayGetDepth($ia, $idx)
    ; CVAPI(int) cveInputArrayGetDepth(cv::_InputArray* ia, int idx);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayGetDepth", "ptr", $ia, "int", $idx), "cveInputArrayGetDepth", @error)
EndFunc   ;==>_cveInputArrayGetDepth

Func _cveInputArrayGetDepthMat($matIa, $idx)
    ; cveInputArrayGetDepth using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    Local $retval = _cveInputArrayGetDepth($iArrIa, $idx)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)

    Return $retval
EndFunc   ;==>_cveInputArrayGetDepthMat

Func _cveInputArrayGetChannels($ia, $idx)
    ; CVAPI(int) cveInputArrayGetChannels(cv::_InputArray* ia, int idx);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayGetChannels", "ptr", $ia, "int", $idx), "cveInputArrayGetChannels", @error)
EndFunc   ;==>_cveInputArrayGetChannels

Func _cveInputArrayGetChannelsMat($matIa, $idx)
    ; cveInputArrayGetChannels using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    Local $retval = _cveInputArrayGetChannels($iArrIa, $idx)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)

    Return $retval
EndFunc   ;==>_cveInputArrayGetChannelsMat

Func _cveInputArrayIsEmpty($ia)
    ; CVAPI(bool) cveInputArrayIsEmpty(cv::_InputArray* ia);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsEmpty", "ptr", $ia), "cveInputArrayIsEmpty", @error)
EndFunc   ;==>_cveInputArrayIsEmpty

Func _cveInputArrayIsEmptyMat($matIa)
    ; cveInputArrayIsEmpty using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    Local $retval = _cveInputArrayIsEmpty($iArrIa)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)

    Return $retval
EndFunc   ;==>_cveInputArrayIsEmptyMat

Func _cveInputArrayRelease($arr)
    ; CVAPI(void) cveInputArrayRelease(cv::_InputArray** arr);

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayRelease", $bArrDllType, $arr), "cveInputArrayRelease", @error)
EndFunc   ;==>_cveInputArrayRelease

Func _cveInputArrayReleaseMat($matArr)
    ; cveInputArrayRelease using cv::Mat instead of _*Array

    Local $iArrArr, $vectorOfMatArr, $iArrArrSize
    Local $bArrIsArray = VarGetType($matArr) == "Array"

    If $bArrIsArray Then
        $vectorOfMatArr = _VectorOfMatCreate()

        $iArrArrSize = UBound($matArr)
        For $i = 0 To $iArrArrSize - 1
            _VectorOfMatPush($vectorOfMatArr, $matArr[$i])
        Next

        $iArrArr = _cveInputArrayFromVectorOfMat($vectorOfMatArr)
    Else
        $iArrArr = _cveInputArrayFromMat($matArr)
    EndIf

    _cveInputArrayRelease($iArrArr)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveInputArrayRelease($iArrArr)
EndFunc   ;==>_cveInputArrayReleaseMat

Func _cveInputArrayGetMat($ia, $idx, $mat)
    ; CVAPI(void) cveInputArrayGetMat(cv::_InputArray* ia, int idx, cv::Mat* mat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetMat", "ptr", $ia, "int", $idx, "ptr", $mat), "cveInputArrayGetMat", @error)
EndFunc   ;==>_cveInputArrayGetMat

Func _cveInputArrayGetMatMat($matIa, $idx, $mat)
    ; cveInputArrayGetMat using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    _cveInputArrayGetMat($iArrIa, $idx, $mat)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)
EndFunc   ;==>_cveInputArrayGetMatMat

Func _cveInputArrayGetUMat($ia, $idx, $umat)
    ; CVAPI(void) cveInputArrayGetUMat(cv::_InputArray* ia, int idx, cv::UMat* umat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetUMat", "ptr", $ia, "int", $idx, "ptr", $umat), "cveInputArrayGetUMat", @error)
EndFunc   ;==>_cveInputArrayGetUMat

Func _cveInputArrayGetUMatMat($matIa, $idx, $umat)
    ; cveInputArrayGetUMat using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    _cveInputArrayGetUMat($iArrIa, $idx, $umat)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)
EndFunc   ;==>_cveInputArrayGetUMatMat

Func _cveInputArrayGetGpuMat($ia, $gpuMat)
    ; CVAPI(void) cveInputArrayGetGpuMat(cv::_InputArray* ia, cv::cuda::GpuMat* gpuMat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetGpuMat", "ptr", $ia, "ptr", $gpuMat), "cveInputArrayGetGpuMat", @error)
EndFunc   ;==>_cveInputArrayGetGpuMat

Func _cveInputArrayGetGpuMatMat($matIa, $gpuMat)
    ; cveInputArrayGetGpuMat using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    _cveInputArrayGetGpuMat($iArrIa, $gpuMat)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)
EndFunc   ;==>_cveInputArrayGetGpuMatMat

Func _cveInputArrayCopyTo($ia, $arr, $mask)
    ; CVAPI(void) cveInputArrayCopyTo(cv::_InputArray* ia, cv::_OutputArray* arr, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayCopyTo", "ptr", $ia, "ptr", $arr, "ptr", $mask), "cveInputArrayCopyTo", @error)
EndFunc   ;==>_cveInputArrayCopyTo

Func _cveInputArrayCopyToMat($matIa, $matArr, $matMask)
    ; cveInputArrayCopyTo using cv::Mat instead of _*Array

    Local $iArrIa, $vectorOfMatIa, $iArrIaSize
    Local $bIaIsArray = VarGetType($matIa) == "Array"

    If $bIaIsArray Then
        $vectorOfMatIa = _VectorOfMatCreate()

        $iArrIaSize = UBound($matIa)
        For $i = 0 To $iArrIaSize - 1
            _VectorOfMatPush($vectorOfMatIa, $matIa[$i])
        Next

        $iArrIa = _cveInputArrayFromVectorOfMat($vectorOfMatIa)
    Else
        $iArrIa = _cveInputArrayFromMat($matIa)
    EndIf

    Local $oArrArr, $vectorOfMatArr, $iArrArrSize
    Local $bArrIsArray = VarGetType($matArr) == "Array"

    If $bArrIsArray Then
        $vectorOfMatArr = _VectorOfMatCreate()

        $iArrArrSize = UBound($matArr)
        For $i = 0 To $iArrArrSize - 1
            _VectorOfMatPush($vectorOfMatArr, $matArr[$i])
        Next

        $oArrArr = _cveOutputArrayFromVectorOfMat($vectorOfMatArr)
    Else
        $oArrArr = _cveOutputArrayFromMat($matArr)
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

    _cveInputArrayCopyTo($iArrIa, $oArrArr, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveOutputArrayRelease($oArrArr)

    If $bIaIsArray Then
        _VectorOfMatRelease($vectorOfMatIa)
    EndIf

    _cveInputArrayRelease($iArrIa)
EndFunc   ;==>_cveInputArrayCopyToMat

Func _cveOutputArrayFromMat($mat)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromMat(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromMat", "ptr", $mat), "cveOutputArrayFromMat", @error)
EndFunc   ;==>_cveOutputArrayFromMat

Func _cveOutputArrayFromGpuMat($mat)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromGpuMat(cv::cuda::GpuMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromGpuMat", "ptr", $mat), "cveOutputArrayFromGpuMat", @error)
EndFunc   ;==>_cveOutputArrayFromGpuMat

Func _cveOutputArrayFromUMat($mat)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromUMat(cv::UMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromUMat", "ptr", $mat), "cveOutputArrayFromUMat", @error)
EndFunc   ;==>_cveOutputArrayFromUMat

Func _cveOutputArrayRelease($arr)
    ; CVAPI(void) cveOutputArrayRelease(cv::_OutputArray** arr);

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOutputArrayRelease", $bArrDllType, $arr), "cveOutputArrayRelease", @error)
EndFunc   ;==>_cveOutputArrayRelease

Func _cveOutputArrayReleaseMat($matArr)
    ; cveOutputArrayRelease using cv::Mat instead of _*Array

    Local $oArrArr, $vectorOfMatArr, $iArrArrSize
    Local $bArrIsArray = VarGetType($matArr) == "Array"

    If $bArrIsArray Then
        $vectorOfMatArr = _VectorOfMatCreate()

        $iArrArrSize = UBound($matArr)
        For $i = 0 To $iArrArrSize - 1
            _VectorOfMatPush($vectorOfMatArr, $matArr[$i])
        Next

        $oArrArr = _cveOutputArrayFromVectorOfMat($vectorOfMatArr)
    Else
        $oArrArr = _cveOutputArrayFromMat($matArr)
    EndIf

    _cveOutputArrayRelease($oArrArr)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveOutputArrayRelease($oArrArr)
EndFunc   ;==>_cveOutputArrayReleaseMat

Func _cveInputOutputArrayFromMat($mat)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromMat(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromMat", "ptr", $mat), "cveInputOutputArrayFromMat", @error)
EndFunc   ;==>_cveInputOutputArrayFromMat

Func _cveInputOutputArrayFromUMat($mat)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromUMat(cv::UMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromUMat", "ptr", $mat), "cveInputOutputArrayFromUMat", @error)
EndFunc   ;==>_cveInputOutputArrayFromUMat

Func _cveInputOutputArrayFromGpuMat($mat)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromGpuMat(cv::cuda::GpuMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromGpuMat", "ptr", $mat), "cveInputOutputArrayFromGpuMat", @error)
EndFunc   ;==>_cveInputOutputArrayFromGpuMat

Func _cveInputOutputArrayRelease($arr)
    ; CVAPI(void) cveInputOutputArrayRelease(cv::_InputOutputArray** arr);

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputOutputArrayRelease", $bArrDllType, $arr), "cveInputOutputArrayRelease", @error)
EndFunc   ;==>_cveInputOutputArrayRelease

Func _cveInputOutputArrayReleaseMat($matArr)
    ; cveInputOutputArrayRelease using cv::Mat instead of _*Array

    Local $ioArrArr, $vectorOfMatArr, $iArrArrSize
    Local $bArrIsArray = VarGetType($matArr) == "Array"

    If $bArrIsArray Then
        $vectorOfMatArr = _VectorOfMatCreate()

        $iArrArrSize = UBound($matArr)
        For $i = 0 To $iArrArrSize - 1
            _VectorOfMatPush($vectorOfMatArr, $matArr[$i])
        Next

        $ioArrArr = _cveInputOutputArrayFromVectorOfMat($vectorOfMatArr)
    Else
        $ioArrArr = _cveInputOutputArrayFromMat($matArr)
    EndIf

    _cveInputOutputArrayRelease($ioArrArr)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveInputOutputArrayRelease($ioArrArr)
EndFunc   ;==>_cveInputOutputArrayReleaseMat

Func _cveScalarCreate($scalar)
    ; CVAPI(cv::Scalar*) cveScalarCreate(CvScalar* scalar);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveScalarCreate", "struct*", $scalar), "cveScalarCreate", @error)
EndFunc   ;==>_cveScalarCreate

Func _cveScalarRelease($scalar)
    ; CVAPI(void) cveScalarRelease(cv::Scalar** scalar);

    Local $bScalarDllType
    If VarGetType($scalar) == "DLLStruct" Then
        $bScalarDllType = "struct*"
    Else
        $bScalarDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScalarRelease", $bScalarDllType, $scalar), "cveScalarRelease", @error)
EndFunc   ;==>_cveScalarRelease

Func _cveMinMaxIdx($src, $minVal, $maxVal, $minIdx, $maxIdx, $mask)
    ; CVAPI(void) cveMinMaxIdx(cv::_InputArray* src, double* minVal, double* maxVal, int* minIdx, int* maxIdx, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinMaxIdx", "ptr", $src, "struct*", $minVal, "struct*", $maxVal, "struct*", $minIdx, "struct*", $maxIdx, "ptr", $mask), "cveMinMaxIdx", @error)
EndFunc   ;==>_cveMinMaxIdx

Func _cveMinMaxIdxMat($matSrc, $minVal, $maxVal, $minIdx, $maxIdx, $matMask)
    ; cveMinMaxIdx using cv::Mat instead of _*Array

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

    _cveMinMaxIdx($iArrSrc, $minVal, $maxVal, $minIdx, $maxIdx, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMinMaxIdxMat

Func _cveMinMaxLoc($src, $minVal, $maxVal, $minLoc, $macLoc, $mask = _cveNoArray())
    ; CVAPI(void) cveMinMaxLoc(cv::_InputArray* src, double* minVal, double* maxVal, CvPoint* minLoc, CvPoint* macLoc, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinMaxLoc", "ptr", $src, "struct*", $minVal, "struct*", $maxVal, "struct*", $minLoc, "struct*", $macLoc, "ptr", $mask), "cveMinMaxLoc", @error)
EndFunc   ;==>_cveMinMaxLoc

Func _cveMinMaxLocMat($matSrc, $minVal, $maxVal, $minLoc, $macLoc, $matMask = _cveNoArrayMat())
    ; cveMinMaxLoc using cv::Mat instead of _*Array

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

    _cveMinMaxLoc($iArrSrc, $minVal, $maxVal, $minLoc, $macLoc, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMinMaxLocMat

Func _cveBitwiseAnd($src1, $src2, $dst, $mask)
    ; CVAPI(void) cveBitwiseAnd(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseAnd", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask), "cveBitwiseAnd", @error)
EndFunc   ;==>_cveBitwiseAnd

Func _cveBitwiseAndMat($matSrc1, $matSrc2, $matDst, $matMask)
    ; cveBitwiseAnd using cv::Mat instead of _*Array

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

    _cveBitwiseAnd($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseAndMat

Func _cveBitwiseNot($src, $dst, $mask)
    ; CVAPI(void) cveBitwiseNot(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseNot", "ptr", $src, "ptr", $dst, "ptr", $mask), "cveBitwiseNot", @error)
EndFunc   ;==>_cveBitwiseNot

Func _cveBitwiseNotMat($matSrc, $matDst, $matMask)
    ; cveBitwiseNot using cv::Mat instead of _*Array

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

    _cveBitwiseNot($iArrSrc, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseNotMat

Func _cveBitwiseOr($src1, $src2, $dst, $mask)
    ; CVAPI(void) cveBitwiseOr(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseOr", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask), "cveBitwiseOr", @error)
EndFunc   ;==>_cveBitwiseOr

Func _cveBitwiseOrMat($matSrc1, $matSrc2, $matDst, $matMask)
    ; cveBitwiseOr using cv::Mat instead of _*Array

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

    _cveBitwiseOr($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseOrMat

Func _cveBitwiseXor($src1, $src2, $dst, $mask)
    ; CVAPI(void) cveBitwiseXor(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseXor", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask), "cveBitwiseXor", @error)
EndFunc   ;==>_cveBitwiseXor

Func _cveBitwiseXorMat($matSrc1, $matSrc2, $matDst, $matMask)
    ; cveBitwiseXor using cv::Mat instead of _*Array

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

    _cveBitwiseXor($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseXorMat

Func _cveAdd($src1, $src2, $dst, $mask = _cveNoArray(), $dtype = -1)
    ; CVAPI(void) cveAdd(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAdd", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask, "int", $dtype), "cveAdd", @error)
EndFunc   ;==>_cveAdd

Func _cveAddMat($matSrc1, $matSrc2, $matDst, $matMask = _cveNoArrayMat(), $dtype = -1)
    ; cveAdd using cv::Mat instead of _*Array

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

    _cveAdd($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $dtype)

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
EndFunc   ;==>_cveAddMat

Func _cveSubtract($src1, $src2, $dst, $mask = _cveNoArray(), $dtype = -1)
    ; CVAPI(void) cveSubtract(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, cv::_InputArray* mask, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubtract", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask, "int", $dtype), "cveSubtract", @error)
EndFunc   ;==>_cveSubtract

Func _cveSubtractMat($matSrc1, $matSrc2, $matDst, $matMask = _cveNoArrayMat(), $dtype = -1)
    ; cveSubtract using cv::Mat instead of _*Array

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

    _cveSubtract($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $dtype)

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
EndFunc   ;==>_cveSubtractMat

Func _cveDivide($src1, $src2, $dst, $scale = 1, $dtype = -1)
    ; CVAPI(void) cveDivide(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, double scale, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDivide", "ptr", $src1, "ptr", $src2, "ptr", $dst, "double", $scale, "int", $dtype), "cveDivide", @error)
EndFunc   ;==>_cveDivide

Func _cveDivideMat($matSrc1, $matSrc2, $matDst, $scale = 1, $dtype = -1)
    ; cveDivide using cv::Mat instead of _*Array

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

    _cveDivide($iArrSrc1, $iArrSrc2, $oArrDst, $scale, $dtype)

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
EndFunc   ;==>_cveDivideMat

Func _cveMultiply($src1, $src2, $dst, $scale = 1, $dtype = -1)
    ; CVAPI(void) cveMultiply(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, double scale, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiply", "ptr", $src1, "ptr", $src2, "ptr", $dst, "double", $scale, "int", $dtype), "cveMultiply", @error)
EndFunc   ;==>_cveMultiply

Func _cveMultiplyMat($matSrc1, $matSrc2, $matDst, $scale = 1, $dtype = -1)
    ; cveMultiply using cv::Mat instead of _*Array

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

    _cveMultiply($iArrSrc1, $iArrSrc2, $oArrDst, $scale, $dtype)

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
EndFunc   ;==>_cveMultiplyMat

Func _cveCountNonZero($src)
    ; CVAPI(void) cveCountNonZero(cv::_InputArray* src);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCountNonZero", "ptr", $src), "cveCountNonZero", @error)
EndFunc   ;==>_cveCountNonZero

Func _cveCountNonZeroMat($matSrc)
    ; cveCountNonZero using cv::Mat instead of _*Array

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

    _cveCountNonZero($iArrSrc)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveCountNonZeroMat

Func _cveFindNonZero($src, $idx)
    ; CVAPI(void) cveFindNonZero(cv::_InputArray* src, cv::_OutputArray* idx);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindNonZero", "ptr", $src, "ptr", $idx), "cveFindNonZero", @error)
EndFunc   ;==>_cveFindNonZero

Func _cveFindNonZeroMat($matSrc, $matIdx)
    ; cveFindNonZero using cv::Mat instead of _*Array

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

    Local $oArrIdx, $vectorOfMatIdx, $iArrIdxSize
    Local $bIdxIsArray = VarGetType($matIdx) == "Array"

    If $bIdxIsArray Then
        $vectorOfMatIdx = _VectorOfMatCreate()

        $iArrIdxSize = UBound($matIdx)
        For $i = 0 To $iArrIdxSize - 1
            _VectorOfMatPush($vectorOfMatIdx, $matIdx[$i])
        Next

        $oArrIdx = _cveOutputArrayFromVectorOfMat($vectorOfMatIdx)
    Else
        $oArrIdx = _cveOutputArrayFromMat($matIdx)
    EndIf

    _cveFindNonZero($iArrSrc, $oArrIdx)

    If $bIdxIsArray Then
        _VectorOfMatRelease($vectorOfMatIdx)
    EndIf

    _cveOutputArrayRelease($oArrIdx)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveFindNonZeroMat

Func _cveMin($src1, $src2, $dst)
    ; CVAPI(void) cveMin(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMin", "ptr", $src1, "ptr", $src2, "ptr", $dst), "cveMin", @error)
EndFunc   ;==>_cveMin

Func _cveMinMat($matSrc1, $matSrc2, $matDst)
    ; cveMin using cv::Mat instead of _*Array

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

    _cveMin($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveMinMat

Func _cveMax($src1, $src2, $dst)
    ; CVAPI(void) cveMax(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMax", "ptr", $src1, "ptr", $src2, "ptr", $dst), "cveMax", @error)
EndFunc   ;==>_cveMax

Func _cveMaxMat($matSrc1, $matSrc2, $matDst)
    ; cveMax using cv::Mat instead of _*Array

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

    _cveMax($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveMaxMat

Func _cveAbsDiff($src1, $src2, $dst)
    ; CVAPI(void) cveAbsDiff(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAbsDiff", "ptr", $src1, "ptr", $src2, "ptr", $dst), "cveAbsDiff", @error)
EndFunc   ;==>_cveAbsDiff

Func _cveAbsDiffMat($matSrc1, $matSrc2, $matDst)
    ; cveAbsDiff using cv::Mat instead of _*Array

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

    _cveAbsDiff($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveAbsDiffMat

Func _cveInRange($src1, $lowerb, $upperb, $dst)
    ; CVAPI(void) cveInRange(cv::_InputArray* src1, cv::_InputArray* lowerb, cv::_InputArray* upperb, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInRange", "ptr", $src1, "ptr", $lowerb, "ptr", $upperb, "ptr", $dst), "cveInRange", @error)
EndFunc   ;==>_cveInRange

Func _cveInRangeMat($matSrc1, $matLowerb, $matUpperb, $matDst)
    ; cveInRange using cv::Mat instead of _*Array

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

    Local $iArrLowerb, $vectorOfMatLowerb, $iArrLowerbSize
    Local $bLowerbIsArray = VarGetType($matLowerb) == "Array"

    If $bLowerbIsArray Then
        $vectorOfMatLowerb = _VectorOfMatCreate()

        $iArrLowerbSize = UBound($matLowerb)
        For $i = 0 To $iArrLowerbSize - 1
            _VectorOfMatPush($vectorOfMatLowerb, $matLowerb[$i])
        Next

        $iArrLowerb = _cveInputArrayFromVectorOfMat($vectorOfMatLowerb)
    Else
        $iArrLowerb = _cveInputArrayFromMat($matLowerb)
    EndIf

    Local $iArrUpperb, $vectorOfMatUpperb, $iArrUpperbSize
    Local $bUpperbIsArray = VarGetType($matUpperb) == "Array"

    If $bUpperbIsArray Then
        $vectorOfMatUpperb = _VectorOfMatCreate()

        $iArrUpperbSize = UBound($matUpperb)
        For $i = 0 To $iArrUpperbSize - 1
            _VectorOfMatPush($vectorOfMatUpperb, $matUpperb[$i])
        Next

        $iArrUpperb = _cveInputArrayFromVectorOfMat($vectorOfMatUpperb)
    Else
        $iArrUpperb = _cveInputArrayFromMat($matUpperb)
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

    _cveInRange($iArrSrc1, $iArrLowerb, $iArrUpperb, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bUpperbIsArray Then
        _VectorOfMatRelease($vectorOfMatUpperb)
    EndIf

    _cveInputArrayRelease($iArrUpperb)

    If $bLowerbIsArray Then
        _VectorOfMatRelease($vectorOfMatLowerb)
    EndIf

    _cveInputArrayRelease($iArrLowerb)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cveInRangeMat

Func _cveSqrt($src, $dst)
    ; CVAPI(void) cveSqrt(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSqrt", "ptr", $src, "ptr", $dst), "cveSqrt", @error)
EndFunc   ;==>_cveSqrt

Func _cveSqrtMat($matSrc, $matDst)
    ; cveSqrt using cv::Mat instead of _*Array

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

    _cveSqrt($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSqrtMat

Func _cveCompare($src1, $src2, $dst, $compop)
    ; CVAPI(void) cveCompare(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int compop);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompare", "ptr", $src1, "ptr", $src2, "ptr", $dst, "int", $compop), "cveCompare", @error)
EndFunc   ;==>_cveCompare

Func _cveCompareMat($matSrc1, $matSrc2, $matDst, $compop)
    ; cveCompare using cv::Mat instead of _*Array

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

    _cveCompare($iArrSrc1, $iArrSrc2, $oArrDst, $compop)

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
EndFunc   ;==>_cveCompareMat

Func _cveFlip($src, $dst, $flipCode)
    ; CVAPI(void) cveFlip(cv::_InputArray* src, cv::_OutputArray* dst, int flipCode);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlip", "ptr", $src, "ptr", $dst, "int", $flipCode), "cveFlip", @error)
EndFunc   ;==>_cveFlip

Func _cveFlipMat($matSrc, $matDst, $flipCode)
    ; cveFlip using cv::Mat instead of _*Array

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

    _cveFlip($iArrSrc, $oArrDst, $flipCode)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveFlipMat

Func _cveRotate($src, $dst, $rotateCode)
    ; CVAPI(void) cveRotate(cv::_InputArray* src, cv::_OutputArray* dst, int rotateCode);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRotate", "ptr", $src, "ptr", $dst, "int", $rotateCode), "cveRotate", @error)
EndFunc   ;==>_cveRotate

Func _cveRotateMat($matSrc, $matDst, $rotateCode)
    ; cveRotate using cv::Mat instead of _*Array

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

    _cveRotate($iArrSrc, $oArrDst, $rotateCode)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRotateMat

Func _cveTranspose($src, $dst)
    ; CVAPI(void) cveTranspose(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTranspose", "ptr", $src, "ptr", $dst), "cveTranspose", @error)
EndFunc   ;==>_cveTranspose

Func _cveTransposeMat($matSrc, $matDst)
    ; cveTranspose using cv::Mat instead of _*Array

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

    _cveTranspose($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveTransposeMat

Func _cveLUT($src, $lut, $dst)
    ; CVAPI(void) cveLUT(cv::_InputArray* src, cv::_InputArray* lut, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLUT", "ptr", $src, "ptr", $lut, "ptr", $dst), "cveLUT", @error)
EndFunc   ;==>_cveLUT

Func _cveLUTMat($matSrc, $matLut, $matDst)
    ; cveLUT using cv::Mat instead of _*Array

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

    _cveLUT($iArrSrc, $iArrLut, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bLutIsArray Then
        _VectorOfMatRelease($vectorOfMatLut)
    EndIf

    _cveInputArrayRelease($iArrLut)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveLUTMat

Func _cveSum($src, $result)
    ; CVAPI(void) cveSum(cv::_InputArray* src, CvScalar* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSum", "ptr", $src, "struct*", $result), "cveSum", @error)
EndFunc   ;==>_cveSum

Func _cveSumMat($matSrc, $result)
    ; cveSum using cv::Mat instead of _*Array

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

    _cveSum($iArrSrc, $result)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSumMat

Func _cveMean($src, $mask, $result)
    ; CVAPI(void) cveMean(cv::_InputArray* src, cv::_InputArray* mask, CvScalar* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMean", "ptr", $src, "ptr", $mask, "struct*", $result), "cveMean", @error)
EndFunc   ;==>_cveMean

Func _cveMeanMat($matSrc, $matMask, $result)
    ; cveMean using cv::Mat instead of _*Array

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

    _cveMean($iArrSrc, $iArrMask, $result)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMeanMat

Func _cveMeanStdDev($src, $mean, $stddev, $mask = _cveNoArray())
    ; CVAPI(void) cveMeanStdDev(cv::_InputArray* src, cv::_OutputArray* mean, cv::_OutputArray* stddev, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMeanStdDev", "ptr", $src, "ptr", $mean, "ptr", $stddev, "ptr", $mask), "cveMeanStdDev", @error)
EndFunc   ;==>_cveMeanStdDev

Func _cveMeanStdDevMat($matSrc, $matMean, $matStddev, $matMask = _cveNoArrayMat())
    ; cveMeanStdDev using cv::Mat instead of _*Array

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

    Local $oArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $oArrMean = _cveOutputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $oArrMean = _cveOutputArrayFromMat($matMean)
    EndIf

    Local $oArrStddev, $vectorOfMatStddev, $iArrStddevSize
    Local $bStddevIsArray = VarGetType($matStddev) == "Array"

    If $bStddevIsArray Then
        $vectorOfMatStddev = _VectorOfMatCreate()

        $iArrStddevSize = UBound($matStddev)
        For $i = 0 To $iArrStddevSize - 1
            _VectorOfMatPush($vectorOfMatStddev, $matStddev[$i])
        Next

        $oArrStddev = _cveOutputArrayFromVectorOfMat($vectorOfMatStddev)
    Else
        $oArrStddev = _cveOutputArrayFromMat($matStddev)
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

    _cveMeanStdDev($iArrSrc, $oArrMean, $oArrStddev, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bStddevIsArray Then
        _VectorOfMatRelease($vectorOfMatStddev)
    EndIf

    _cveOutputArrayRelease($oArrStddev)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveOutputArrayRelease($oArrMean)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMeanStdDevMat

Func _cveTrace($mtx, $result)
    ; CVAPI(void) cveTrace(cv::_InputArray* mtx, CvScalar* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrace", "ptr", $mtx, "struct*", $result), "cveTrace", @error)
EndFunc   ;==>_cveTrace

Func _cveTraceMat($matMtx, $result)
    ; cveTrace using cv::Mat instead of _*Array

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

    _cveTrace($iArrMtx, $result)

    If $bMtxIsArray Then
        _VectorOfMatRelease($vectorOfMatMtx)
    EndIf

    _cveInputArrayRelease($iArrMtx)
EndFunc   ;==>_cveTraceMat

Func _cveDeterminant($mtx)
    ; CVAPI(double) cveDeterminant(cv::_InputArray* mtx);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDeterminant", "ptr", $mtx), "cveDeterminant", @error)
EndFunc   ;==>_cveDeterminant

Func _cveDeterminantMat($matMtx)
    ; cveDeterminant using cv::Mat instead of _*Array

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

    Local $retval = _cveDeterminant($iArrMtx)

    If $bMtxIsArray Then
        _VectorOfMatRelease($vectorOfMatMtx)
    EndIf

    _cveInputArrayRelease($iArrMtx)

    Return $retval
EndFunc   ;==>_cveDeterminantMat

Func _cveNorm($src1, $src2, $normType = $CV_NORM_L2, $mask = _cveNoArray())
    ; CVAPI(double) cveNorm(cv::_InputArray* src1, cv::_InputArray* src2, int normType, cv::_InputArray* mask);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveNorm", "ptr", $src1, "ptr", $src2, "int", $normType, "ptr", $mask), "cveNorm", @error)
EndFunc   ;==>_cveNorm

Func _cveNormMat($matSrc1, $matSrc2, $normType = $CV_NORM_L2, $matMask = _cveNoArrayMat())
    ; cveNorm using cv::Mat instead of _*Array

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

    Local $retval = _cveNorm($iArrSrc1, $iArrSrc2, $normType, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)

    Return $retval
EndFunc   ;==>_cveNormMat

Func _cveCheckRange($arr, $quiet, $index, $minVal = -$CV_DBL_MAX, $maxVal = $CV_DBL_MAX)
    ; CVAPI(bool) cveCheckRange(cv::_InputArray* arr, bool quiet, CvPoint* index, double minVal, double maxVal);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCheckRange", "ptr", $arr, "boolean", $quiet, "struct*", $index, "double", $minVal, "double", $maxVal), "cveCheckRange", @error)
EndFunc   ;==>_cveCheckRange

Func _cveCheckRangeMat($matArr, $quiet, $index, $minVal = -$CV_DBL_MAX, $maxVal = $CV_DBL_MAX)
    ; cveCheckRange using cv::Mat instead of _*Array

    Local $iArrArr, $vectorOfMatArr, $iArrArrSize
    Local $bArrIsArray = VarGetType($matArr) == "Array"

    If $bArrIsArray Then
        $vectorOfMatArr = _VectorOfMatCreate()

        $iArrArrSize = UBound($matArr)
        For $i = 0 To $iArrArrSize - 1
            _VectorOfMatPush($vectorOfMatArr, $matArr[$i])
        Next

        $iArrArr = _cveInputArrayFromVectorOfMat($vectorOfMatArr)
    Else
        $iArrArr = _cveInputArrayFromMat($matArr)
    EndIf

    Local $retval = _cveCheckRange($iArrArr, $quiet, $index, $minVal, $maxVal)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveInputArrayRelease($iArrArr)

    Return $retval
EndFunc   ;==>_cveCheckRangeMat

Func _cvePatchNaNs($a, $val = 0)
    ; CVAPI(void) cvePatchNaNs(cv::_InputOutputArray* a, double val);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePatchNaNs", "ptr", $a, "double", $val), "cvePatchNaNs", @error)
EndFunc   ;==>_cvePatchNaNs

Func _cvePatchNaNsMat($matA, $val = 0)
    ; cvePatchNaNs using cv::Mat instead of _*Array

    Local $ioArrA, $vectorOfMatA, $iArrASize
    Local $bAIsArray = VarGetType($matA) == "Array"

    If $bAIsArray Then
        $vectorOfMatA = _VectorOfMatCreate()

        $iArrASize = UBound($matA)
        For $i = 0 To $iArrASize - 1
            _VectorOfMatPush($vectorOfMatA, $matA[$i])
        Next

        $ioArrA = _cveInputOutputArrayFromVectorOfMat($vectorOfMatA)
    Else
        $ioArrA = _cveInputOutputArrayFromMat($matA)
    EndIf

    _cvePatchNaNs($ioArrA, $val)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputOutputArrayRelease($ioArrA)
EndFunc   ;==>_cvePatchNaNsMat

Func _cveGemm($src1, $src2, $alpha, $src3, $beta, $dst, $flags = 0)
    ; CVAPI(void) cveGemm(cv::_InputArray* src1, cv::_InputArray* src2, double alpha, cv::_InputArray* src3, double beta, cv::_OutputArray* dst, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGemm", "ptr", $src1, "ptr", $src2, "double", $alpha, "ptr", $src3, "double", $beta, "ptr", $dst, "int", $flags), "cveGemm", @error)
EndFunc   ;==>_cveGemm

Func _cveGemmMat($matSrc1, $matSrc2, $alpha, $matSrc3, $beta, $matDst, $flags = 0)
    ; cveGemm using cv::Mat instead of _*Array

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

    _cveGemm($iArrSrc1, $iArrSrc2, $alpha, $iArrSrc3, $beta, $oArrDst, $flags)

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
EndFunc   ;==>_cveGemmMat

Func _cveScaleAdd($src1, $alpha, $src2, $dst)
    ; CVAPI(void) cveScaleAdd(cv::_InputArray* src1, double alpha, cv::_InputArray* src2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScaleAdd", "ptr", $src1, "double", $alpha, "ptr", $src2, "ptr", $dst), "cveScaleAdd", @error)
EndFunc   ;==>_cveScaleAdd

Func _cveScaleAddMat($matSrc1, $alpha, $matSrc2, $matDst)
    ; cveScaleAdd using cv::Mat instead of _*Array

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

    _cveScaleAdd($iArrSrc1, $alpha, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveScaleAddMat

Func _cveAddWeighted($src1, $alpha, $src2, $beta, $gamma, $dst, $dtype = -1)
    ; CVAPI(void) cveAddWeighted(cv::_InputArray* src1, double alpha, cv::_InputArray* src2, double beta, double gamma, cv::_OutputArray* dst, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAddWeighted", "ptr", $src1, "double", $alpha, "ptr", $src2, "double", $beta, "double", $gamma, "ptr", $dst, "int", $dtype), "cveAddWeighted", @error)
EndFunc   ;==>_cveAddWeighted

Func _cveAddWeightedMat($matSrc1, $alpha, $matSrc2, $beta, $gamma, $matDst, $dtype = -1)
    ; cveAddWeighted using cv::Mat instead of _*Array

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

    _cveAddWeighted($iArrSrc1, $alpha, $iArrSrc2, $beta, $gamma, $oArrDst, $dtype)

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
EndFunc   ;==>_cveAddWeightedMat

Func _cveConvertScaleAbs($src, $dst, $alpha = 1, $beta = 0)
    ; CVAPI(void) cveConvertScaleAbs(cv::_InputArray* src, cv::_OutputArray* dst, double alpha, double beta);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertScaleAbs", "ptr", $src, "ptr", $dst, "double", $alpha, "double", $beta), "cveConvertScaleAbs", @error)
EndFunc   ;==>_cveConvertScaleAbs

Func _cveConvertScaleAbsMat($matSrc, $matDst, $alpha = 1, $beta = 0)
    ; cveConvertScaleAbs using cv::Mat instead of _*Array

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

    _cveConvertScaleAbs($iArrSrc, $oArrDst, $alpha, $beta)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveConvertScaleAbsMat

Func _cveReduce($src, $dst, $dim, $rtype, $dtype = -1)
    ; CVAPI(void) cveReduce(cv::_InputArray* src, cv::_OutputArray* dst, int dim, int rtype, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReduce", "ptr", $src, "ptr", $dst, "int", $dim, "int", $rtype, "int", $dtype), "cveReduce", @error)
EndFunc   ;==>_cveReduce

Func _cveReduceMat($matSrc, $matDst, $dim, $rtype, $dtype = -1)
    ; cveReduce using cv::Mat instead of _*Array

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

    _cveReduce($iArrSrc, $oArrDst, $dim, $rtype, $dtype)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveReduceMat

Func _cveRandShuffle($dst, $iterFactor = 1.0, $rng = 0)
    ; CVAPI(void) cveRandShuffle(cv::_InputOutputArray* dst, double iterFactor, uint64 rng);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRandShuffle", "ptr", $dst, "double", $iterFactor, "uint64", $rng), "cveRandShuffle", @error)
EndFunc   ;==>_cveRandShuffle

Func _cveRandShuffleMat($matDst, $iterFactor = 1.0, $rng = 0)
    ; cveRandShuffle using cv::Mat instead of _*Array

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
    EndIf

    _cveRandShuffle($ioArrDst, $iterFactor, $rng)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)
EndFunc   ;==>_cveRandShuffleMat

Func _cvePow($src, $power, $dst)
    ; CVAPI(void) cvePow(cv::_InputArray* src, double power, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePow", "ptr", $src, "double", $power, "ptr", $dst), "cvePow", @error)
EndFunc   ;==>_cvePow

Func _cvePowMat($matSrc, $power, $matDst)
    ; cvePow using cv::Mat instead of _*Array

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

    _cvePow($iArrSrc, $power, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cvePowMat

Func _cveExp($src, $dst)
    ; CVAPI(void) cveExp(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExp", "ptr", $src, "ptr", $dst), "cveExp", @error)
EndFunc   ;==>_cveExp

Func _cveExpMat($matSrc, $matDst)
    ; cveExp using cv::Mat instead of _*Array

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

    _cveExp($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveExpMat

Func _cveLog($src, $dst)
    ; CVAPI(void) cveLog(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLog", "ptr", $src, "ptr", $dst), "cveLog", @error)
EndFunc   ;==>_cveLog

Func _cveLogMat($matSrc, $matDst)
    ; cveLog using cv::Mat instead of _*Array

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

    _cveLog($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveLogMat

Func _cveCartToPolar($x, $y, $magnitude, $angle, $angleInDegrees = false)
    ; CVAPI(void) cveCartToPolar(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::_OutputArray* angle, bool angleInDegrees);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCartToPolar", "ptr", $x, "ptr", $y, "ptr", $magnitude, "ptr", $angle, "boolean", $angleInDegrees), "cveCartToPolar", @error)
EndFunc   ;==>_cveCartToPolar

Func _cveCartToPolarMat($matX, $matY, $matMagnitude, $matAngle, $angleInDegrees = false)
    ; cveCartToPolar using cv::Mat instead of _*Array

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

    _cveCartToPolar($iArrX, $iArrY, $oArrMagnitude, $oArrAngle, $angleInDegrees)

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
EndFunc   ;==>_cveCartToPolarMat

Func _cvePolarToCart($magnitude, $angle, $x, $y, $angleInDegrees = false)
    ; CVAPI(void) cvePolarToCart(cv::_InputArray* magnitude, cv::_InputArray* angle, cv::_OutputArray* x, cv::_OutputArray* y, bool angleInDegrees);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePolarToCart", "ptr", $magnitude, "ptr", $angle, "ptr", $x, "ptr", $y, "boolean", $angleInDegrees), "cvePolarToCart", @error)
EndFunc   ;==>_cvePolarToCart

Func _cvePolarToCartMat($matMagnitude, $matAngle, $matX, $matY, $angleInDegrees = false)
    ; cvePolarToCart using cv::Mat instead of _*Array

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

    _cvePolarToCart($iArrMagnitude, $iArrAngle, $oArrX, $oArrY, $angleInDegrees)

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
EndFunc   ;==>_cvePolarToCartMat

Func _cveSetIdentity($mtx, $scalar)
    ; CVAPI(void) cveSetIdentity(cv::_InputOutputArray* mtx, CvScalar* scalar);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetIdentity", "ptr", $mtx, "struct*", $scalar), "cveSetIdentity", @error)
EndFunc   ;==>_cveSetIdentity

Func _cveSetIdentityMat($matMtx, $scalar)
    ; cveSetIdentity using cv::Mat instead of _*Array

    Local $ioArrMtx, $vectorOfMatMtx, $iArrMtxSize
    Local $bMtxIsArray = VarGetType($matMtx) == "Array"

    If $bMtxIsArray Then
        $vectorOfMatMtx = _VectorOfMatCreate()

        $iArrMtxSize = UBound($matMtx)
        For $i = 0 To $iArrMtxSize - 1
            _VectorOfMatPush($vectorOfMatMtx, $matMtx[$i])
        Next

        $ioArrMtx = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMtx)
    Else
        $ioArrMtx = _cveInputOutputArrayFromMat($matMtx)
    EndIf

    _cveSetIdentity($ioArrMtx, $scalar)

    If $bMtxIsArray Then
        _VectorOfMatRelease($vectorOfMatMtx)
    EndIf

    _cveInputOutputArrayRelease($ioArrMtx)
EndFunc   ;==>_cveSetIdentityMat

Func _cveSolveCubic($coeffs, $roots)
    ; CVAPI(int) cveSolveCubic(cv::_InputArray* coeffs, cv::_OutputArray* roots);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveCubic", "ptr", $coeffs, "ptr", $roots), "cveSolveCubic", @error)
EndFunc   ;==>_cveSolveCubic

Func _cveSolveCubicMat($matCoeffs, $matRoots)
    ; cveSolveCubic using cv::Mat instead of _*Array

    Local $iArrCoeffs, $vectorOfMatCoeffs, $iArrCoeffsSize
    Local $bCoeffsIsArray = VarGetType($matCoeffs) == "Array"

    If $bCoeffsIsArray Then
        $vectorOfMatCoeffs = _VectorOfMatCreate()

        $iArrCoeffsSize = UBound($matCoeffs)
        For $i = 0 To $iArrCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatCoeffs, $matCoeffs[$i])
        Next

        $iArrCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatCoeffs)
    Else
        $iArrCoeffs = _cveInputArrayFromMat($matCoeffs)
    EndIf

    Local $oArrRoots, $vectorOfMatRoots, $iArrRootsSize
    Local $bRootsIsArray = VarGetType($matRoots) == "Array"

    If $bRootsIsArray Then
        $vectorOfMatRoots = _VectorOfMatCreate()

        $iArrRootsSize = UBound($matRoots)
        For $i = 0 To $iArrRootsSize - 1
            _VectorOfMatPush($vectorOfMatRoots, $matRoots[$i])
        Next

        $oArrRoots = _cveOutputArrayFromVectorOfMat($vectorOfMatRoots)
    Else
        $oArrRoots = _cveOutputArrayFromMat($matRoots)
    EndIf

    Local $retval = _cveSolveCubic($iArrCoeffs, $oArrRoots)

    If $bRootsIsArray Then
        _VectorOfMatRelease($vectorOfMatRoots)
    EndIf

    _cveOutputArrayRelease($oArrRoots)

    If $bCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatCoeffs)
    EndIf

    _cveInputArrayRelease($iArrCoeffs)

    Return $retval
EndFunc   ;==>_cveSolveCubicMat

Func _cveSolvePoly($coeffs, $roots, $maxIters = 300)
    ; CVAPI(double) cveSolvePoly(cv::_InputArray* coeffs, cv::_OutputArray* roots, int maxIters);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSolvePoly", "ptr", $coeffs, "ptr", $roots, "int", $maxIters), "cveSolvePoly", @error)
EndFunc   ;==>_cveSolvePoly

Func _cveSolvePolyMat($matCoeffs, $matRoots, $maxIters = 300)
    ; cveSolvePoly using cv::Mat instead of _*Array

    Local $iArrCoeffs, $vectorOfMatCoeffs, $iArrCoeffsSize
    Local $bCoeffsIsArray = VarGetType($matCoeffs) == "Array"

    If $bCoeffsIsArray Then
        $vectorOfMatCoeffs = _VectorOfMatCreate()

        $iArrCoeffsSize = UBound($matCoeffs)
        For $i = 0 To $iArrCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatCoeffs, $matCoeffs[$i])
        Next

        $iArrCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatCoeffs)
    Else
        $iArrCoeffs = _cveInputArrayFromMat($matCoeffs)
    EndIf

    Local $oArrRoots, $vectorOfMatRoots, $iArrRootsSize
    Local $bRootsIsArray = VarGetType($matRoots) == "Array"

    If $bRootsIsArray Then
        $vectorOfMatRoots = _VectorOfMatCreate()

        $iArrRootsSize = UBound($matRoots)
        For $i = 0 To $iArrRootsSize - 1
            _VectorOfMatPush($vectorOfMatRoots, $matRoots[$i])
        Next

        $oArrRoots = _cveOutputArrayFromVectorOfMat($vectorOfMatRoots)
    Else
        $oArrRoots = _cveOutputArrayFromMat($matRoots)
    EndIf

    Local $retval = _cveSolvePoly($iArrCoeffs, $oArrRoots, $maxIters)

    If $bRootsIsArray Then
        _VectorOfMatRelease($vectorOfMatRoots)
    EndIf

    _cveOutputArrayRelease($oArrRoots)

    If $bCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatCoeffs)
    EndIf

    _cveInputArrayRelease($iArrCoeffs)

    Return $retval
EndFunc   ;==>_cveSolvePolyMat

Func _cveSolve($src1, $src2, $dst, $flags = $CV_DECOMP_LU)
    ; CVAPI(void) cveSolve(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSolve", "ptr", $src1, "ptr", $src2, "ptr", $dst, "int", $flags), "cveSolve", @error)
EndFunc   ;==>_cveSolve

Func _cveSolveMat($matSrc1, $matSrc2, $matDst, $flags = $CV_DECOMP_LU)
    ; cveSolve using cv::Mat instead of _*Array

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

    _cveSolve($iArrSrc1, $iArrSrc2, $oArrDst, $flags)

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
EndFunc   ;==>_cveSolveMat

Func _cveSort($src, $dst, $flags)
    ; CVAPI(void) cveSort(cv::_InputArray* src, cv::_OutputArray* dst, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSort", "ptr", $src, "ptr", $dst, "int", $flags), "cveSort", @error)
EndFunc   ;==>_cveSort

Func _cveSortMat($matSrc, $matDst, $flags)
    ; cveSort using cv::Mat instead of _*Array

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

    _cveSort($iArrSrc, $oArrDst, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSortMat

Func _cveSortIdx($src, $dst, $flags)
    ; CVAPI(void) cveSortIdx(cv::_InputArray* src, cv::_OutputArray* dst, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSortIdx", "ptr", $src, "ptr", $dst, "int", $flags), "cveSortIdx", @error)
EndFunc   ;==>_cveSortIdx

Func _cveSortIdxMat($matSrc, $matDst, $flags)
    ; cveSortIdx using cv::Mat instead of _*Array

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

    _cveSortIdx($iArrSrc, $oArrDst, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSortIdxMat

Func _cveInvert($src, $dst, $flags = $CV_DECOMP_LU)
    ; CVAPI(void) cveInvert(cv::_InputArray* src, cv::_OutputArray* dst, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInvert", "ptr", $src, "ptr", $dst, "int", $flags), "cveInvert", @error)
EndFunc   ;==>_cveInvert

Func _cveInvertMat($matSrc, $matDst, $flags = $CV_DECOMP_LU)
    ; cveInvert using cv::Mat instead of _*Array

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

    _cveInvert($iArrSrc, $oArrDst, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveInvertMat

Func _cveDft($src, $dst, $flags = 0, $nonzeroRows = 0)
    ; CVAPI(void) cveDft(cv::_InputArray* src, cv::_OutputArray* dst, int flags, int nonzeroRows);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDft", "ptr", $src, "ptr", $dst, "int", $flags, "int", $nonzeroRows), "cveDft", @error)
EndFunc   ;==>_cveDft

Func _cveDftMat($matSrc, $matDst, $flags = 0, $nonzeroRows = 0)
    ; cveDft using cv::Mat instead of _*Array

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

    _cveDft($iArrSrc, $oArrDst, $flags, $nonzeroRows)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveDftMat

Func _cveDct($src, $dst, $flags = 0)
    ; CVAPI(void) cveDct(cv::_InputArray* src, cv::_OutputArray* dst, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDct", "ptr", $src, "ptr", $dst, "int", $flags), "cveDct", @error)
EndFunc   ;==>_cveDct

Func _cveDctMat($matSrc, $matDst, $flags = 0)
    ; cveDct using cv::Mat instead of _*Array

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

    _cveDct($iArrSrc, $oArrDst, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveDctMat

Func _cveMulSpectrums($a, $b, $c, $flags, $conjB = false)
    ; CVAPI(void) cveMulSpectrums(cv::_InputArray * a, cv::_InputArray* b, cv::_OutputArray* c, int flags, bool conjB);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMulSpectrums", "ptr", $a, "ptr", $b, "ptr", $c, "int", $flags, "boolean", $conjB), "cveMulSpectrums", @error)
EndFunc   ;==>_cveMulSpectrums

Func _cveMulSpectrumsMat($a, $matB, $matC, $flags, $conjB = false)
    ; cveMulSpectrums using cv::Mat instead of _*Array

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

    _cveMulSpectrums($a, $iArrB, $oArrC, $flags, $conjB)

    If $bCIsArray Then
        _VectorOfMatRelease($vectorOfMatC)
    EndIf

    _cveOutputArrayRelease($oArrC)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)
EndFunc   ;==>_cveMulSpectrumsMat

Func _cveGetOptimalDFTSize($vecsize)
    ; CVAPI(int) cveGetOptimalDFTSize(int vecsize);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetOptimalDFTSize", "int", $vecsize), "cveGetOptimalDFTSize", @error)
EndFunc   ;==>_cveGetOptimalDFTSize

Func _cveTransform($src, $dst, $m)
    ; CVAPI(void) cveTransform(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTransform", "ptr", $src, "ptr", $dst, "ptr", $m), "cveTransform", @error)
EndFunc   ;==>_cveTransform

Func _cveTransformMat($matSrc, $matDst, $matM)
    ; cveTransform using cv::Mat instead of _*Array

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

    Local $iArrM, $vectorOfMatM, $iArrMSize
    Local $bMIsArray = VarGetType($matM) == "Array"

    If $bMIsArray Then
        $vectorOfMatM = _VectorOfMatCreate()

        $iArrMSize = UBound($matM)
        For $i = 0 To $iArrMSize - 1
            _VectorOfMatPush($vectorOfMatM, $matM[$i])
        Next

        $iArrM = _cveInputArrayFromVectorOfMat($vectorOfMatM)
    Else
        $iArrM = _cveInputArrayFromMat($matM)
    EndIf

    _cveTransform($iArrSrc, $oArrDst, $iArrM)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveTransformMat

Func _cveMahalanobis($v1, $v2, $icovar)
    ; CVAPI(void) cveMahalanobis(cv::_InputArray* v1, cv::_InputArray* v2, cv::_InputArray* icovar);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMahalanobis", "ptr", $v1, "ptr", $v2, "ptr", $icovar), "cveMahalanobis", @error)
EndFunc   ;==>_cveMahalanobis

Func _cveMahalanobisMat($matV1, $matV2, $matIcovar)
    ; cveMahalanobis using cv::Mat instead of _*Array

    Local $iArrV1, $vectorOfMatV1, $iArrV1Size
    Local $bV1IsArray = VarGetType($matV1) == "Array"

    If $bV1IsArray Then
        $vectorOfMatV1 = _VectorOfMatCreate()

        $iArrV1Size = UBound($matV1)
        For $i = 0 To $iArrV1Size - 1
            _VectorOfMatPush($vectorOfMatV1, $matV1[$i])
        Next

        $iArrV1 = _cveInputArrayFromVectorOfMat($vectorOfMatV1)
    Else
        $iArrV1 = _cveInputArrayFromMat($matV1)
    EndIf

    Local $iArrV2, $vectorOfMatV2, $iArrV2Size
    Local $bV2IsArray = VarGetType($matV2) == "Array"

    If $bV2IsArray Then
        $vectorOfMatV2 = _VectorOfMatCreate()

        $iArrV2Size = UBound($matV2)
        For $i = 0 To $iArrV2Size - 1
            _VectorOfMatPush($vectorOfMatV2, $matV2[$i])
        Next

        $iArrV2 = _cveInputArrayFromVectorOfMat($vectorOfMatV2)
    Else
        $iArrV2 = _cveInputArrayFromMat($matV2)
    EndIf

    Local $iArrIcovar, $vectorOfMatIcovar, $iArrIcovarSize
    Local $bIcovarIsArray = VarGetType($matIcovar) == "Array"

    If $bIcovarIsArray Then
        $vectorOfMatIcovar = _VectorOfMatCreate()

        $iArrIcovarSize = UBound($matIcovar)
        For $i = 0 To $iArrIcovarSize - 1
            _VectorOfMatPush($vectorOfMatIcovar, $matIcovar[$i])
        Next

        $iArrIcovar = _cveInputArrayFromVectorOfMat($vectorOfMatIcovar)
    Else
        $iArrIcovar = _cveInputArrayFromMat($matIcovar)
    EndIf

    _cveMahalanobis($iArrV1, $iArrV2, $iArrIcovar)

    If $bIcovarIsArray Then
        _VectorOfMatRelease($vectorOfMatIcovar)
    EndIf

    _cveInputArrayRelease($iArrIcovar)

    If $bV2IsArray Then
        _VectorOfMatRelease($vectorOfMatV2)
    EndIf

    _cveInputArrayRelease($iArrV2)

    If $bV1IsArray Then
        _VectorOfMatRelease($vectorOfMatV1)
    EndIf

    _cveInputArrayRelease($iArrV1)
EndFunc   ;==>_cveMahalanobisMat

Func _cveCalcCovarMatrix($samples, $covar, $mean, $flags, $ctype = $CV_64F)
    ; CVAPI(void) cveCalcCovarMatrix(cv::_InputArray* samples, cv::_OutputArray* covar, cv::_InputOutputArray* mean, int flags, int ctype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcCovarMatrix", "ptr", $samples, "ptr", $covar, "ptr", $mean, "int", $flags, "int", $ctype), "cveCalcCovarMatrix", @error)
EndFunc   ;==>_cveCalcCovarMatrix

Func _cveCalcCovarMatrixMat($matSamples, $matCovar, $matMean, $flags, $ctype = $CV_64F)
    ; cveCalcCovarMatrix using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $oArrCovar, $vectorOfMatCovar, $iArrCovarSize
    Local $bCovarIsArray = VarGetType($matCovar) == "Array"

    If $bCovarIsArray Then
        $vectorOfMatCovar = _VectorOfMatCreate()

        $iArrCovarSize = UBound($matCovar)
        For $i = 0 To $iArrCovarSize - 1
            _VectorOfMatPush($vectorOfMatCovar, $matCovar[$i])
        Next

        $oArrCovar = _cveOutputArrayFromVectorOfMat($vectorOfMatCovar)
    Else
        $oArrCovar = _cveOutputArrayFromMat($matCovar)
    EndIf

    Local $ioArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $ioArrMean = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $ioArrMean = _cveInputOutputArrayFromMat($matMean)
    EndIf

    _cveCalcCovarMatrix($iArrSamples, $oArrCovar, $ioArrMean, $flags, $ctype)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveInputOutputArrayRelease($ioArrMean)

    If $bCovarIsArray Then
        _VectorOfMatRelease($vectorOfMatCovar)
    EndIf

    _cveOutputArrayRelease($oArrCovar)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)
EndFunc   ;==>_cveCalcCovarMatrixMat

Func _cveNormalize($src, $dst, $alpha, $beta, $normType, $dType, $mask = _cveNoArray())
    ; CVAPI(void) cveNormalize(cv::_InputArray* src, cv::_InputOutputArray* dst, double alpha, double beta, int normType, int dType, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNormalize", "ptr", $src, "ptr", $dst, "double", $alpha, "double", $beta, "int", $normType, "int", $dType, "ptr", $mask), "cveNormalize", @error)
EndFunc   ;==>_cveNormalize

Func _cveNormalizeMat($matSrc, $matDst, $alpha, $beta, $normType, $dType, $matMask = _cveNoArrayMat())
    ; cveNormalize using cv::Mat instead of _*Array

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

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
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

    _cveNormalize($iArrSrc, $ioArrDst, $alpha, $beta, $normType, $dType, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveNormalizeMat

Func _cvePerspectiveTransform($src, $dst, $m)
    ; CVAPI(void) cvePerspectiveTransform(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePerspectiveTransform", "ptr", $src, "ptr", $dst, "ptr", $m), "cvePerspectiveTransform", @error)
EndFunc   ;==>_cvePerspectiveTransform

Func _cvePerspectiveTransformMat($matSrc, $matDst, $matM)
    ; cvePerspectiveTransform using cv::Mat instead of _*Array

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

    Local $iArrM, $vectorOfMatM, $iArrMSize
    Local $bMIsArray = VarGetType($matM) == "Array"

    If $bMIsArray Then
        $vectorOfMatM = _VectorOfMatCreate()

        $iArrMSize = UBound($matM)
        For $i = 0 To $iArrMSize - 1
            _VectorOfMatPush($vectorOfMatM, $matM[$i])
        Next

        $iArrM = _cveInputArrayFromVectorOfMat($vectorOfMatM)
    Else
        $iArrM = _cveInputArrayFromMat($matM)
    EndIf

    _cvePerspectiveTransform($iArrSrc, $oArrDst, $iArrM)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cvePerspectiveTransformMat

Func _cveMulTransposed($src, $dst, $aTa, $delta = _cveNoArray(), $scale = 1, $dtype = -1)
    ; CVAPI(void) cveMulTransposed(cv::_InputArray* src, cv::_OutputArray* dst, bool aTa, cv::_InputArray* delta, double scale, int dtype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMulTransposed", "ptr", $src, "ptr", $dst, "boolean", $aTa, "ptr", $delta, "double", $scale, "int", $dtype), "cveMulTransposed", @error)
EndFunc   ;==>_cveMulTransposed

Func _cveMulTransposedMat($matSrc, $matDst, $aTa, $matDelta = _cveNoArrayMat(), $scale = 1, $dtype = -1)
    ; cveMulTransposed using cv::Mat instead of _*Array

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

    Local $iArrDelta, $vectorOfMatDelta, $iArrDeltaSize
    Local $bDeltaIsArray = VarGetType($matDelta) == "Array"

    If $bDeltaIsArray Then
        $vectorOfMatDelta = _VectorOfMatCreate()

        $iArrDeltaSize = UBound($matDelta)
        For $i = 0 To $iArrDeltaSize - 1
            _VectorOfMatPush($vectorOfMatDelta, $matDelta[$i])
        Next

        $iArrDelta = _cveInputArrayFromVectorOfMat($vectorOfMatDelta)
    Else
        $iArrDelta = _cveInputArrayFromMat($matDelta)
    EndIf

    _cveMulTransposed($iArrSrc, $oArrDst, $aTa, $iArrDelta, $scale, $dtype)

    If $bDeltaIsArray Then
        _VectorOfMatRelease($vectorOfMatDelta)
    EndIf

    _cveInputArrayRelease($iArrDelta)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMulTransposedMat

Func _cveSplit($src, $mv)
    ; CVAPI(void) cveSplit(cv::_InputArray* src, cv::_OutputArray* mv);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSplit", "ptr", $src, "ptr", $mv), "cveSplit", @error)
EndFunc   ;==>_cveSplit

Func _cveSplitMat($matSrc, $matMv)
    ; cveSplit using cv::Mat instead of _*Array

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

    Local $oArrMv, $vectorOfMatMv, $iArrMvSize
    Local $bMvIsArray = VarGetType($matMv) == "Array"

    If $bMvIsArray Then
        $vectorOfMatMv = _VectorOfMatCreate()

        $iArrMvSize = UBound($matMv)
        For $i = 0 To $iArrMvSize - 1
            _VectorOfMatPush($vectorOfMatMv, $matMv[$i])
        Next

        $oArrMv = _cveOutputArrayFromVectorOfMat($vectorOfMatMv)
    Else
        $oArrMv = _cveOutputArrayFromMat($matMv)
    EndIf

    _cveSplit($iArrSrc, $oArrMv)

    If $bMvIsArray Then
        _VectorOfMatRelease($vectorOfMatMv)
    EndIf

    _cveOutputArrayRelease($oArrMv)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSplitMat

Func _cveMerge($mv, $dst)
    ; CVAPI(void) cveMerge(cv::_InputArray* mv, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMerge", "ptr", $mv, "ptr", $dst), "cveMerge", @error)
EndFunc   ;==>_cveMerge

Func _cveMergeMat($matMv, $matDst)
    ; cveMerge using cv::Mat instead of _*Array

    Local $iArrMv, $vectorOfMatMv, $iArrMvSize
    Local $bMvIsArray = VarGetType($matMv) == "Array"

    If $bMvIsArray Then
        $vectorOfMatMv = _VectorOfMatCreate()

        $iArrMvSize = UBound($matMv)
        For $i = 0 To $iArrMvSize - 1
            _VectorOfMatPush($vectorOfMatMv, $matMv[$i])
        Next

        $iArrMv = _cveInputArrayFromVectorOfMat($vectorOfMatMv)
    Else
        $iArrMv = _cveInputArrayFromMat($matMv)
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

    _cveMerge($iArrMv, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bMvIsArray Then
        _VectorOfMatRelease($vectorOfMatMv)
    EndIf

    _cveInputArrayRelease($iArrMv)
EndFunc   ;==>_cveMergeMat

Func _cveMixChannels($src, $dst, $fromTo, $npairs)
    ; CVAPI(void) cveMixChannels(cv::_InputArray* src, cv::_InputOutputArray* dst, const int* fromTo, int npairs);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMixChannels", "ptr", $src, "ptr", $dst, "const int*", $fromTo, "int", $npairs), "cveMixChannels", @error)
EndFunc   ;==>_cveMixChannels

Func _cveMixChannelsMat($matSrc, $matDst, $fromTo, $npairs)
    ; cveMixChannels using cv::Mat instead of _*Array

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

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
    EndIf

    _cveMixChannels($iArrSrc, $ioArrDst, $fromTo, $npairs)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMixChannelsMat

Func _cveExtractChannel($src, $dst, $coi)
    ; CVAPI(void) cveExtractChannel(cv::_InputArray* src, cv::_OutputArray* dst, int coi);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExtractChannel", "ptr", $src, "ptr", $dst, "int", $coi), "cveExtractChannel", @error)
EndFunc   ;==>_cveExtractChannel

Func _cveExtractChannelMat($matSrc, $matDst, $coi)
    ; cveExtractChannel using cv::Mat instead of _*Array

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

    _cveExtractChannel($iArrSrc, $oArrDst, $coi)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveExtractChannelMat

Func _cveInsertChannel($src, $dst, $coi)
    ; CVAPI(void) cveInsertChannel(cv::_InputArray* src, cv::_InputOutputArray* dst, int coi);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInsertChannel", "ptr", $src, "ptr", $dst, "int", $coi), "cveInsertChannel", @error)
EndFunc   ;==>_cveInsertChannel

Func _cveInsertChannelMat($matSrc, $matDst, $coi)
    ; cveInsertChannel using cv::Mat instead of _*Array

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

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
    EndIf

    _cveInsertChannel($iArrSrc, $ioArrDst, $coi)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveInsertChannelMat

Func _cveKmeans($data, $k, $bestLabels, $criteria, $attempts, $flags, $centers = _cveNoArray())
    ; CVAPI(double) cveKmeans(cv::_InputArray* data, int k, cv::_InputOutputArray* bestLabels, CvTermCriteria* criteria, int attempts, int flags, cv::_OutputArray* centers);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveKmeans", "ptr", $data, "int", $k, "ptr", $bestLabels, "struct*", $criteria, "int", $attempts, "int", $flags, "ptr", $centers), "cveKmeans", @error)
EndFunc   ;==>_cveKmeans

Func _cveKmeansMat($matData, $k, $matBestLabels, $criteria, $attempts, $flags, $matCenters = _cveNoArrayMat())
    ; cveKmeans using cv::Mat instead of _*Array

    Local $iArrData, $vectorOfMatData, $iArrDataSize
    Local $bDataIsArray = VarGetType($matData) == "Array"

    If $bDataIsArray Then
        $vectorOfMatData = _VectorOfMatCreate()

        $iArrDataSize = UBound($matData)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfMatPush($vectorOfMatData, $matData[$i])
        Next

        $iArrData = _cveInputArrayFromVectorOfMat($vectorOfMatData)
    Else
        $iArrData = _cveInputArrayFromMat($matData)
    EndIf

    Local $ioArrBestLabels, $vectorOfMatBestLabels, $iArrBestLabelsSize
    Local $bBestLabelsIsArray = VarGetType($matBestLabels) == "Array"

    If $bBestLabelsIsArray Then
        $vectorOfMatBestLabels = _VectorOfMatCreate()

        $iArrBestLabelsSize = UBound($matBestLabels)
        For $i = 0 To $iArrBestLabelsSize - 1
            _VectorOfMatPush($vectorOfMatBestLabels, $matBestLabels[$i])
        Next

        $ioArrBestLabels = _cveInputOutputArrayFromVectorOfMat($vectorOfMatBestLabels)
    Else
        $ioArrBestLabels = _cveInputOutputArrayFromMat($matBestLabels)
    EndIf

    Local $oArrCenters, $vectorOfMatCenters, $iArrCentersSize
    Local $bCentersIsArray = VarGetType($matCenters) == "Array"

    If $bCentersIsArray Then
        $vectorOfMatCenters = _VectorOfMatCreate()

        $iArrCentersSize = UBound($matCenters)
        For $i = 0 To $iArrCentersSize - 1
            _VectorOfMatPush($vectorOfMatCenters, $matCenters[$i])
        Next

        $oArrCenters = _cveOutputArrayFromVectorOfMat($vectorOfMatCenters)
    Else
        $oArrCenters = _cveOutputArrayFromMat($matCenters)
    EndIf

    Local $retval = _cveKmeans($iArrData, $k, $ioArrBestLabels, $criteria, $attempts, $flags, $oArrCenters)

    If $bCentersIsArray Then
        _VectorOfMatRelease($vectorOfMatCenters)
    EndIf

    _cveOutputArrayRelease($oArrCenters)

    If $bBestLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatBestLabels)
    EndIf

    _cveInputOutputArrayRelease($ioArrBestLabels)

    If $bDataIsArray Then
        _VectorOfMatRelease($vectorOfMatData)
    EndIf

    _cveInputArrayRelease($iArrData)

    Return $retval
EndFunc   ;==>_cveKmeansMat

Func _cveHConcat($src1, $src2, $dst)
    ; CVAPI(void) cveHConcat(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHConcat", "ptr", $src1, "ptr", $src2, "ptr", $dst), "cveHConcat", @error)
EndFunc   ;==>_cveHConcat

Func _cveHConcatMat($matSrc1, $matSrc2, $matDst)
    ; cveHConcat using cv::Mat instead of _*Array

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

    _cveHConcat($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveHConcatMat

Func _cveVConcat($src1, $src2, $dst)
    ; CVAPI(void) cveVConcat(cv::_InputArray* src1, cv::_InputArray* src2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVConcat", "ptr", $src1, "ptr", $src2, "ptr", $dst), "cveVConcat", @error)
EndFunc   ;==>_cveVConcat

Func _cveVConcatMat($matSrc1, $matSrc2, $matDst)
    ; cveVConcat using cv::Mat instead of _*Array

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

    _cveVConcat($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveVConcatMat

Func _cveHConcat2($src, $dst)
    ; CVAPI(void) cveHConcat2(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHConcat2", "ptr", $src, "ptr", $dst), "cveHConcat2", @error)
EndFunc   ;==>_cveHConcat2

Func _cveHConcat2Mat($matSrc, $matDst)
    ; cveHConcat2 using cv::Mat instead of _*Array

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

    _cveHConcat2($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveHConcat2Mat

Func _cveVConcat2($src, $dst)
    ; CVAPI(void) cveVConcat2(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVConcat2", "ptr", $src, "ptr", $dst), "cveVConcat2", @error)
EndFunc   ;==>_cveVConcat2

Func _cveVConcat2Mat($matSrc, $matDst)
    ; cveVConcat2 using cv::Mat instead of _*Array

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

    _cveVConcat2($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveVConcat2Mat

Func _cvePSNR($src1, $src2)
    ; CVAPI(double) cvePSNR(cv::_InputArray* src1, cv::_InputArray* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cvePSNR", "ptr", $src1, "ptr", $src2), "cvePSNR", @error)
EndFunc   ;==>_cvePSNR

Func _cvePSNRMat($matSrc1, $matSrc2)
    ; cvePSNR using cv::Mat instead of _*Array

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

    Local $retval = _cvePSNR($iArrSrc1, $iArrSrc2)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)

    Return $retval
EndFunc   ;==>_cvePSNRMat

Func _cveEigen($src, $eigenValues, $eigenVectors)
    ; CVAPI(bool) cveEigen(cv::_InputArray* src, cv::_OutputArray* eigenValues, cv::_OutputArray* eigenVectors);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveEigen", "ptr", $src, "ptr", $eigenValues, "ptr", $eigenVectors), "cveEigen", @error)
EndFunc   ;==>_cveEigen

Func _cveEigenMat($matSrc, $matEigenValues, $matEigenVectors)
    ; cveEigen using cv::Mat instead of _*Array

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

    Local $oArrEigenValues, $vectorOfMatEigenValues, $iArrEigenValuesSize
    Local $bEigenValuesIsArray = VarGetType($matEigenValues) == "Array"

    If $bEigenValuesIsArray Then
        $vectorOfMatEigenValues = _VectorOfMatCreate()

        $iArrEigenValuesSize = UBound($matEigenValues)
        For $i = 0 To $iArrEigenValuesSize - 1
            _VectorOfMatPush($vectorOfMatEigenValues, $matEigenValues[$i])
        Next

        $oArrEigenValues = _cveOutputArrayFromVectorOfMat($vectorOfMatEigenValues)
    Else
        $oArrEigenValues = _cveOutputArrayFromMat($matEigenValues)
    EndIf

    Local $oArrEigenVectors, $vectorOfMatEigenVectors, $iArrEigenVectorsSize
    Local $bEigenVectorsIsArray = VarGetType($matEigenVectors) == "Array"

    If $bEigenVectorsIsArray Then
        $vectorOfMatEigenVectors = _VectorOfMatCreate()

        $iArrEigenVectorsSize = UBound($matEigenVectors)
        For $i = 0 To $iArrEigenVectorsSize - 1
            _VectorOfMatPush($vectorOfMatEigenVectors, $matEigenVectors[$i])
        Next

        $oArrEigenVectors = _cveOutputArrayFromVectorOfMat($vectorOfMatEigenVectors)
    Else
        $oArrEigenVectors = _cveOutputArrayFromMat($matEigenVectors)
    EndIf

    Local $retval = _cveEigen($iArrSrc, $oArrEigenValues, $oArrEigenVectors)

    If $bEigenVectorsIsArray Then
        _VectorOfMatRelease($vectorOfMatEigenVectors)
    EndIf

    _cveOutputArrayRelease($oArrEigenVectors)

    If $bEigenValuesIsArray Then
        _VectorOfMatRelease($vectorOfMatEigenValues)
    EndIf

    _cveOutputArrayRelease($oArrEigenValues)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    Return $retval
EndFunc   ;==>_cveEigenMat

Func _cveAlgorithmRead($algorithm, $node)
    ; CVAPI(void) cveAlgorithmRead(cv::Algorithm* algorithm, cv::FileNode* node);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmRead", "ptr", $algorithm, "ptr", $node), "cveAlgorithmRead", @error)
EndFunc   ;==>_cveAlgorithmRead

Func _cveAlgorithmWrite($algorithm, $storage)
    ; CVAPI(void) cveAlgorithmWrite(cv::Algorithm* algorithm, cv::FileStorage* storage);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmWrite", "ptr", $algorithm, "ptr", $storage), "cveAlgorithmWrite", @error)
EndFunc   ;==>_cveAlgorithmWrite

Func _cveAlgorithmWrite2($algorithm, $storage, $name)
    ; CVAPI(void) cveAlgorithmWrite2(cv::Algorithm* algorithm, cv::FileStorage* storage, cv::String* name);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmWrite2", "ptr", $algorithm, "ptr", $storage, "ptr", $name), "cveAlgorithmWrite2", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveAlgorithmWrite2

Func _cveAlgorithmSave($algorithm, $filename)
    ; CVAPI(void) cveAlgorithmSave(cv::Algorithm* algorithm, cv::String* filename);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmSave", "ptr", $algorithm, "ptr", $filename), "cveAlgorithmSave", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf
EndFunc   ;==>_cveAlgorithmSave

Func _cveAlgorithmClear($algorithm)
    ; CVAPI(void) cveAlgorithmClear(cv::Algorithm* algorithm);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmClear", "ptr", $algorithm), "cveAlgorithmClear", @error)
EndFunc   ;==>_cveAlgorithmClear

Func _cveAlgorithmEmpty($algorithm)
    ; CVAPI(bool) cveAlgorithmEmpty(cv::Algorithm* algorithm);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveAlgorithmEmpty", "ptr", $algorithm), "cveAlgorithmEmpty", @error)
EndFunc   ;==>_cveAlgorithmEmpty

Func _cveAlgorithmGetDefaultName($algorithm, $defaultName)
    ; CVAPI(void) cveAlgorithmGetDefaultName(cv::Algorithm* algorithm, cv::String* defaultName);

    Local $bDefaultNameIsString = VarGetType($defaultName) == "String"
    If $bDefaultNameIsString Then
        $defaultName = _cveStringCreateFromStr($defaultName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmGetDefaultName", "ptr", $algorithm, "ptr", $defaultName), "cveAlgorithmGetDefaultName", @error)

    If $bDefaultNameIsString Then
        _cveStringRelease($defaultName)
    EndIf
EndFunc   ;==>_cveAlgorithmGetDefaultName

Func _cveClipLine($rect, $pt1, $pt2)
    ; CVAPI(bool) cveClipLine(CvRect* rect, CvPoint* pt1, CvPoint* pt2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveClipLine", "struct*", $rect, "struct*", $pt1, "struct*", $pt2), "cveClipLine", @error)
EndFunc   ;==>_cveClipLine

Func _cveRandn($dst, $mean, $stddev)
    ; CVAPI(void) cveRandn(cv::_InputOutputArray* dst, cv::_InputArray* mean, cv::_InputArray* stddev);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRandn", "ptr", $dst, "ptr", $mean, "ptr", $stddev), "cveRandn", @error)
EndFunc   ;==>_cveRandn

Func _cveRandnMat($matDst, $matMean, $matStddev)
    ; cveRandn using cv::Mat instead of _*Array

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
    EndIf

    Local $iArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $iArrMean = _cveInputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $iArrMean = _cveInputArrayFromMat($matMean)
    EndIf

    Local $iArrStddev, $vectorOfMatStddev, $iArrStddevSize
    Local $bStddevIsArray = VarGetType($matStddev) == "Array"

    If $bStddevIsArray Then
        $vectorOfMatStddev = _VectorOfMatCreate()

        $iArrStddevSize = UBound($matStddev)
        For $i = 0 To $iArrStddevSize - 1
            _VectorOfMatPush($vectorOfMatStddev, $matStddev[$i])
        Next

        $iArrStddev = _cveInputArrayFromVectorOfMat($vectorOfMatStddev)
    Else
        $iArrStddev = _cveInputArrayFromMat($matStddev)
    EndIf

    _cveRandn($ioArrDst, $iArrMean, $iArrStddev)

    If $bStddevIsArray Then
        _VectorOfMatRelease($vectorOfMatStddev)
    EndIf

    _cveInputArrayRelease($iArrStddev)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveInputArrayRelease($iArrMean)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)
EndFunc   ;==>_cveRandnMat

Func _cveRandu($dst, $low, $high)
    ; CVAPI(void) cveRandu(cv::_InputOutputArray* dst, cv::_InputArray* low, cv::_InputArray* high);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRandu", "ptr", $dst, "ptr", $low, "ptr", $high), "cveRandu", @error)
EndFunc   ;==>_cveRandu

Func _cveRanduMat($matDst, $matLow, $matHigh)
    ; cveRandu using cv::Mat instead of _*Array

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
    EndIf

    Local $iArrLow, $vectorOfMatLow, $iArrLowSize
    Local $bLowIsArray = VarGetType($matLow) == "Array"

    If $bLowIsArray Then
        $vectorOfMatLow = _VectorOfMatCreate()

        $iArrLowSize = UBound($matLow)
        For $i = 0 To $iArrLowSize - 1
            _VectorOfMatPush($vectorOfMatLow, $matLow[$i])
        Next

        $iArrLow = _cveInputArrayFromVectorOfMat($vectorOfMatLow)
    Else
        $iArrLow = _cveInputArrayFromMat($matLow)
    EndIf

    Local $iArrHigh, $vectorOfMatHigh, $iArrHighSize
    Local $bHighIsArray = VarGetType($matHigh) == "Array"

    If $bHighIsArray Then
        $vectorOfMatHigh = _VectorOfMatCreate()

        $iArrHighSize = UBound($matHigh)
        For $i = 0 To $iArrHighSize - 1
            _VectorOfMatPush($vectorOfMatHigh, $matHigh[$i])
        Next

        $iArrHigh = _cveInputArrayFromVectorOfMat($vectorOfMatHigh)
    Else
        $iArrHigh = _cveInputArrayFromMat($matHigh)
    EndIf

    _cveRandu($ioArrDst, $iArrLow, $iArrHigh)

    If $bHighIsArray Then
        _VectorOfMatRelease($vectorOfMatHigh)
    EndIf

    _cveInputArrayRelease($iArrHigh)

    If $bLowIsArray Then
        _VectorOfMatRelease($vectorOfMatLow)
    EndIf

    _cveInputArrayRelease($iArrLow)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)
EndFunc   ;==>_cveRanduMat

Func _cveFileStorageCreate($source, $flags, $encoding)
    ; CVAPI(cv::FileStorage*) cveFileStorageCreate(const cv::String* source, int flags, const cv::String* encoding);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageCreate", "ptr", $source, "int", $flags, "ptr", $encoding), "cveFileStorageCreate", @error)
EndFunc   ;==>_cveFileStorageCreate

Func _cveFileStorageIsOpened($storage)
    ; CVAPI(bool) cveFileStorageIsOpened(cv::FileStorage* storage);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileStorageIsOpened", "ptr", $storage), "cveFileStorageIsOpened", @error)
EndFunc   ;==>_cveFileStorageIsOpened

Func _cveFileStorageReleaseAndGetString($storage, $result)
    ; CVAPI(void) cveFileStorageReleaseAndGetString(cv::FileStorage* storage, cv::String* result);

    Local $bResultIsString = VarGetType($result) == "String"
    If $bResultIsString Then
        $result = _cveStringCreateFromStr($result)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageReleaseAndGetString", "ptr", $storage, "ptr", $result), "cveFileStorageReleaseAndGetString", @error)

    If $bResultIsString Then
        _cveStringRelease($result)
    EndIf
EndFunc   ;==>_cveFileStorageReleaseAndGetString

Func _cveFileStorageRelease($storage)
    ; CVAPI(void) cveFileStorageRelease(cv::FileStorage** storage);

    Local $bStorageDllType
    If VarGetType($storage) == "DLLStruct" Then
        $bStorageDllType = "struct*"
    Else
        $bStorageDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageRelease", $bStorageDllType, $storage), "cveFileStorageRelease", @error)
EndFunc   ;==>_cveFileStorageRelease

Func _cveFileStorageWriteMat($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteMat(cv::FileStorage* fs, cv::String* name, cv::Mat* value);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteMat", "ptr", $fs, "ptr", $name, "ptr", $value), "cveFileStorageWriteMat", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteMat

Func _cveFileStorageWriteInt($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteInt(cv::FileStorage* fs, cv::String* name, int value);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteInt", "ptr", $fs, "ptr", $name, "int", $value), "cveFileStorageWriteInt", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteInt

Func _cveFileStorageWriteFloat($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteFloat(cv::FileStorage* fs, cv::String* name, float value);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteFloat", "ptr", $fs, "ptr", $name, "float", $value), "cveFileStorageWriteFloat", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteFloat

Func _cveFileStorageWriteDouble($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteDouble(cv::FileStorage* fs, cv::String* name, double value);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteDouble", "ptr", $fs, "ptr", $name, "double", $value), "cveFileStorageWriteDouble", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteDouble

Func _cveFileStorageWriteString($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteString(cv::FileStorage* fs, cv::String* name, cv::String* value);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteString", "ptr", $fs, "ptr", $name, "ptr", $value), "cveFileStorageWriteString", @error)

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteString

Func _cveFileStorageInsertString($fs, $value)
    ; CVAPI(void) cveFileStorageInsertString(cv::FileStorage* fs, cv::String* value);

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageInsertString", "ptr", $fs, "ptr", $value), "cveFileStorageInsertString", @error)

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf
EndFunc   ;==>_cveFileStorageInsertString

Func _cveFileStorageRoot($fs, $streamIdx)
    ; CVAPI(cv::FileNode*) cveFileStorageRoot(cv::FileStorage* fs, int streamIdx);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageRoot", "ptr", $fs, "int", $streamIdx), "cveFileStorageRoot", @error)
EndFunc   ;==>_cveFileStorageRoot

Func _cveFileStorageGetFirstTopLevelNode($fs)
    ; CVAPI(cv::FileNode*) cveFileStorageGetFirstTopLevelNode(cv::FileStorage* fs);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageGetFirstTopLevelNode", "ptr", $fs), "cveFileStorageGetFirstTopLevelNode", @error)
EndFunc   ;==>_cveFileStorageGetFirstTopLevelNode

Func _cveFileStorageGetNode($fs, $nodeName)
    ; CVAPI(cv::FileNode*) cveFileStorageGetNode(cv::FileStorage* fs, cv::String* nodeName);

    Local $bNodeNameIsString = VarGetType($nodeName) == "String"
    If $bNodeNameIsString Then
        $nodeName = _cveStringCreateFromStr($nodeName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageGetNode", "ptr", $fs, "ptr", $nodeName), "cveFileStorageGetNode", @error)

    If $bNodeNameIsString Then
        _cveStringRelease($nodeName)
    EndIf

    Return $retval
EndFunc   ;==>_cveFileStorageGetNode

Func _cveFileNodeGetType($node)
    ; CVAPI(int) cveFileNodeGetType(cv::FileNode* node);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFileNodeGetType", "ptr", $node), "cveFileNodeGetType", @error)
EndFunc   ;==>_cveFileNodeGetType

Func _cveFileNodeGetName($node, $name)
    ; CVAPI(void) cveFileNodeGetName(cv::FileNode* node, cv::String* name);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeGetName", "ptr", $node, "ptr", $name), "cveFileNodeGetName", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileNodeGetName

Func _cveFileNodeGetKeys($node, $keys)
    ; CVAPI(void) cveFileNodeGetKeys(cv::FileNode* node, std::vector< cv::String >* keys);

    Local $vecKeys, $iArrKeysSize
    Local $bKeysIsArray = VarGetType($keys) == "Array"

    If $bKeysIsArray Then
        $vecKeys = _VectorOfCvStringCreate()

        $iArrKeysSize = UBound($keys)
        For $i = 0 To $iArrKeysSize - 1
            _VectorOfCvStringPush($vecKeys, $keys[$i])
        Next
    Else
        $vecKeys = $keys
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeGetKeys", "ptr", $node, "ptr", $vecKeys), "cveFileNodeGetKeys", @error)

    If $bKeysIsArray Then
        _VectorOfCvStringRelease($vecKeys)
    EndIf
EndFunc   ;==>_cveFileNodeGetKeys

Func _cveFileNodeReadMat($node, $mat, $defaultMat)
    ; CVAPI(void) cveFileNodeReadMat(cv::FileNode* node, cv::Mat* mat, cv::Mat* defaultMat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeReadMat", "ptr", $node, "ptr", $mat, "ptr", $defaultMat), "cveFileNodeReadMat", @error)
EndFunc   ;==>_cveFileNodeReadMat

Func _cveFileNodeReadString($node, $str, $defaultStr)
    ; CVAPI(void) cveFileNodeReadString(cv::FileNode* node, cv::String* str, cv::String* defaultStr);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bDefaultStrIsString = VarGetType($defaultStr) == "String"
    If $bDefaultStrIsString Then
        $defaultStr = _cveStringCreateFromStr($defaultStr)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeReadString", "ptr", $node, "ptr", $str, "ptr", $defaultStr), "cveFileNodeReadString", @error)

    If $bDefaultStrIsString Then
        _cveStringRelease($defaultStr)
    EndIf

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFileNodeReadString

Func _cveFileNodeReadInt($node, $defaultInt)
    ; CVAPI(int) cveFileNodeReadInt(cv::FileNode* node, int defaultInt);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFileNodeReadInt", "ptr", $node, "int", $defaultInt), "cveFileNodeReadInt", @error)
EndFunc   ;==>_cveFileNodeReadInt

Func _cveFileNodeReadDouble($node, $defaultDouble)
    ; CVAPI(double) cveFileNodeReadDouble(cv::FileNode* node, double defaultDouble);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFileNodeReadDouble", "ptr", $node, "double", $defaultDouble), "cveFileNodeReadDouble", @error)
EndFunc   ;==>_cveFileNodeReadDouble

Func _cveFileNodeReadFloat($node, $defaultFloat)
    ; CVAPI(float) cveFileNodeReadFloat(cv::FileNode* node, float defaultFloat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveFileNodeReadFloat", "ptr", $node, "float", $defaultFloat), "cveFileNodeReadFloat", @error)
EndFunc   ;==>_cveFileNodeReadFloat

Func _cveFileNodeRelease($node)
    ; CVAPI(void) cveFileNodeRelease(cv::FileNode** node);

    Local $bNodeDllType
    If VarGetType($node) == "DLLStruct" Then
        $bNodeDllType = "struct*"
    Else
        $bNodeDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeRelease", $bNodeDllType, $node), "cveFileNodeRelease", @error)
EndFunc   ;==>_cveFileNodeRelease

Func _cveFileNodeIteratorCreate()
    ; CVAPI(cv::FileNodeIterator*) cveFileNodeIteratorCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileNodeIteratorCreate"), "cveFileNodeIteratorCreate", @error)
EndFunc   ;==>_cveFileNodeIteratorCreate

Func _cveFileNodeIteratorCreateFromNode($node, $seekEnd)
    ; CVAPI(cv::FileNodeIterator*) cveFileNodeIteratorCreateFromNode(cv::FileNode* node, bool seekEnd);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileNodeIteratorCreateFromNode", "ptr", $node, "boolean", $seekEnd), "cveFileNodeIteratorCreateFromNode", @error)
EndFunc   ;==>_cveFileNodeIteratorCreateFromNode

Func _cveFileNodeIteratorEqualTo($iterator, $otherIterator)
    ; CVAPI(bool) cveFileNodeIteratorEqualTo(cv::FileNodeIterator* iterator, cv::FileNodeIterator* otherIterator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIteratorEqualTo", "ptr", $iterator, "ptr", $otherIterator), "cveFileNodeIteratorEqualTo", @error)
EndFunc   ;==>_cveFileNodeIteratorEqualTo

Func _cveFileNodeIteratorNext($iterator)
    ; CVAPI(void) cveFileNodeIteratorNext(cv::FileNodeIterator* iterator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeIteratorNext", "ptr", $iterator), "cveFileNodeIteratorNext", @error)
EndFunc   ;==>_cveFileNodeIteratorNext

Func _cveFileNodeIteratorGetFileNode($iterator)
    ; CVAPI(cv::FileNode*) cveFileNodeIteratorGetFileNode(cv::FileNodeIterator* iterator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileNodeIteratorGetFileNode", "ptr", $iterator), "cveFileNodeIteratorGetFileNode", @error)
EndFunc   ;==>_cveFileNodeIteratorGetFileNode

Func _cveFileNodeIteratorRelease($iterator)
    ; CVAPI(void) cveFileNodeIteratorRelease(cv::FileNodeIterator** iterator);

    Local $bIteratorDllType
    If VarGetType($iterator) == "DLLStruct" Then
        $bIteratorDllType = "struct*"
    Else
        $bIteratorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeIteratorRelease", $bIteratorDllType, $iterator), "cveFileNodeIteratorRelease", @error)
EndFunc   ;==>_cveFileNodeIteratorRelease

Func _cveCreateImage($size, $depth, $channels)
    ; CVAPI(IplImage*) cveCreateImage(CvSize* size, int depth, int channels);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateImage", "struct*", $size, "int", $depth, "int", $channels), "cveCreateImage", @error)
EndFunc   ;==>_cveCreateImage

Func _cveCreateImageHeader($size, $depth, $channels)
    ; CVAPI(IplImage*) cveCreateImageHeader(CvSize* size, int depth, int channels);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateImageHeader", "struct*", $size, "int", $depth, "int", $channels), "cveCreateImageHeader", @error)
EndFunc   ;==>_cveCreateImageHeader

Func _cveInitImageHeader($image, $size, $depth, $channels, $origin, $align)
    ; CVAPI(IplImage*) cveInitImageHeader(IplImage* image, CvSize* size, int depth, int channels, int origin, int align);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInitImageHeader", "struct*", $image, "struct*", $size, "int", $depth, "int", $channels, "int", $origin, "int", $align), "cveInitImageHeader", @error)
EndFunc   ;==>_cveInitImageHeader

Func _cveSetData($arr, $data, $step)
    ; CVAPI(void) cveSetData(CvArr* arr, void* data, int step);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetData", "struct*", $arr, "struct*", $data, "int", $step), "cveSetData", @error)
EndFunc   ;==>_cveSetData

Func _cveReleaseImageHeader($image)
    ; CVAPI(void) cveReleaseImageHeader(IplImage** image);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseImageHeader", $bImageDllType, $image), "cveReleaseImageHeader", @error)
EndFunc   ;==>_cveReleaseImageHeader

Func _cveSetImageCOI($image, $coi)
    ; CVAPI(void) cveSetImageCOI(IplImage* image, int coi);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetImageCOI", "struct*", $image, "int", $coi), "cveSetImageCOI", @error)
EndFunc   ;==>_cveSetImageCOI

Func _cveGetImageCOI($image)
    ; CVAPI(int) cveGetImageCOI(IplImage* image);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetImageCOI", "struct*", $image), "cveGetImageCOI", @error)
EndFunc   ;==>_cveGetImageCOI

Func _cveResetImageROI($image)
    ; CVAPI(void) cveResetImageROI(IplImage* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveResetImageROI", "struct*", $image), "cveResetImageROI", @error)
EndFunc   ;==>_cveResetImageROI

Func _cveSetImageROI($image, $rect)
    ; CVAPI(void) cveSetImageROI(IplImage* image, CvRect* rect);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetImageROI", "struct*", $image, "struct*", $rect), "cveSetImageROI", @error)
EndFunc   ;==>_cveSetImageROI

Func _cveGetImageROI($image, $rect)
    ; CVAPI(void) cveGetImageROI(IplImage* image, CvRect* rect);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetImageROI", "struct*", $image, "struct*", $rect), "cveGetImageROI", @error)
EndFunc   ;==>_cveGetImageROI

Func _cveInitMatHeader($mat, $rows, $cols, $type, $data, $step)
    ; CVAPI(CvMat*) cveInitMatHeader(CvMat* mat, int rows, int cols, int type, void* data, int step);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInitMatHeader", "struct*", $mat, "int", $rows, "int", $cols, "int", $type, "struct*", $data, "int", $step), "cveInitMatHeader", @error)
EndFunc   ;==>_cveInitMatHeader

Func _cveCreateMat($rows, $cols, $type)
    ; CVAPI(CvMat*) cveCreateMat(int rows, int cols, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateMat", "int", $rows, "int", $cols, "int", $type), "cveCreateMat", @error)
EndFunc   ;==>_cveCreateMat

Func _cveInitMatNDHeader($mat, $dims, $sizes, $type, $data)
    ; CVAPI(CvMatND*) cveInitMatNDHeader(CvMatND* mat, int dims, int* sizes, int type, void* data);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInitMatNDHeader", "struct*", $mat, "int", $dims, "struct*", $sizes, "int", $type, "struct*", $data), "cveInitMatNDHeader", @error)
EndFunc   ;==>_cveInitMatNDHeader

Func _cveReleaseMat($mat)
    ; CVAPI(void) cveReleaseMat(CvMat** mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseMat", $bMatDllType, $mat), "cveReleaseMat", @error)
EndFunc   ;==>_cveReleaseMat

Func _cveCreateSparseMat($dim, $sizes, $type)
    ; CVAPI(CvSparseMat*) cveCreateSparseMat(int dim, int* sizes, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateSparseMat", "int", $dim, "struct*", $sizes, "int", $type), "cveCreateSparseMat", @error)
EndFunc   ;==>_cveCreateSparseMat

Func _cveReleaseSparseMat($mat)
    ; CVAPI(void) cveReleaseSparseMat(CvSparseMat** mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseSparseMat", $bMatDllType, $mat), "cveReleaseSparseMat", @error)
EndFunc   ;==>_cveReleaseSparseMat

Func _cveSet2D($arr, $idx0, $idx1, $value)
    ; CVAPI(void) cveSet2D(CvArr* arr, int idx0, int idx1, CvScalar* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSet2D", "struct*", $arr, "int", $idx0, "int", $idx1, "struct*", $value), "cveSet2D", @error)
EndFunc   ;==>_cveSet2D

Func _cveGetSubRect($arr, $submat, $rect)
    ; CVAPI(CvMat*) cveGetSubRect(CvArr* arr, CvMat* submat, CvRect* rect);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetSubRect", "struct*", $arr, "struct*", $submat, "struct*", $rect), "cveGetSubRect", @error)
EndFunc   ;==>_cveGetSubRect

Func _cveGetRows($arr, $submat, $startRow, $endRow, $deltaRow)
    ; CVAPI(CvMat*) cveGetRows(CvArr* arr, CvMat* submat, int startRow, int endRow, int deltaRow);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetRows", "struct*", $arr, "struct*", $submat, "int", $startRow, "int", $endRow, "int", $deltaRow), "cveGetRows", @error)
EndFunc   ;==>_cveGetRows

Func _cveGetCols($arr, $submat, $startCol, $endCol)
    ; CVAPI(CvMat*) cveGetCols(CvArr* arr, CvMat* submat, int startCol, int endCol);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetCols", "struct*", $arr, "struct*", $submat, "int", $startCol, "int", $endCol), "cveGetCols", @error)
EndFunc   ;==>_cveGetCols

Func _cveGetSize($arr, $width, $height)
    ; CVAPI(void) cveGetSize(CvArr* arr, int* width, int* height);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetSize", "struct*", $arr, "struct*", $width, "struct*", $height), "cveGetSize", @error)
EndFunc   ;==>_cveGetSize

Func _cveCopy($src, $dst, $mask)
    ; CVAPI(void) cveCopy(CvArr* src, CvArr* dst, CvArr* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCopy", "struct*", $src, "struct*", $dst, "struct*", $mask), "cveCopy", @error)
EndFunc   ;==>_cveCopy

Func _cveRange($mat, $start, $end)
    ; CVAPI(void) cveRange(CvArr* mat, double start, double end);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRange", "struct*", $mat, "double", $start, "double", $end), "cveRange", @error)
EndFunc   ;==>_cveRange

Func _cveSetReal1D($arr, $idx0, $value)
    ; CVAPI(void) cveSetReal1D(CvArr* arr, int idx0, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetReal1D", "struct*", $arr, "int", $idx0, "double", $value), "cveSetReal1D", @error)
EndFunc   ;==>_cveSetReal1D

Func _cveSetReal2D($arr, $idx0, $idx1, $value)
    ; CVAPI(void) cveSetReal2D(CvArr* arr, int idx0, int idx1, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetReal2D", "struct*", $arr, "int", $idx0, "int", $idx1, "double", $value), "cveSetReal2D", @error)
EndFunc   ;==>_cveSetReal2D

Func _cveSetReal3D($arr, $idx0, $idx1, $idx2, $value)
    ; CVAPI(void) cveSetReal3D(CvArr* arr, int idx0, int idx1, int idx2, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetReal3D", "struct*", $arr, "int", $idx0, "int", $idx1, "int", $idx2, "double", $value), "cveSetReal3D", @error)
EndFunc   ;==>_cveSetReal3D

Func _cveSetRealND($arr, $idx, $value)
    ; CVAPI(void) cveSetRealND(CvArr* arr, int* idx, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetRealND", "struct*", $arr, "struct*", $idx, "double", $value), "cveSetRealND", @error)
EndFunc   ;==>_cveSetRealND

Func _cveGet1D($arr, $idx0, $value)
    ; CVAPI(void) cveGet1D(CvArr* arr, int idx0, CvScalar* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGet1D", "struct*", $arr, "int", $idx0, "struct*", $value), "cveGet1D", @error)
EndFunc   ;==>_cveGet1D

Func _cveGet2D($arr, $idx0, $idx1, $value)
    ; CVAPI(void) cveGet2D(CvArr* arr, int idx0, int idx1, CvScalar* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGet2D", "struct*", $arr, "int", $idx0, "int", $idx1, "struct*", $value), "cveGet2D", @error)
EndFunc   ;==>_cveGet2D

Func _cveGet3D($arr, $idx0, $idx1, $idx2, $value)
    ; CVAPI(void) cveGet3D(CvArr* arr, int idx0, int idx1, int idx2, CvScalar* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGet3D", "struct*", $arr, "int", $idx0, "int", $idx1, "int", $idx2, "struct*", $value), "cveGet3D", @error)
EndFunc   ;==>_cveGet3D

Func _cveGetReal1D($arr, $idx0)
    ; CVAPI(double) cveGetReal1D(CvArr* arr, int idx0);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetReal1D", "struct*", $arr, "int", $idx0), "cveGetReal1D", @error)
EndFunc   ;==>_cveGetReal1D

Func _cveGetReal2D($arr, $idx0, $idx1)
    ; CVAPI(double) cveGetReal2D(CvArr* arr, int idx0, int idx1);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetReal2D", "struct*", $arr, "int", $idx0, "int", $idx1), "cveGetReal2D", @error)
EndFunc   ;==>_cveGetReal2D

Func _cveGetReal3D($arr, $idx0, $idx1, $idx2)
    ; CVAPI(double) cveGetReal3D(CvArr* arr, int idx0, int idx1, int idx2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetReal3D", "struct*", $arr, "int", $idx0, "int", $idx1, "int", $idx2), "cveGetReal3D", @error)
EndFunc   ;==>_cveGetReal3D

Func _cveClearND($arr, $idx)
    ; CVAPI(void) cveClearND(CvArr* arr, int* idx);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveClearND", "struct*", $arr, "struct*", $idx), "cveClearND", @error)
EndFunc   ;==>_cveClearND

Func _cveUseOptimized()
    ; CVAPI(bool) cveUseOptimized();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUseOptimized"), "cveUseOptimized", @error)
EndFunc   ;==>_cveUseOptimized

Func _cveSetUseOptimized($onoff)
    ; CVAPI(void) cveSetUseOptimized(bool onoff);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetUseOptimized", "boolean", $onoff), "cveSetUseOptimized", @error)
EndFunc   ;==>_cveSetUseOptimized

Func _cveHaveOpenVX()
    ; CVAPI(bool) cveHaveOpenVX();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHaveOpenVX"), "cveHaveOpenVX", @error)
EndFunc   ;==>_cveHaveOpenVX

Func _cveUseOpenVX()
    ; CVAPI(bool) cveUseOpenVX();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUseOpenVX"), "cveUseOpenVX", @error)
EndFunc   ;==>_cveUseOpenVX

Func _cveSetUseOpenVX($flag)
    ; CVAPI(void) cveSetUseOpenVX(bool flag);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetUseOpenVX", "boolean", $flag), "cveSetUseOpenVX", @error)
EndFunc   ;==>_cveSetUseOpenVX

Func _cveGetBuildInformation($buildInformation)
    ; CVAPI(void) cveGetBuildInformation(cv::String* buildInformation);

    Local $bBuildInformationIsString = VarGetType($buildInformation) == "String"
    If $bBuildInformationIsString Then
        $buildInformation = _cveStringCreateFromStr($buildInformation)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetBuildInformation", "ptr", $buildInformation), "cveGetBuildInformation", @error)

    If $bBuildInformationIsString Then
        _cveStringRelease($buildInformation)
    EndIf
EndFunc   ;==>_cveGetBuildInformation

Func _cveGetRawData($arr, $data, $step, $roiSize)
    ; CVAPI(void) cveGetRawData(CvArr* arr, uchar** data, int* step, CvSize* roiSize);

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRawData", "struct*", $arr, $bDataDllType, $data, "struct*", $step, "struct*", $roiSize), "cveGetRawData", @error)
EndFunc   ;==>_cveGetRawData

Func _cveGetMat($arr, $header, $coi, $allowNd)
    ; CVAPI(CvMat*) cveGetMat(CvArr* arr, CvMat* header, int* coi, int allowNd);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetMat", "struct*", $arr, "struct*", $header, "struct*", $coi, "int", $allowNd), "cveGetMat", @error)
EndFunc   ;==>_cveGetMat

Func _cveGetImage($arr, $imageHeader)
    ; CVAPI(IplImage*) cveGetImage(CvArr* arr, IplImage* imageHeader);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetImage", "struct*", $arr, "struct*", $imageHeader), "cveGetImage", @error)
EndFunc   ;==>_cveGetImage

Func _cveCheckArr($arr, $flags, $minVal, $maxVal)
    ; CVAPI(int) cveCheckArr(CvArr* arr, int flags, double minVal, double maxVal);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCheckArr", "struct*", $arr, "int", $flags, "double", $minVal, "double", $maxVal), "cveCheckArr", @error)
EndFunc   ;==>_cveCheckArr

Func _cveReshape($arr, $header, $newCn, $newRows)
    ; CVAPI(CvMat*) cveReshape(CvArr* arr, CvMat* header, int newCn, int newRows);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReshape", "struct*", $arr, "struct*", $header, "int", $newCn, "int", $newRows), "cveReshape", @error)
EndFunc   ;==>_cveReshape

Func _cveGetDiag($arr, $submat, $diag)
    ; CVAPI(CvMat*) cveGetDiag(CvArr* arr, CvMat* submat, int diag);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetDiag", "struct*", $arr, "struct*", $submat, "int", $diag), "cveGetDiag", @error)
EndFunc   ;==>_cveGetDiag

Func _cveConvertScale($arr, $dst, $scale, $shift)
    ; CVAPI(void) cveConvertScale(CvArr* arr, CvArr* dst, double scale, double shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertScale", "struct*", $arr, "struct*", $dst, "double", $scale, "double", $shift), "cveConvertScale", @error)
EndFunc   ;==>_cveConvertScale

Func _cveReleaseImage($image)
    ; CVAPI(void) cveReleaseImage(IplImage** image);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseImage", $bImageDllType, $image), "cveReleaseImage", @error)
EndFunc   ;==>_cveReleaseImage

Func _cveSVDecomp($src, $w, $u, $vt, $flags = 0)
    ; CVAPI(void) cveSVDecomp(cv::_InputArray* src, cv::_OutputArray* w, cv::_OutputArray* u, cv::_OutputArray* vt, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVDecomp", "ptr", $src, "ptr", $w, "ptr", $u, "ptr", $vt, "int", $flags), "cveSVDecomp", @error)
EndFunc   ;==>_cveSVDecomp

Func _cveSVDecompMat($matSrc, $matW, $matU, $matVt, $flags = 0)
    ; cveSVDecomp using cv::Mat instead of _*Array

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

    Local $oArrW, $vectorOfMatW, $iArrWSize
    Local $bWIsArray = VarGetType($matW) == "Array"

    If $bWIsArray Then
        $vectorOfMatW = _VectorOfMatCreate()

        $iArrWSize = UBound($matW)
        For $i = 0 To $iArrWSize - 1
            _VectorOfMatPush($vectorOfMatW, $matW[$i])
        Next

        $oArrW = _cveOutputArrayFromVectorOfMat($vectorOfMatW)
    Else
        $oArrW = _cveOutputArrayFromMat($matW)
    EndIf

    Local $oArrU, $vectorOfMatU, $iArrUSize
    Local $bUIsArray = VarGetType($matU) == "Array"

    If $bUIsArray Then
        $vectorOfMatU = _VectorOfMatCreate()

        $iArrUSize = UBound($matU)
        For $i = 0 To $iArrUSize - 1
            _VectorOfMatPush($vectorOfMatU, $matU[$i])
        Next

        $oArrU = _cveOutputArrayFromVectorOfMat($vectorOfMatU)
    Else
        $oArrU = _cveOutputArrayFromMat($matU)
    EndIf

    Local $oArrVt, $vectorOfMatVt, $iArrVtSize
    Local $bVtIsArray = VarGetType($matVt) == "Array"

    If $bVtIsArray Then
        $vectorOfMatVt = _VectorOfMatCreate()

        $iArrVtSize = UBound($matVt)
        For $i = 0 To $iArrVtSize - 1
            _VectorOfMatPush($vectorOfMatVt, $matVt[$i])
        Next

        $oArrVt = _cveOutputArrayFromVectorOfMat($vectorOfMatVt)
    Else
        $oArrVt = _cveOutputArrayFromMat($matVt)
    EndIf

    _cveSVDecomp($iArrSrc, $oArrW, $oArrU, $oArrVt, $flags)

    If $bVtIsArray Then
        _VectorOfMatRelease($vectorOfMatVt)
    EndIf

    _cveOutputArrayRelease($oArrVt)

    If $bUIsArray Then
        _VectorOfMatRelease($vectorOfMatU)
    EndIf

    _cveOutputArrayRelease($oArrU)

    If $bWIsArray Then
        _VectorOfMatRelease($vectorOfMatW)
    EndIf

    _cveOutputArrayRelease($oArrW)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSVDecompMat

Func _cveSVBackSubst($w, $u, $vt, $rhs, $dst)
    ; CVAPI(void) cveSVBackSubst(cv::_InputArray* w, cv::_InputArray* u, cv::_InputArray* vt, cv::_InputArray* rhs, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVBackSubst", "ptr", $w, "ptr", $u, "ptr", $vt, "ptr", $rhs, "ptr", $dst), "cveSVBackSubst", @error)
EndFunc   ;==>_cveSVBackSubst

Func _cveSVBackSubstMat($matW, $matU, $matVt, $matRhs, $matDst)
    ; cveSVBackSubst using cv::Mat instead of _*Array

    Local $iArrW, $vectorOfMatW, $iArrWSize
    Local $bWIsArray = VarGetType($matW) == "Array"

    If $bWIsArray Then
        $vectorOfMatW = _VectorOfMatCreate()

        $iArrWSize = UBound($matW)
        For $i = 0 To $iArrWSize - 1
            _VectorOfMatPush($vectorOfMatW, $matW[$i])
        Next

        $iArrW = _cveInputArrayFromVectorOfMat($vectorOfMatW)
    Else
        $iArrW = _cveInputArrayFromMat($matW)
    EndIf

    Local $iArrU, $vectorOfMatU, $iArrUSize
    Local $bUIsArray = VarGetType($matU) == "Array"

    If $bUIsArray Then
        $vectorOfMatU = _VectorOfMatCreate()

        $iArrUSize = UBound($matU)
        For $i = 0 To $iArrUSize - 1
            _VectorOfMatPush($vectorOfMatU, $matU[$i])
        Next

        $iArrU = _cveInputArrayFromVectorOfMat($vectorOfMatU)
    Else
        $iArrU = _cveInputArrayFromMat($matU)
    EndIf

    Local $iArrVt, $vectorOfMatVt, $iArrVtSize
    Local $bVtIsArray = VarGetType($matVt) == "Array"

    If $bVtIsArray Then
        $vectorOfMatVt = _VectorOfMatCreate()

        $iArrVtSize = UBound($matVt)
        For $i = 0 To $iArrVtSize - 1
            _VectorOfMatPush($vectorOfMatVt, $matVt[$i])
        Next

        $iArrVt = _cveInputArrayFromVectorOfMat($vectorOfMatVt)
    Else
        $iArrVt = _cveInputArrayFromMat($matVt)
    EndIf

    Local $iArrRhs, $vectorOfMatRhs, $iArrRhsSize
    Local $bRhsIsArray = VarGetType($matRhs) == "Array"

    If $bRhsIsArray Then
        $vectorOfMatRhs = _VectorOfMatCreate()

        $iArrRhsSize = UBound($matRhs)
        For $i = 0 To $iArrRhsSize - 1
            _VectorOfMatPush($vectorOfMatRhs, $matRhs[$i])
        Next

        $iArrRhs = _cveInputArrayFromVectorOfMat($vectorOfMatRhs)
    Else
        $iArrRhs = _cveInputArrayFromMat($matRhs)
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

    _cveSVBackSubst($iArrW, $iArrU, $iArrVt, $iArrRhs, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bRhsIsArray Then
        _VectorOfMatRelease($vectorOfMatRhs)
    EndIf

    _cveInputArrayRelease($iArrRhs)

    If $bVtIsArray Then
        _VectorOfMatRelease($vectorOfMatVt)
    EndIf

    _cveInputArrayRelease($iArrVt)

    If $bUIsArray Then
        _VectorOfMatRelease($vectorOfMatU)
    EndIf

    _cveInputArrayRelease($iArrU)

    If $bWIsArray Then
        _VectorOfMatRelease($vectorOfMatW)
    EndIf

    _cveInputArrayRelease($iArrW)
EndFunc   ;==>_cveSVBackSubstMat

Func _cvePCACompute1($data, $mean, $eigenvectors, $maxComponents)
    ; CVAPI(void) cvePCACompute1(cv::_InputArray* data, cv::_InputOutputArray* mean, cv::_OutputArray* eigenvectors, int maxComponents);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCACompute1", "ptr", $data, "ptr", $mean, "ptr", $eigenvectors, "int", $maxComponents), "cvePCACompute1", @error)
EndFunc   ;==>_cvePCACompute1

Func _cvePCACompute1Mat($matData, $matMean, $matEigenvectors, $maxComponents)
    ; cvePCACompute1 using cv::Mat instead of _*Array

    Local $iArrData, $vectorOfMatData, $iArrDataSize
    Local $bDataIsArray = VarGetType($matData) == "Array"

    If $bDataIsArray Then
        $vectorOfMatData = _VectorOfMatCreate()

        $iArrDataSize = UBound($matData)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfMatPush($vectorOfMatData, $matData[$i])
        Next

        $iArrData = _cveInputArrayFromVectorOfMat($vectorOfMatData)
    Else
        $iArrData = _cveInputArrayFromMat($matData)
    EndIf

    Local $ioArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $ioArrMean = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $ioArrMean = _cveInputOutputArrayFromMat($matMean)
    EndIf

    Local $oArrEigenvectors, $vectorOfMatEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = VarGetType($matEigenvectors) == "Array"

    If $bEigenvectorsIsArray Then
        $vectorOfMatEigenvectors = _VectorOfMatCreate()

        $iArrEigenvectorsSize = UBound($matEigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            _VectorOfMatPush($vectorOfMatEigenvectors, $matEigenvectors[$i])
        Next

        $oArrEigenvectors = _cveOutputArrayFromVectorOfMat($vectorOfMatEigenvectors)
    Else
        $oArrEigenvectors = _cveOutputArrayFromMat($matEigenvectors)
    EndIf

    _cvePCACompute1($iArrData, $ioArrMean, $oArrEigenvectors, $maxComponents)

    If $bEigenvectorsIsArray Then
        _VectorOfMatRelease($vectorOfMatEigenvectors)
    EndIf

    _cveOutputArrayRelease($oArrEigenvectors)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveInputOutputArrayRelease($ioArrMean)

    If $bDataIsArray Then
        _VectorOfMatRelease($vectorOfMatData)
    EndIf

    _cveInputArrayRelease($iArrData)
EndFunc   ;==>_cvePCACompute1Mat

Func _cvePCACompute2($data, $mean, $eigenvectors, $retainedVariance)
    ; CVAPI(void) cvePCACompute2(cv::_InputArray* data, cv::_InputOutputArray* mean, cv::_OutputArray* eigenvectors, double retainedVariance);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCACompute2", "ptr", $data, "ptr", $mean, "ptr", $eigenvectors, "double", $retainedVariance), "cvePCACompute2", @error)
EndFunc   ;==>_cvePCACompute2

Func _cvePCACompute2Mat($matData, $matMean, $matEigenvectors, $retainedVariance)
    ; cvePCACompute2 using cv::Mat instead of _*Array

    Local $iArrData, $vectorOfMatData, $iArrDataSize
    Local $bDataIsArray = VarGetType($matData) == "Array"

    If $bDataIsArray Then
        $vectorOfMatData = _VectorOfMatCreate()

        $iArrDataSize = UBound($matData)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfMatPush($vectorOfMatData, $matData[$i])
        Next

        $iArrData = _cveInputArrayFromVectorOfMat($vectorOfMatData)
    Else
        $iArrData = _cveInputArrayFromMat($matData)
    EndIf

    Local $ioArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $ioArrMean = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $ioArrMean = _cveInputOutputArrayFromMat($matMean)
    EndIf

    Local $oArrEigenvectors, $vectorOfMatEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = VarGetType($matEigenvectors) == "Array"

    If $bEigenvectorsIsArray Then
        $vectorOfMatEigenvectors = _VectorOfMatCreate()

        $iArrEigenvectorsSize = UBound($matEigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            _VectorOfMatPush($vectorOfMatEigenvectors, $matEigenvectors[$i])
        Next

        $oArrEigenvectors = _cveOutputArrayFromVectorOfMat($vectorOfMatEigenvectors)
    Else
        $oArrEigenvectors = _cveOutputArrayFromMat($matEigenvectors)
    EndIf

    _cvePCACompute2($iArrData, $ioArrMean, $oArrEigenvectors, $retainedVariance)

    If $bEigenvectorsIsArray Then
        _VectorOfMatRelease($vectorOfMatEigenvectors)
    EndIf

    _cveOutputArrayRelease($oArrEigenvectors)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveInputOutputArrayRelease($ioArrMean)

    If $bDataIsArray Then
        _VectorOfMatRelease($vectorOfMatData)
    EndIf

    _cveInputArrayRelease($iArrData)
EndFunc   ;==>_cvePCACompute2Mat

Func _cvePCAProject($data, $mean, $eigenvectors, $result)
    ; CVAPI(void) cvePCAProject(cv::_InputArray* data, cv::_InputArray* mean, cv::_InputArray* eigenvectors, cv::_OutputArray* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCAProject", "ptr", $data, "ptr", $mean, "ptr", $eigenvectors, "ptr", $result), "cvePCAProject", @error)
EndFunc   ;==>_cvePCAProject

Func _cvePCAProjectMat($matData, $matMean, $matEigenvectors, $matResult)
    ; cvePCAProject using cv::Mat instead of _*Array

    Local $iArrData, $vectorOfMatData, $iArrDataSize
    Local $bDataIsArray = VarGetType($matData) == "Array"

    If $bDataIsArray Then
        $vectorOfMatData = _VectorOfMatCreate()

        $iArrDataSize = UBound($matData)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfMatPush($vectorOfMatData, $matData[$i])
        Next

        $iArrData = _cveInputArrayFromVectorOfMat($vectorOfMatData)
    Else
        $iArrData = _cveInputArrayFromMat($matData)
    EndIf

    Local $iArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $iArrMean = _cveInputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $iArrMean = _cveInputArrayFromMat($matMean)
    EndIf

    Local $iArrEigenvectors, $vectorOfMatEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = VarGetType($matEigenvectors) == "Array"

    If $bEigenvectorsIsArray Then
        $vectorOfMatEigenvectors = _VectorOfMatCreate()

        $iArrEigenvectorsSize = UBound($matEigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            _VectorOfMatPush($vectorOfMatEigenvectors, $matEigenvectors[$i])
        Next

        $iArrEigenvectors = _cveInputArrayFromVectorOfMat($vectorOfMatEigenvectors)
    Else
        $iArrEigenvectors = _cveInputArrayFromMat($matEigenvectors)
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

    _cvePCAProject($iArrData, $iArrMean, $iArrEigenvectors, $oArrResult)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bEigenvectorsIsArray Then
        _VectorOfMatRelease($vectorOfMatEigenvectors)
    EndIf

    _cveInputArrayRelease($iArrEigenvectors)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveInputArrayRelease($iArrMean)

    If $bDataIsArray Then
        _VectorOfMatRelease($vectorOfMatData)
    EndIf

    _cveInputArrayRelease($iArrData)
EndFunc   ;==>_cvePCAProjectMat

Func _cvePCABackProject($data, $mean, $eigenvectors, $result)
    ; CVAPI(void) cvePCABackProject(cv::_InputArray* data, cv::_InputArray* mean, cv::_InputArray* eigenvectors, cv::_OutputArray* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCABackProject", "ptr", $data, "ptr", $mean, "ptr", $eigenvectors, "ptr", $result), "cvePCABackProject", @error)
EndFunc   ;==>_cvePCABackProject

Func _cvePCABackProjectMat($matData, $matMean, $matEigenvectors, $matResult)
    ; cvePCABackProject using cv::Mat instead of _*Array

    Local $iArrData, $vectorOfMatData, $iArrDataSize
    Local $bDataIsArray = VarGetType($matData) == "Array"

    If $bDataIsArray Then
        $vectorOfMatData = _VectorOfMatCreate()

        $iArrDataSize = UBound($matData)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfMatPush($vectorOfMatData, $matData[$i])
        Next

        $iArrData = _cveInputArrayFromVectorOfMat($vectorOfMatData)
    Else
        $iArrData = _cveInputArrayFromMat($matData)
    EndIf

    Local $iArrMean, $vectorOfMatMean, $iArrMeanSize
    Local $bMeanIsArray = VarGetType($matMean) == "Array"

    If $bMeanIsArray Then
        $vectorOfMatMean = _VectorOfMatCreate()

        $iArrMeanSize = UBound($matMean)
        For $i = 0 To $iArrMeanSize - 1
            _VectorOfMatPush($vectorOfMatMean, $matMean[$i])
        Next

        $iArrMean = _cveInputArrayFromVectorOfMat($vectorOfMatMean)
    Else
        $iArrMean = _cveInputArrayFromMat($matMean)
    EndIf

    Local $iArrEigenvectors, $vectorOfMatEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = VarGetType($matEigenvectors) == "Array"

    If $bEigenvectorsIsArray Then
        $vectorOfMatEigenvectors = _VectorOfMatCreate()

        $iArrEigenvectorsSize = UBound($matEigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            _VectorOfMatPush($vectorOfMatEigenvectors, $matEigenvectors[$i])
        Next

        $iArrEigenvectors = _cveInputArrayFromVectorOfMat($vectorOfMatEigenvectors)
    Else
        $iArrEigenvectors = _cveInputArrayFromMat($matEigenvectors)
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

    _cvePCABackProject($iArrData, $iArrMean, $iArrEigenvectors, $oArrResult)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bEigenvectorsIsArray Then
        _VectorOfMatRelease($vectorOfMatEigenvectors)
    EndIf

    _cveInputArrayRelease($iArrEigenvectors)

    If $bMeanIsArray Then
        _VectorOfMatRelease($vectorOfMatMean)
    EndIf

    _cveInputArrayRelease($iArrMean)

    If $bDataIsArray Then
        _VectorOfMatRelease($vectorOfMatData)
    EndIf

    _cveInputArrayRelease($iArrData)
EndFunc   ;==>_cvePCABackProjectMat

Func _cveGetRangeAll($range)
    ; CVAPI(void) cveGetRangeAll(cv::Range* range);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRangeAll", "ptr", $range), "cveGetRangeAll", @error)
EndFunc   ;==>_cveGetRangeAll

Func _cveAffine3dCreate()
    ; CVAPI(cv::Affine3d*) cveAffine3dCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffine3dCreate"), "cveAffine3dCreate", @error)
EndFunc   ;==>_cveAffine3dCreate

Func _cveAffine3dGetIdentity()
    ; CVAPI(cv::Affine3d*) cveAffine3dGetIdentity();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffine3dGetIdentity"), "cveAffine3dGetIdentity", @error)
EndFunc   ;==>_cveAffine3dGetIdentity

Func _cveAffine3dRotate($affine, $r0, $r1, $r2)
    ; CVAPI(cv::Affine3d*) cveAffine3dRotate(cv::Affine3d* affine, double r0, double r1, double r2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffine3dRotate", "ptr", $affine, "double", $r0, "double", $r1, "double", $r2), "cveAffine3dRotate", @error)
EndFunc   ;==>_cveAffine3dRotate

Func _cveAffine3dTranslate($affine, $t0, $t1, $t2)
    ; CVAPI(cv::Affine3d*) cveAffine3dTranslate(cv::Affine3d* affine, double t0, double t1, double t2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffine3dTranslate", "ptr", $affine, "double", $t0, "double", $t1, "double", $t2), "cveAffine3dTranslate", @error)
EndFunc   ;==>_cveAffine3dTranslate

Func _cveAffine3dGetValues($affine, $values)
    ; CVAPI(void) cveAffine3dGetValues(cv::Affine3d* affine, double* values);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffine3dGetValues", "ptr", $affine, "struct*", $values), "cveAffine3dGetValues", @error)
EndFunc   ;==>_cveAffine3dGetValues

Func _cveAffine3dRelease($affine)
    ; CVAPI(void) cveAffine3dRelease(cv::Affine3d** affine);

    Local $bAffineDllType
    If VarGetType($affine) == "DLLStruct" Then
        $bAffineDllType = "struct*"
    Else
        $bAffineDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffine3dRelease", $bAffineDllType, $affine), "cveAffine3dRelease", @error)
EndFunc   ;==>_cveAffine3dRelease

Func _cveRngCreate()
    ; CVAPI(cv::RNG*) cveRngCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRngCreate"), "cveRngCreate", @error)
EndFunc   ;==>_cveRngCreate

Func _cveRngCreateWithSeed($state)
    ; CVAPI(cv::RNG*) cveRngCreateWithSeed(uint64 state);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRngCreateWithSeed", "uint64", $state), "cveRngCreateWithSeed", @error)
EndFunc   ;==>_cveRngCreateWithSeed

Func _cveRngFill($rng, $mat, $distType, $a, $b, $saturateRange)
    ; CVAPI(void) cveRngFill(cv::RNG* rng, cv::_InputOutputArray* mat, int distType, cv::_InputArray* a, cv::_InputArray* b, bool saturateRange);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRngFill", "ptr", $rng, "ptr", $mat, "int", $distType, "ptr", $a, "ptr", $b, "boolean", $saturateRange), "cveRngFill", @error)
EndFunc   ;==>_cveRngFill

Func _cveRngFillMat($rng, $matMat, $distType, $matA, $matB, $saturateRange)
    ; cveRngFill using cv::Mat instead of _*Array

    Local $ioArrMat, $vectorOfMatMat, $iArrMatSize
    Local $bMatIsArray = VarGetType($matMat) == "Array"

    If $bMatIsArray Then
        $vectorOfMatMat = _VectorOfMatCreate()

        $iArrMatSize = UBound($matMat)
        For $i = 0 To $iArrMatSize - 1
            _VectorOfMatPush($vectorOfMatMat, $matMat[$i])
        Next

        $ioArrMat = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMat)
    Else
        $ioArrMat = _cveInputOutputArrayFromMat($matMat)
    EndIf

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

    _cveRngFill($rng, $ioArrMat, $distType, $iArrA, $iArrB, $saturateRange)

    If $bBIsArray Then
        _VectorOfMatRelease($vectorOfMatB)
    EndIf

    _cveInputArrayRelease($iArrB)

    If $bAIsArray Then
        _VectorOfMatRelease($vectorOfMatA)
    EndIf

    _cveInputArrayRelease($iArrA)

    If $bMatIsArray Then
        _VectorOfMatRelease($vectorOfMatMat)
    EndIf

    _cveInputOutputArrayRelease($ioArrMat)
EndFunc   ;==>_cveRngFillMat

Func _cveRngGaussian($rng, $sigma)
    ; CVAPI(double) cveRngGaussian(cv::RNG* rng, double sigma);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveRngGaussian", "ptr", $rng, "double", $sigma), "cveRngGaussian", @error)
EndFunc   ;==>_cveRngGaussian

Func _cveRngNext($rng)
    ; CVAPI(unsigned) cveRngNext(cv::RNG* rng);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveRngNext", "ptr", $rng), "cveRngNext", @error)
EndFunc   ;==>_cveRngNext

Func _cveRngUniformInt($rng, $a, $b)
    ; CVAPI(int) cveRngUniformInt(cv::RNG* rng, int a, int b);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRngUniformInt", "ptr", $rng, "int", $a, "int", $b), "cveRngUniformInt", @error)
EndFunc   ;==>_cveRngUniformInt

Func _cveRngUniformFloat($rng, $a, $b)
    ; CVAPI(float) cveRngUniformFloat(cv::RNG* rng, float a, float b);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRngUniformFloat", "ptr", $rng, "float", $a, "float", $b), "cveRngUniformFloat", @error)
EndFunc   ;==>_cveRngUniformFloat

Func _cveRngUniformDouble($rng, $a, $b)
    ; CVAPI(double) cveRngUniformDouble(cv::RNG* rng, double a, double b);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveRngUniformDouble", "ptr", $rng, "double", $a, "double", $b), "cveRngUniformDouble", @error)
EndFunc   ;==>_cveRngUniformDouble

Func _cveRngRelease($rng)
    ; CVAPI(void) cveRngRelease(cv::RNG** rng);

    Local $bRngDllType
    If VarGetType($rng) == "DLLStruct" Then
        $bRngDllType = "struct*"
    Else
        $bRngDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRngRelease", $bRngDllType, $rng), "cveRngRelease", @error)
EndFunc   ;==>_cveRngRelease

Func _cveMomentsCreate()
    ; CVAPI(cv::Moments*) cveMomentsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMomentsCreate"), "cveMomentsCreate", @error)
EndFunc   ;==>_cveMomentsCreate

Func _cveMomentsRelease($moments)
    ; CVAPI(void) cveMomentsRelease(cv::Moments** moments);

    Local $bMomentsDllType
    If VarGetType($moments) == "DLLStruct" Then
        $bMomentsDllType = "struct*"
    Else
        $bMomentsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsRelease", $bMomentsDllType, $moments), "cveMomentsRelease", @error)
EndFunc   ;==>_cveMomentsRelease

Func _cveGetConfigDict($key, $value)
    ; CVAPI(void) cveGetConfigDict(std::vector<cv::String>* key, std::vector<double>* value);

    Local $vecKey, $iArrKeySize
    Local $bKeyIsArray = VarGetType($key) == "Array"

    If $bKeyIsArray Then
        $vecKey = _VectorOfCvStringCreate()

        $iArrKeySize = UBound($key)
        For $i = 0 To $iArrKeySize - 1
            _VectorOfCvStringPush($vecKey, $key[$i])
        Next
    Else
        $vecKey = $key
    EndIf

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfDoubleCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfDoublePush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetConfigDict", "ptr", $vecKey, "ptr", $vecValue), "cveGetConfigDict", @error)

    If $bValueIsArray Then
        _VectorOfDoubleRelease($vecValue)
    EndIf

    If $bKeyIsArray Then
        _VectorOfCvStringRelease($vecKey)
    EndIf
EndFunc   ;==>_cveGetConfigDict