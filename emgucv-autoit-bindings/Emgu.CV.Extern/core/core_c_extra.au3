#include-once
#include "..\..\CVEUtils.au3"

Func _cveRedirectError($error_handler, $userdata, $prev_userdata)
    ; CVAPI(CvErrorCallback) cveRedirectError(CvErrorCallback error_handler, void* userdata, void** prev_userdata);

    Local $sUserdataDllType
    If IsDllStruct($userdata) Then
        $sUserdataDllType = "struct*"
    Else
        $sUserdataDllType = "ptr"
    EndIf

    Local $sPrev_userdataDllType
    If IsDllStruct($prev_userdata) Then
        $sPrev_userdataDllType = "struct*"
    ElseIf $prev_userdata == Null Then
        $sPrev_userdataDllType = "ptr"
    Else
        $sPrev_userdataDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRedirectError", "ptr", $error_handler, $sUserdataDllType, $userdata, $sPrev_userdataDllType, $prev_userdata), "cveRedirectError", @error)
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

    Local $sBackendNameDllType
    If IsDllStruct($backendName) Then
        $sBackendNameDllType = "struct*"
    Else
        $sBackendNameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSetParallelForBackend", $sBackendNameDllType, $backendName, "boolean", $propagateNumThreads), "cveSetParallelForBackend", @error)

    If $bBackendNameIsString Then
        _cveStringRelease($backendName)
    EndIf

    Return $retval
EndFunc   ;==>_cveSetParallelForBackend

Func _cveGetParallelBackends($backendNames)
    ; CVAPI(void) cveGetParallelBackends(std::vector<cv::String>* backendNames);

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

    Local $sBackendNamesDllType
    If IsDllStruct($backendNames) Then
        $sBackendNamesDllType = "struct*"
    Else
        $sBackendNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetParallelBackends", $sBackendNamesDllType, $vecBackendNames), "cveGetParallelBackends", @error)

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

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    ElseIf IsPtr($c) Then
        $sCDllType = "ptr"
    Else
        $sCDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStringCreateFromStr", $sCDllType, $c), "cveStringCreateFromStr", @error)
EndFunc   ;==>_cveStringCreateFromStr

Func _cveStringGetCStr($string, $c, $size)
    ; CVAPI(void) cveStringGetCStr(cv::String* string, const char** c, int* size);

    Local $bStringIsString = VarGetType($string) == "String"
    If $bStringIsString Then
        $string = _cveStringCreateFromStr($string)
    EndIf

    Local $sStringDllType
    If IsDllStruct($string) Then
        $sStringDllType = "struct*"
    Else
        $sStringDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    ElseIf $c == Null Then
        $sCDllType = "ptr"
    Else
        $sCDllType = "ptr*"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStringGetCStr", $sStringDllType, $string, $sCDllType, $c, $sSizeDllType, $size), "cveStringGetCStr", @error)

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

    Local $sStringDllType
    If IsDllStruct($string) Then
        $sStringDllType = "struct*"
    Else
        $sStringDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStringGetLength", $sStringDllType, $string), "cveStringGetLength", @error)

    If $bStringIsString Then
        _cveStringRelease($string)
    EndIf

    Return $retval
EndFunc   ;==>_cveStringGetLength

Func _cveStringRelease($string)
    ; CVAPI(void) cveStringRelease(cv::String** string);

    Local $sStringDllType
    If IsDllStruct($string) Then
        $sStringDllType = "struct*"
    ElseIf $string == Null Then
        $sStringDllType = "ptr"
    Else
        $sStringDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStringRelease", $sStringDllType, $string), "cveStringRelease", @error)
EndFunc   ;==>_cveStringRelease

Func _cveInputArrayFromDouble($scalar)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromDouble(double* scalar);

    Local $sScalarDllType
    If IsDllStruct($scalar) Then
        $sScalarDllType = "struct*"
    Else
        $sScalarDllType = "double*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromDouble", $sScalarDllType, $scalar), "cveInputArrayFromDouble", @error)
EndFunc   ;==>_cveInputArrayFromDouble

Func _cveInputArrayFromScalar($scalar)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromScalar(cv::Scalar* scalar);

    Local $sScalarDllType
    If IsDllStruct($scalar) Then
        $sScalarDllType = "struct*"
    Else
        $sScalarDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromScalar", $sScalarDllType, $scalar), "cveInputArrayFromScalar", @error)
EndFunc   ;==>_cveInputArrayFromScalar

Func _cveInputArrayFromMat($mat)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromMat(cv::Mat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromMat", $sMatDllType, $mat), "cveInputArrayFromMat", @error)
EndFunc   ;==>_cveInputArrayFromMat

Func _cveInputArrayFromGpuMat($mat)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromGpuMat(cv::cuda::GpuMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromGpuMat", $sMatDllType, $mat), "cveInputArrayFromGpuMat", @error)
EndFunc   ;==>_cveInputArrayFromGpuMat

Func _cveInputArrayFromUMat($mat)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromUMat(cv::UMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromUMat", $sMatDllType, $mat), "cveInputArrayFromUMat", @error)
EndFunc   ;==>_cveInputArrayFromUMat

Func _cveInputArrayGetDims($ia, $i)
    ; CVAPI(int) cveInputArrayGetDims(cv::_InputArray* ia, int i);

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayGetDims", $sIaDllType, $ia, "int", $i), "cveInputArrayGetDims", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetSize", $sIaDllType, $ia, $sSizeDllType, $size, "int", $idx), "cveInputArrayGetSize", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayGetDepth", $sIaDllType, $ia, "int", $idx), "cveInputArrayGetDepth", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveInputArrayGetChannels", $sIaDllType, $ia, "int", $idx), "cveInputArrayGetChannels", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveInputArrayIsEmpty", $sIaDllType, $ia), "cveInputArrayIsEmpty", @error)
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

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    ElseIf $arr == Null Then
        $sArrDllType = "ptr"
    Else
        $sArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayRelease", $sArrDllType, $arr), "cveInputArrayRelease", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetMat", $sIaDllType, $ia, "int", $idx, $sMatDllType, $mat), "cveInputArrayGetMat", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf

    Local $sUmatDllType
    If IsDllStruct($umat) Then
        $sUmatDllType = "struct*"
    Else
        $sUmatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetUMat", $sIaDllType, $ia, "int", $idx, $sUmatDllType, $umat), "cveInputArrayGetUMat", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayGetGpuMat", $sIaDllType, $ia, $sGpuMatDllType, $gpuMat), "cveInputArrayGetGpuMat", @error)
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

    Local $sIaDllType
    If IsDllStruct($ia) Then
        $sIaDllType = "struct*"
    Else
        $sIaDllType = "ptr"
    EndIf

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputArrayCopyTo", $sIaDllType, $ia, $sArrDllType, $arr, $sMaskDllType, $mask), "cveInputArrayCopyTo", @error)
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

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromMat", $sMatDllType, $mat), "cveOutputArrayFromMat", @error)
EndFunc   ;==>_cveOutputArrayFromMat

Func _cveOutputArrayFromGpuMat($mat)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromGpuMat(cv::cuda::GpuMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromGpuMat", $sMatDllType, $mat), "cveOutputArrayFromGpuMat", @error)
EndFunc   ;==>_cveOutputArrayFromGpuMat

Func _cveOutputArrayFromUMat($mat)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromUMat(cv::UMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromUMat", $sMatDllType, $mat), "cveOutputArrayFromUMat", @error)
EndFunc   ;==>_cveOutputArrayFromUMat

Func _cveOutputArrayRelease($arr)
    ; CVAPI(void) cveOutputArrayRelease(cv::_OutputArray** arr);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    ElseIf $arr == Null Then
        $sArrDllType = "ptr"
    Else
        $sArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOutputArrayRelease", $sArrDllType, $arr), "cveOutputArrayRelease", @error)
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

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromMat", $sMatDllType, $mat), "cveInputOutputArrayFromMat", @error)
EndFunc   ;==>_cveInputOutputArrayFromMat

Func _cveInputOutputArrayFromUMat($mat)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromUMat(cv::UMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromUMat", $sMatDllType, $mat), "cveInputOutputArrayFromUMat", @error)
EndFunc   ;==>_cveInputOutputArrayFromUMat

Func _cveInputOutputArrayFromGpuMat($mat)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromGpuMat(cv::cuda::GpuMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromGpuMat", $sMatDllType, $mat), "cveInputOutputArrayFromGpuMat", @error)
EndFunc   ;==>_cveInputOutputArrayFromGpuMat

Func _cveInputOutputArrayRelease($arr)
    ; CVAPI(void) cveInputOutputArrayRelease(cv::_InputOutputArray** arr);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    ElseIf $arr == Null Then
        $sArrDllType = "ptr"
    Else
        $sArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputOutputArrayRelease", $sArrDllType, $arr), "cveInputOutputArrayRelease", @error)
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

    Local $sScalarDllType
    If IsDllStruct($scalar) Then
        $sScalarDllType = "struct*"
    Else
        $sScalarDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveScalarCreate", $sScalarDllType, $scalar), "cveScalarCreate", @error)
EndFunc   ;==>_cveScalarCreate

Func _cveScalarRelease($scalar)
    ; CVAPI(void) cveScalarRelease(cv::Scalar** scalar);

    Local $sScalarDllType
    If IsDllStruct($scalar) Then
        $sScalarDllType = "struct*"
    ElseIf $scalar == Null Then
        $sScalarDllType = "ptr"
    Else
        $sScalarDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScalarRelease", $sScalarDllType, $scalar), "cveScalarRelease", @error)
EndFunc   ;==>_cveScalarRelease

Func _cveMinMaxIdx($src, $minVal, $maxVal, $minIdx, $maxIdx, $mask)
    ; CVAPI(void) cveMinMaxIdx(cv::_InputArray* src, double* minVal, double* maxVal, int* minIdx, int* maxIdx, cv::_InputArray* mask);

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

    Local $sMinIdxDllType
    If IsDllStruct($minIdx) Then
        $sMinIdxDllType = "struct*"
    Else
        $sMinIdxDllType = "int*"
    EndIf

    Local $sMaxIdxDllType
    If IsDllStruct($maxIdx) Then
        $sMaxIdxDllType = "struct*"
    Else
        $sMaxIdxDllType = "int*"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinMaxIdx", $sSrcDllType, $src, $sMinValDllType, $minVal, $sMaxValDllType, $maxVal, $sMinIdxDllType, $minIdx, $sMaxIdxDllType, $maxIdx, $sMaskDllType, $mask), "cveMinMaxIdx", @error)
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

    Local $sMacLocDllType
    If IsDllStruct($macLoc) Then
        $sMacLocDllType = "struct*"
    Else
        $sMacLocDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinMaxLoc", $sSrcDllType, $src, $sMinValDllType, $minVal, $sMaxValDllType, $maxVal, $sMinLocDllType, $minLoc, $sMacLocDllType, $macLoc, $sMaskDllType, $mask), "cveMinMaxLoc", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseAnd", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask), "cveBitwiseAnd", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseNot", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask), "cveBitwiseNot", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseOr", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask), "cveBitwiseOr", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBitwiseXor", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask), "cveBitwiseXor", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAdd", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask, "int", $dtype), "cveAdd", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubtract", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask, "int", $dtype), "cveSubtract", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDivide", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "double", $scale, "int", $dtype), "cveDivide", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiply", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "double", $scale, "int", $dtype), "cveMultiply", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCountNonZero", $sSrcDllType, $src), "cveCountNonZero", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sIdxDllType
    If IsDllStruct($idx) Then
        $sIdxDllType = "struct*"
    Else
        $sIdxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindNonZero", $sSrcDllType, $src, $sIdxDllType, $idx), "cveFindNonZero", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMin", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst), "cveMin", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMax", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst), "cveMax", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAbsDiff", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst), "cveAbsDiff", @error)
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

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInRange", $sSrc1DllType, $src1, $sLowerbDllType, $lowerb, $sUpperbDllType, $upperb, $sDstDllType, $dst), "cveInRange", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSqrt", $sSrcDllType, $src, $sDstDllType, $dst), "cveSqrt", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompare", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "int", $compop), "cveCompare", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlip", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flipCode), "cveFlip", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRotate", $sSrcDllType, $src, $sDstDllType, $dst, "int", $rotateCode), "cveRotate", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTranspose", $sSrcDllType, $src, $sDstDllType, $dst), "cveTranspose", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sLutDllType
    If IsDllStruct($lut) Then
        $sLutDllType = "struct*"
    Else
        $sLutDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLUT", $sSrcDllType, $src, $sLutDllType, $lut, $sDstDllType, $dst), "cveLUT", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSum", $sSrcDllType, $src, $sResultDllType, $result), "cveSum", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMean", $sSrcDllType, $src, $sMaskDllType, $mask, $sResultDllType, $result), "cveMean", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMeanStdDev", $sSrcDllType, $src, $sMeanDllType, $mean, $sStddevDllType, $stddev, $sMaskDllType, $mask), "cveMeanStdDev", @error)
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

    Local $sMtxDllType
    If IsDllStruct($mtx) Then
        $sMtxDllType = "struct*"
    Else
        $sMtxDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrace", $sMtxDllType, $mtx, $sResultDllType, $result), "cveTrace", @error)
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

    Local $sMtxDllType
    If IsDllStruct($mtx) Then
        $sMtxDllType = "struct*"
    Else
        $sMtxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDeterminant", $sMtxDllType, $mtx), "cveDeterminant", @error)
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

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveNorm", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "int", $normType, $sMaskDllType, $mask), "cveNorm", @error)
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

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sIndexDllType
    If IsDllStruct($index) Then
        $sIndexDllType = "struct*"
    Else
        $sIndexDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCheckRange", $sArrDllType, $arr, "boolean", $quiet, $sIndexDllType, $index, "double", $minVal, "double", $maxVal), "cveCheckRange", @error)
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

    Local $sADllType
    If IsDllStruct($a) Then
        $sADllType = "struct*"
    Else
        $sADllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePatchNaNs", $sADllType, $a, "double", $val), "cvePatchNaNs", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGemm", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "double", $alpha, $sSrc3DllType, $src3, "double", $beta, $sDstDllType, $dst, "int", $flags), "cveGemm", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScaleAdd", $sSrc1DllType, $src1, "double", $alpha, $sSrc2DllType, $src2, $sDstDllType, $dst), "cveScaleAdd", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAddWeighted", $sSrc1DllType, $src1, "double", $alpha, $sSrc2DllType, $src2, "double", $beta, "double", $gamma, $sDstDllType, $dst, "int", $dtype), "cveAddWeighted", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertScaleAbs", $sSrcDllType, $src, $sDstDllType, $dst, "double", $alpha, "double", $beta), "cveConvertScaleAbs", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReduce", $sSrcDllType, $src, $sDstDllType, $dst, "int", $dim, "int", $rtype, "int", $dtype), "cveReduce", @error)
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

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRandShuffle", $sDstDllType, $dst, "double", $iterFactor, "uint64", $rng), "cveRandShuffle", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePow", $sSrcDllType, $src, "double", $power, $sDstDllType, $dst), "cvePow", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExp", $sSrcDllType, $src, $sDstDllType, $dst), "cveExp", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLog", $sSrcDllType, $src, $sDstDllType, $dst), "cveLog", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCartToPolar", $sXDllType, $x, $sYDllType, $y, $sMagnitudeDllType, $magnitude, $sAngleDllType, $angle, "boolean", $angleInDegrees), "cveCartToPolar", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePolarToCart", $sMagnitudeDllType, $magnitude, $sAngleDllType, $angle, $sXDllType, $x, $sYDllType, $y, "boolean", $angleInDegrees), "cvePolarToCart", @error)
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

    Local $sMtxDllType
    If IsDllStruct($mtx) Then
        $sMtxDllType = "struct*"
    Else
        $sMtxDllType = "ptr"
    EndIf

    Local $sScalarDllType
    If IsDllStruct($scalar) Then
        $sScalarDllType = "struct*"
    Else
        $sScalarDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetIdentity", $sMtxDllType, $mtx, $sScalarDllType, $scalar), "cveSetIdentity", @error)
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

    Local $sCoeffsDllType
    If IsDllStruct($coeffs) Then
        $sCoeffsDllType = "struct*"
    Else
        $sCoeffsDllType = "ptr"
    EndIf

    Local $sRootsDllType
    If IsDllStruct($roots) Then
        $sRootsDllType = "struct*"
    Else
        $sRootsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveCubic", $sCoeffsDllType, $coeffs, $sRootsDllType, $roots), "cveSolveCubic", @error)
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

    Local $sCoeffsDllType
    If IsDllStruct($coeffs) Then
        $sCoeffsDllType = "struct*"
    Else
        $sCoeffsDllType = "ptr"
    EndIf

    Local $sRootsDllType
    If IsDllStruct($roots) Then
        $sRootsDllType = "struct*"
    Else
        $sRootsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSolvePoly", $sCoeffsDllType, $coeffs, $sRootsDllType, $roots, "int", $maxIters), "cveSolvePoly", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSolve", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, "int", $flags), "cveSolve", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSort", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flags), "cveSort", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSortIdx", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flags), "cveSortIdx", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInvert", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flags), "cveInvert", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDft", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flags, "int", $nonzeroRows), "cveDft", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDct", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flags), "cveDct", @error)
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
    ; CVAPI(void) cveMulSpectrums(cv::_InputArray* a, cv::_InputArray* b, cv::_OutputArray* c, int flags, bool conjB);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMulSpectrums", $sADllType, $a, $sBDllType, $b, $sCDllType, $c, "int", $flags, "boolean", $conjB), "cveMulSpectrums", @error)
EndFunc   ;==>_cveMulSpectrums

Func _cveMulSpectrumsMat($matA, $matB, $matC, $flags, $conjB = false)
    ; cveMulSpectrums using cv::Mat instead of _*Array

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

    _cveMulSpectrums($iArrA, $iArrB, $oArrC, $flags, $conjB)

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
EndFunc   ;==>_cveMulSpectrumsMat

Func _cveGetOptimalDFTSize($vecsize)
    ; CVAPI(int) cveGetOptimalDFTSize(int vecsize);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetOptimalDFTSize", "int", $vecsize), "cveGetOptimalDFTSize", @error)
EndFunc   ;==>_cveGetOptimalDFTSize

Func _cveTransform($src, $dst, $m)
    ; CVAPI(void) cveTransform(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m);

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

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTransform", $sSrcDllType, $src, $sDstDllType, $dst, $sMDllType, $m), "cveTransform", @error)
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

    Local $sV1DllType
    If IsDllStruct($v1) Then
        $sV1DllType = "struct*"
    Else
        $sV1DllType = "ptr"
    EndIf

    Local $sV2DllType
    If IsDllStruct($v2) Then
        $sV2DllType = "struct*"
    Else
        $sV2DllType = "ptr"
    EndIf

    Local $sIcovarDllType
    If IsDllStruct($icovar) Then
        $sIcovarDllType = "struct*"
    Else
        $sIcovarDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMahalanobis", $sV1DllType, $v1, $sV2DllType, $v2, $sIcovarDllType, $icovar), "cveMahalanobis", @error)
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

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sCovarDllType
    If IsDllStruct($covar) Then
        $sCovarDllType = "struct*"
    Else
        $sCovarDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcCovarMatrix", $sSamplesDllType, $samples, $sCovarDllType, $covar, $sMeanDllType, $mean, "int", $flags, "int", $ctype), "cveCalcCovarMatrix", @error)
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

Func _cveNormalize($src, $dst, $alpha, $beta, $normType, $dType = -1, $mask = _cveNoArray())
    ; CVAPI(void) cveNormalize(cv::_InputArray* src, cv::_InputOutputArray* dst, double alpha, double beta, int normType, int dType, cv::_InputArray* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNormalize", $sSrcDllType, $src, $sDstDllType, $dst, "double", $alpha, "double", $beta, "int", $normType, "int", $dType, $sMaskDllType, $mask), "cveNormalize", @error)
EndFunc   ;==>_cveNormalize

Func _cveNormalizeMat($matSrc, $matDst, $alpha, $beta, $normType, $dType = -1, $matMask = _cveNoArrayMat())
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

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePerspectiveTransform", $sSrcDllType, $src, $sDstDllType, $dst, $sMDllType, $m), "cvePerspectiveTransform", @error)
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

    Local $sDeltaDllType
    If IsDllStruct($delta) Then
        $sDeltaDllType = "struct*"
    Else
        $sDeltaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMulTransposed", $sSrcDllType, $src, $sDstDllType, $dst, "boolean", $aTa, $sDeltaDllType, $delta, "double", $scale, "int", $dtype), "cveMulTransposed", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMvDllType
    If IsDllStruct($mv) Then
        $sMvDllType = "struct*"
    Else
        $sMvDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSplit", $sSrcDllType, $src, $sMvDllType, $mv), "cveSplit", @error)
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

    Local $sMvDllType
    If IsDllStruct($mv) Then
        $sMvDllType = "struct*"
    Else
        $sMvDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMerge", $sMvDllType, $mv, $sDstDllType, $dst), "cveMerge", @error)
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

    Local $sFromToDllType
    If IsDllStruct($fromTo) Then
        $sFromToDllType = "struct*"
    Else
        $sFromToDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMixChannels", $sSrcDllType, $src, $sDstDllType, $dst, $sFromToDllType, $fromTo, "int", $npairs), "cveMixChannels", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExtractChannel", $sSrcDllType, $src, $sDstDllType, $dst, "int", $coi), "cveExtractChannel", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInsertChannel", $sSrcDllType, $src, $sDstDllType, $dst, "int", $coi), "cveInsertChannel", @error)
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

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sBestLabelsDllType
    If IsDllStruct($bestLabels) Then
        $sBestLabelsDllType = "struct*"
    Else
        $sBestLabelsDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    Local $sCentersDllType
    If IsDllStruct($centers) Then
        $sCentersDllType = "struct*"
    Else
        $sCentersDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveKmeans", $sDataDllType, $data, "int", $k, $sBestLabelsDllType, $bestLabels, $sCriteriaDllType, $criteria, "int", $attempts, "int", $flags, $sCentersDllType, $centers), "cveKmeans", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHConcat", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst), "cveHConcat", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVConcat", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst), "cveVConcat", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHConcat2", $sSrcDllType, $src, $sDstDllType, $dst), "cveHConcat2", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVConcat2", $sSrcDllType, $src, $sDstDllType, $dst), "cveVConcat2", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cvePSNR", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cvePSNR", @error)
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

Func _cveEigen($src, $eigenValues, $eigenVectors = _cveNoArray())
    ; CVAPI(bool) cveEigen(cv::_InputArray* src, cv::_OutputArray* eigenValues, cv::_OutputArray* eigenVectors);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sEigenValuesDllType
    If IsDllStruct($eigenValues) Then
        $sEigenValuesDllType = "struct*"
    Else
        $sEigenValuesDllType = "ptr"
    EndIf

    Local $sEigenVectorsDllType
    If IsDllStruct($eigenVectors) Then
        $sEigenVectorsDllType = "struct*"
    Else
        $sEigenVectorsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveEigen", $sSrcDllType, $src, $sEigenValuesDllType, $eigenValues, $sEigenVectorsDllType, $eigenVectors), "cveEigen", @error)
EndFunc   ;==>_cveEigen

Func _cveEigenMat($matSrc, $matEigenValues, $matEigenVectors = _cveNoArrayMat())
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

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmRead", $sAlgorithmDllType, $algorithm, $sNodeDllType, $node), "cveAlgorithmRead", @error)
EndFunc   ;==>_cveAlgorithmRead

Func _cveAlgorithmWrite($algorithm, $storage)
    ; CVAPI(void) cveAlgorithmWrite(cv::Algorithm* algorithm, cv::FileStorage* storage);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    Local $sStorageDllType
    If IsDllStruct($storage) Then
        $sStorageDllType = "struct*"
    Else
        $sStorageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmWrite", $sAlgorithmDllType, $algorithm, $sStorageDllType, $storage), "cveAlgorithmWrite", @error)
EndFunc   ;==>_cveAlgorithmWrite

Func _cveAlgorithmWrite2($algorithm, $storage, $name)
    ; CVAPI(void) cveAlgorithmWrite2(cv::Algorithm* algorithm, cv::FileStorage* storage, cv::String* name);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    Local $sStorageDllType
    If IsDllStruct($storage) Then
        $sStorageDllType = "struct*"
    Else
        $sStorageDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmWrite2", $sAlgorithmDllType, $algorithm, $sStorageDllType, $storage, $sNameDllType, $name), "cveAlgorithmWrite2", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveAlgorithmWrite2

Func _cveAlgorithmSave($algorithm, $filename)
    ; CVAPI(void) cveAlgorithmSave(cv::Algorithm* algorithm, cv::String* filename);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmSave", $sAlgorithmDllType, $algorithm, $sFilenameDllType, $filename), "cveAlgorithmSave", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf
EndFunc   ;==>_cveAlgorithmSave

Func _cveAlgorithmClear($algorithm)
    ; CVAPI(void) cveAlgorithmClear(cv::Algorithm* algorithm);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmClear", $sAlgorithmDllType, $algorithm), "cveAlgorithmClear", @error)
EndFunc   ;==>_cveAlgorithmClear

Func _cveAlgorithmEmpty($algorithm)
    ; CVAPI(bool) cveAlgorithmEmpty(cv::Algorithm* algorithm);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveAlgorithmEmpty", $sAlgorithmDllType, $algorithm), "cveAlgorithmEmpty", @error)
EndFunc   ;==>_cveAlgorithmEmpty

Func _cveAlgorithmGetDefaultName($algorithm, $defaultName)
    ; CVAPI(void) cveAlgorithmGetDefaultName(cv::Algorithm* algorithm, cv::String* defaultName);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    Local $bDefaultNameIsString = VarGetType($defaultName) == "String"
    If $bDefaultNameIsString Then
        $defaultName = _cveStringCreateFromStr($defaultName)
    EndIf

    Local $sDefaultNameDllType
    If IsDllStruct($defaultName) Then
        $sDefaultNameDllType = "struct*"
    Else
        $sDefaultNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlgorithmGetDefaultName", $sAlgorithmDllType, $algorithm, $sDefaultNameDllType, $defaultName), "cveAlgorithmGetDefaultName", @error)

    If $bDefaultNameIsString Then
        _cveStringRelease($defaultName)
    EndIf
EndFunc   ;==>_cveAlgorithmGetDefaultName

Func _cveClipLine($rect, $pt1, $pt2)
    ; CVAPI(bool) cveClipLine(CvRect* rect, CvPoint* pt1, CvPoint* pt2);

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf

    Local $sPt1DllType
    If IsDllStruct($pt1) Then
        $sPt1DllType = "struct*"
    Else
        $sPt1DllType = "ptr"
    EndIf

    Local $sPt2DllType
    If IsDllStruct($pt2) Then
        $sPt2DllType = "struct*"
    Else
        $sPt2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveClipLine", $sRectDllType, $rect, $sPt1DllType, $pt1, $sPt2DllType, $pt2), "cveClipLine", @error)
EndFunc   ;==>_cveClipLine

Func _cveRandn($dst, $mean, $stddev)
    ; CVAPI(void) cveRandn(cv::_InputOutputArray* dst, cv::_InputArray* mean, cv::_InputArray* stddev);

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRandn", $sDstDllType, $dst, $sMeanDllType, $mean, $sStddevDllType, $stddev), "cveRandn", @error)
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

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sLowDllType
    If IsDllStruct($low) Then
        $sLowDllType = "struct*"
    Else
        $sLowDllType = "ptr"
    EndIf

    Local $sHighDllType
    If IsDllStruct($high) Then
        $sHighDllType = "struct*"
    Else
        $sHighDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRandu", $sDstDllType, $dst, $sLowDllType, $low, $sHighDllType, $high), "cveRandu", @error)
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

    Local $bSourceIsString = VarGetType($source) == "String"
    If $bSourceIsString Then
        $source = _cveStringCreateFromStr($source)
    EndIf

    Local $sSourceDllType
    If IsDllStruct($source) Then
        $sSourceDllType = "struct*"
    Else
        $sSourceDllType = "ptr"
    EndIf

    Local $bEncodingIsString = VarGetType($encoding) == "String"
    If $bEncodingIsString Then
        $encoding = _cveStringCreateFromStr($encoding)
    EndIf

    Local $sEncodingDllType
    If IsDllStruct($encoding) Then
        $sEncodingDllType = "struct*"
    Else
        $sEncodingDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageCreate", $sSourceDllType, $source, "int", $flags, $sEncodingDllType, $encoding), "cveFileStorageCreate", @error)

    If $bEncodingIsString Then
        _cveStringRelease($encoding)
    EndIf

    If $bSourceIsString Then
        _cveStringRelease($source)
    EndIf

    Return $retval
EndFunc   ;==>_cveFileStorageCreate

Func _cveFileStorageIsOpened($storage)
    ; CVAPI(bool) cveFileStorageIsOpened(cv::FileStorage* storage);

    Local $sStorageDllType
    If IsDllStruct($storage) Then
        $sStorageDllType = "struct*"
    Else
        $sStorageDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileStorageIsOpened", $sStorageDllType, $storage), "cveFileStorageIsOpened", @error)
EndFunc   ;==>_cveFileStorageIsOpened

Func _cveFileStorageReleaseAndGetString($storage, $result)
    ; CVAPI(void) cveFileStorageReleaseAndGetString(cv::FileStorage* storage, cv::String* result);

    Local $sStorageDllType
    If IsDllStruct($storage) Then
        $sStorageDllType = "struct*"
    Else
        $sStorageDllType = "ptr"
    EndIf

    Local $bResultIsString = VarGetType($result) == "String"
    If $bResultIsString Then
        $result = _cveStringCreateFromStr($result)
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageReleaseAndGetString", $sStorageDllType, $storage, $sResultDllType, $result), "cveFileStorageReleaseAndGetString", @error)

    If $bResultIsString Then
        _cveStringRelease($result)
    EndIf
EndFunc   ;==>_cveFileStorageReleaseAndGetString

Func _cveFileStorageRelease($storage)
    ; CVAPI(void) cveFileStorageRelease(cv::FileStorage** storage);

    Local $sStorageDllType
    If IsDllStruct($storage) Then
        $sStorageDllType = "struct*"
    ElseIf $storage == Null Then
        $sStorageDllType = "ptr"
    Else
        $sStorageDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageRelease", $sStorageDllType, $storage), "cveFileStorageRelease", @error)
EndFunc   ;==>_cveFileStorageRelease

Func _cveFileStorageWriteMat($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteMat(cv::FileStorage* fs, cv::String* name, cv::Mat* value);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteMat", $sFsDllType, $fs, $sNameDllType, $name, $sValueDllType, $value), "cveFileStorageWriteMat", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteMat

Func _cveFileStorageWriteInt($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteInt(cv::FileStorage* fs, cv::String* name, int value);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteInt", $sFsDllType, $fs, $sNameDllType, $name, "int", $value), "cveFileStorageWriteInt", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteInt

Func _cveFileStorageWriteFloat($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteFloat(cv::FileStorage* fs, cv::String* name, float value);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteFloat", $sFsDllType, $fs, $sNameDllType, $name, "float", $value), "cveFileStorageWriteFloat", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteFloat

Func _cveFileStorageWriteDouble($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteDouble(cv::FileStorage* fs, cv::String* name, double value);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteDouble", $sFsDllType, $fs, $sNameDllType, $name, "double", $value), "cveFileStorageWriteDouble", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteDouble

Func _cveFileStorageWriteString($fs, $name, $value)
    ; CVAPI(void) cveFileStorageWriteString(cv::FileStorage* fs, cv::String* name, cv::String* value);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageWriteString", $sFsDllType, $fs, $sNameDllType, $name, $sValueDllType, $value), "cveFileStorageWriteString", @error)

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileStorageWriteString

Func _cveFileStorageInsertString($fs, $value)
    ; CVAPI(void) cveFileStorageInsertString(cv::FileStorage* fs, cv::String* value);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileStorageInsertString", $sFsDllType, $fs, $sValueDllType, $value), "cveFileStorageInsertString", @error)

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf
EndFunc   ;==>_cveFileStorageInsertString

Func _cveFileStorageRoot($fs, $streamIdx)
    ; CVAPI(cv::FileNode*) cveFileStorageRoot(cv::FileStorage* fs, int streamIdx);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageRoot", $sFsDllType, $fs, "int", $streamIdx), "cveFileStorageRoot", @error)
EndFunc   ;==>_cveFileStorageRoot

Func _cveFileStorageGetFirstTopLevelNode($fs)
    ; CVAPI(cv::FileNode*) cveFileStorageGetFirstTopLevelNode(cv::FileStorage* fs);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageGetFirstTopLevelNode", $sFsDllType, $fs), "cveFileStorageGetFirstTopLevelNode", @error)
EndFunc   ;==>_cveFileStorageGetFirstTopLevelNode

Func _cveFileStorageGetNode($fs, $nodeName)
    ; CVAPI(cv::FileNode*) cveFileStorageGetNode(cv::FileStorage* fs, cv::String* nodeName);

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    Local $bNodeNameIsString = VarGetType($nodeName) == "String"
    If $bNodeNameIsString Then
        $nodeName = _cveStringCreateFromStr($nodeName)
    EndIf

    Local $sNodeNameDllType
    If IsDllStruct($nodeName) Then
        $sNodeNameDllType = "struct*"
    Else
        $sNodeNameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileStorageGetNode", $sFsDllType, $fs, $sNodeNameDllType, $nodeName), "cveFileStorageGetNode", @error)

    If $bNodeNameIsString Then
        _cveStringRelease($nodeName)
    EndIf

    Return $retval
EndFunc   ;==>_cveFileStorageGetNode

Func _cveFileNodeGetType($node)
    ; CVAPI(int) cveFileNodeGetType(cv::FileNode* node);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFileNodeGetType", $sNodeDllType, $node), "cveFileNodeGetType", @error)
EndFunc   ;==>_cveFileNodeGetType

Func _cveFileNodeGetName($node, $name)
    ; CVAPI(void) cveFileNodeGetName(cv::FileNode* node, cv::String* name);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeGetName", $sNodeDllType, $node, $sNameDllType, $name), "cveFileNodeGetName", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveFileNodeGetName

Func _cveFileNodeGetKeys($node, $keys)
    ; CVAPI(void) cveFileNodeGetKeys(cv::FileNode* node, std::vector<cv::String>* keys);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf

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

    Local $sKeysDllType
    If IsDllStruct($keys) Then
        $sKeysDllType = "struct*"
    Else
        $sKeysDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeGetKeys", $sNodeDllType, $node, $sKeysDllType, $vecKeys), "cveFileNodeGetKeys", @error)

    If $bKeysIsArray Then
        _VectorOfCvStringRelease($vecKeys)
    EndIf
EndFunc   ;==>_cveFileNodeGetKeys

Func _cveFileNodeReadMat($node, $mat, $defaultMat)
    ; CVAPI(void) cveFileNodeReadMat(cv::FileNode* node, cv::Mat* mat, cv::Mat* defaultMat);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sDefaultMatDllType
    If IsDllStruct($defaultMat) Then
        $sDefaultMatDllType = "struct*"
    Else
        $sDefaultMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeReadMat", $sNodeDllType, $node, $sMatDllType, $mat, $sDefaultMatDllType, $defaultMat), "cveFileNodeReadMat", @error)
EndFunc   ;==>_cveFileNodeReadMat

Func _cveFileNodeReadString($node, $str, $defaultStr)
    ; CVAPI(void) cveFileNodeReadString(cv::FileNode* node, cv::String* str, cv::String* defaultStr);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    Local $bDefaultStrIsString = VarGetType($defaultStr) == "String"
    If $bDefaultStrIsString Then
        $defaultStr = _cveStringCreateFromStr($defaultStr)
    EndIf

    Local $sDefaultStrDllType
    If IsDllStruct($defaultStr) Then
        $sDefaultStrDllType = "struct*"
    Else
        $sDefaultStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeReadString", $sNodeDllType, $node, $sStrDllType, $str, $sDefaultStrDllType, $defaultStr), "cveFileNodeReadString", @error)

    If $bDefaultStrIsString Then
        _cveStringRelease($defaultStr)
    EndIf

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFileNodeReadString

Func _cveFileNodeReadInt($node, $defaultInt)
    ; CVAPI(int) cveFileNodeReadInt(cv::FileNode* node, int defaultInt);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFileNodeReadInt", $sNodeDllType, $node, "int", $defaultInt), "cveFileNodeReadInt", @error)
EndFunc   ;==>_cveFileNodeReadInt

Func _cveFileNodeReadDouble($node, $defaultDouble)
    ; CVAPI(double) cveFileNodeReadDouble(cv::FileNode* node, double defaultDouble);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFileNodeReadDouble", $sNodeDllType, $node, "double", $defaultDouble), "cveFileNodeReadDouble", @error)
EndFunc   ;==>_cveFileNodeReadDouble

Func _cveFileNodeReadFloat($node, $defaultFloat)
    ; CVAPI(float) cveFileNodeReadFloat(cv::FileNode* node, float defaultFloat);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveFileNodeReadFloat", $sNodeDllType, $node, "float", $defaultFloat), "cveFileNodeReadFloat", @error)
EndFunc   ;==>_cveFileNodeReadFloat

Func _cveFileNodeRelease($node)
    ; CVAPI(void) cveFileNodeRelease(cv::FileNode** node);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    ElseIf $node == Null Then
        $sNodeDllType = "ptr"
    Else
        $sNodeDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeRelease", $sNodeDllType, $node), "cveFileNodeRelease", @error)
EndFunc   ;==>_cveFileNodeRelease

Func _cveFileNodeIteratorCreate()
    ; CVAPI(cv::FileNodeIterator*) cveFileNodeIteratorCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileNodeIteratorCreate"), "cveFileNodeIteratorCreate", @error)
EndFunc   ;==>_cveFileNodeIteratorCreate

Func _cveFileNodeIteratorCreateFromNode($node, $seekEnd)
    ; CVAPI(cv::FileNodeIterator*) cveFileNodeIteratorCreateFromNode(cv::FileNode* node, bool seekEnd);

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileNodeIteratorCreateFromNode", $sNodeDllType, $node, "boolean", $seekEnd), "cveFileNodeIteratorCreateFromNode", @error)
EndFunc   ;==>_cveFileNodeIteratorCreateFromNode

Func _cveFileNodeIteratorEqualTo($iterator, $otherIterator)
    ; CVAPI(bool) cveFileNodeIteratorEqualTo(cv::FileNodeIterator* iterator, cv::FileNodeIterator* otherIterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf

    Local $sOtherIteratorDllType
    If IsDllStruct($otherIterator) Then
        $sOtherIteratorDllType = "struct*"
    Else
        $sOtherIteratorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIteratorEqualTo", $sIteratorDllType, $iterator, $sOtherIteratorDllType, $otherIterator), "cveFileNodeIteratorEqualTo", @error)
EndFunc   ;==>_cveFileNodeIteratorEqualTo

Func _cveFileNodeIteratorNext($iterator)
    ; CVAPI(void) cveFileNodeIteratorNext(cv::FileNodeIterator* iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeIteratorNext", $sIteratorDllType, $iterator), "cveFileNodeIteratorNext", @error)
EndFunc   ;==>_cveFileNodeIteratorNext

Func _cveFileNodeIteratorGetFileNode($iterator)
    ; CVAPI(cv::FileNode*) cveFileNodeIteratorGetFileNode(cv::FileNodeIterator* iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFileNodeIteratorGetFileNode", $sIteratorDllType, $iterator), "cveFileNodeIteratorGetFileNode", @error)
EndFunc   ;==>_cveFileNodeIteratorGetFileNode

Func _cveFileNodeIteratorRelease($iterator)
    ; CVAPI(void) cveFileNodeIteratorRelease(cv::FileNodeIterator** iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    ElseIf $iterator == Null Then
        $sIteratorDllType = "ptr"
    Else
        $sIteratorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFileNodeIteratorRelease", $sIteratorDllType, $iterator), "cveFileNodeIteratorRelease", @error)
EndFunc   ;==>_cveFileNodeIteratorRelease

Func _cveCreateImage($size, $depth, $channels)
    ; CVAPI(IplImage*) cveCreateImage(CvSize* size, int depth, int channels);

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateImage", $sSizeDllType, $size, "int", $depth, "int", $channels), "cveCreateImage", @error)
EndFunc   ;==>_cveCreateImage

Func _cveCreateImageHeader($size, $depth, $channels)
    ; CVAPI(IplImage*) cveCreateImageHeader(CvSize* size, int depth, int channels);

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateImageHeader", $sSizeDllType, $size, "int", $depth, "int", $channels), "cveCreateImageHeader", @error)
EndFunc   ;==>_cveCreateImageHeader

Func _cveInitImageHeader($image, $size, $depth, $channels, $origin, $align)
    ; CVAPI(IplImage*) cveInitImageHeader(IplImage* image, CvSize* size, int depth, int channels, int origin, int align);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInitImageHeader", $sImageDllType, $image, $sSizeDllType, $size, "int", $depth, "int", $channels, "int", $origin, "int", $align), "cveInitImageHeader", @error)
EndFunc   ;==>_cveInitImageHeader

Func _cveSetData($arr, $data, $step)
    ; CVAPI(void) cveSetData(CvArr* arr, void* data, int step);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetData", $sArrDllType, $arr, $sDataDllType, $data, "int", $step), "cveSetData", @error)
EndFunc   ;==>_cveSetData

Func _cveReleaseImageHeader($image)
    ; CVAPI(void) cveReleaseImageHeader(IplImage** image);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    ElseIf $image == Null Then
        $sImageDllType = "ptr"
    Else
        $sImageDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseImageHeader", $sImageDllType, $image), "cveReleaseImageHeader", @error)
EndFunc   ;==>_cveReleaseImageHeader

Func _cveSetImageCOI($image, $coi)
    ; CVAPI(void) cveSetImageCOI(IplImage* image, int coi);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetImageCOI", $sImageDllType, $image, "int", $coi), "cveSetImageCOI", @error)
EndFunc   ;==>_cveSetImageCOI

Func _cveGetImageCOI($image)
    ; CVAPI(int) cveGetImageCOI(IplImage* image);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGetImageCOI", $sImageDllType, $image), "cveGetImageCOI", @error)
EndFunc   ;==>_cveGetImageCOI

Func _cveResetImageROI($image)
    ; CVAPI(void) cveResetImageROI(IplImage* image);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveResetImageROI", $sImageDllType, $image), "cveResetImageROI", @error)
EndFunc   ;==>_cveResetImageROI

Func _cveSetImageROI($image, $rect)
    ; CVAPI(void) cveSetImageROI(IplImage* image, CvRect* rect);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetImageROI", $sImageDllType, $image, $sRectDllType, $rect), "cveSetImageROI", @error)
EndFunc   ;==>_cveSetImageROI

Func _cveGetImageROI($image, $rect)
    ; CVAPI(void) cveGetImageROI(IplImage* image, CvRect* rect);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetImageROI", $sImageDllType, $image, $sRectDllType, $rect), "cveGetImageROI", @error)
EndFunc   ;==>_cveGetImageROI

Func _cveInitMatHeader($mat, $rows, $cols, $type, $data, $step)
    ; CVAPI(CvMat*) cveInitMatHeader(CvMat* mat, int rows, int cols, int type, void* data, int step);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInitMatHeader", $sMatDllType, $mat, "int", $rows, "int", $cols, "int", $type, $sDataDllType, $data, "int", $step), "cveInitMatHeader", @error)
EndFunc   ;==>_cveInitMatHeader

Func _cveCreateMat($rows, $cols, $type)
    ; CVAPI(CvMat*) cveCreateMat(int rows, int cols, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateMat", "int", $rows, "int", $cols, "int", $type), "cveCreateMat", @error)
EndFunc   ;==>_cveCreateMat

Func _cveInitMatNDHeader($mat, $dims, $sizes, $type, $data)
    ; CVAPI(CvMatND*) cveInitMatNDHeader(CvMatND* mat, int dims, int* sizes, int type, void* data);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sSizesDllType
    If IsDllStruct($sizes) Then
        $sSizesDllType = "struct*"
    Else
        $sSizesDllType = "int*"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInitMatNDHeader", $sMatDllType, $mat, "int", $dims, $sSizesDllType, $sizes, "int", $type, $sDataDllType, $data), "cveInitMatNDHeader", @error)
EndFunc   ;==>_cveInitMatNDHeader

Func _cveReleaseMat($mat)
    ; CVAPI(void) cveReleaseMat(CvMat** mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    ElseIf $mat == Null Then
        $sMatDllType = "ptr"
    Else
        $sMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseMat", $sMatDllType, $mat), "cveReleaseMat", @error)
EndFunc   ;==>_cveReleaseMat

Func _cveCreateSparseMat($dim, $sizes, $type)
    ; CVAPI(CvSparseMat*) cveCreateSparseMat(int dim, int* sizes, int type);

    Local $sSizesDllType
    If IsDllStruct($sizes) Then
        $sSizesDllType = "struct*"
    Else
        $sSizesDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateSparseMat", "int", $dim, $sSizesDllType, $sizes, "int", $type), "cveCreateSparseMat", @error)
EndFunc   ;==>_cveCreateSparseMat

Func _cveReleaseSparseMat($mat)
    ; CVAPI(void) cveReleaseSparseMat(CvSparseMat** mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    ElseIf $mat == Null Then
        $sMatDllType = "ptr"
    Else
        $sMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseSparseMat", $sMatDllType, $mat), "cveReleaseSparseMat", @error)
EndFunc   ;==>_cveReleaseSparseMat

Func _cveSet2D($arr, $idx0, $idx1, $value)
    ; CVAPI(void) cveSet2D(CvArr* arr, int idx0, int idx1, CvScalar* value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSet2D", $sArrDllType, $arr, "int", $idx0, "int", $idx1, $sValueDllType, $value), "cveSet2D", @error)
EndFunc   ;==>_cveSet2D

Func _cveGetSubRect($arr, $submat, $rect)
    ; CVAPI(CvMat*) cveGetSubRect(CvArr* arr, CvMat* submat, CvRect* rect);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sSubmatDllType
    If IsDllStruct($submat) Then
        $sSubmatDllType = "struct*"
    Else
        $sSubmatDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetSubRect", $sArrDllType, $arr, $sSubmatDllType, $submat, $sRectDllType, $rect), "cveGetSubRect", @error)
EndFunc   ;==>_cveGetSubRect

Func _cveGetRows($arr, $submat, $startRow, $endRow, $deltaRow)
    ; CVAPI(CvMat*) cveGetRows(CvArr* arr, CvMat* submat, int startRow, int endRow, int deltaRow);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sSubmatDllType
    If IsDllStruct($submat) Then
        $sSubmatDllType = "struct*"
    Else
        $sSubmatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetRows", $sArrDllType, $arr, $sSubmatDllType, $submat, "int", $startRow, "int", $endRow, "int", $deltaRow), "cveGetRows", @error)
EndFunc   ;==>_cveGetRows

Func _cveGetCols($arr, $submat, $startCol, $endCol)
    ; CVAPI(CvMat*) cveGetCols(CvArr* arr, CvMat* submat, int startCol, int endCol);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sSubmatDllType
    If IsDllStruct($submat) Then
        $sSubmatDllType = "struct*"
    Else
        $sSubmatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetCols", $sArrDllType, $arr, $sSubmatDllType, $submat, "int", $startCol, "int", $endCol), "cveGetCols", @error)
EndFunc   ;==>_cveGetCols

Func _cveGetSize($arr, $width, $height)
    ; CVAPI(void) cveGetSize(CvArr* arr, int* width, int* height);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sWidthDllType
    If IsDllStruct($width) Then
        $sWidthDllType = "struct*"
    Else
        $sWidthDllType = "int*"
    EndIf

    Local $sHeightDllType
    If IsDllStruct($height) Then
        $sHeightDllType = "struct*"
    Else
        $sHeightDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetSize", $sArrDllType, $arr, $sWidthDllType, $width, $sHeightDllType, $height), "cveGetSize", @error)
EndFunc   ;==>_cveGetSize

Func _cveCopy($src, $dst, $mask)
    ; CVAPI(void) cveCopy(CvArr* src, CvArr* dst, CvArr* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCopy", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask), "cveCopy", @error)
EndFunc   ;==>_cveCopy

Func _cveRange($mat, $start, $end)
    ; CVAPI(void) cveRange(CvArr* mat, double start, double end);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRange", $sMatDllType, $mat, "double", $start, "double", $end), "cveRange", @error)
EndFunc   ;==>_cveRange

Func _cveSetReal1D($arr, $idx0, $value)
    ; CVAPI(void) cveSetReal1D(CvArr* arr, int idx0, double value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetReal1D", $sArrDllType, $arr, "int", $idx0, "double", $value), "cveSetReal1D", @error)
EndFunc   ;==>_cveSetReal1D

Func _cveSetReal2D($arr, $idx0, $idx1, $value)
    ; CVAPI(void) cveSetReal2D(CvArr* arr, int idx0, int idx1, double value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetReal2D", $sArrDllType, $arr, "int", $idx0, "int", $idx1, "double", $value), "cveSetReal2D", @error)
EndFunc   ;==>_cveSetReal2D

Func _cveSetReal3D($arr, $idx0, $idx1, $idx2, $value)
    ; CVAPI(void) cveSetReal3D(CvArr* arr, int idx0, int idx1, int idx2, double value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetReal3D", $sArrDllType, $arr, "int", $idx0, "int", $idx1, "int", $idx2, "double", $value), "cveSetReal3D", @error)
EndFunc   ;==>_cveSetReal3D

Func _cveSetRealND($arr, $idx, $value)
    ; CVAPI(void) cveSetRealND(CvArr* arr, int* idx, double value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sIdxDllType
    If IsDllStruct($idx) Then
        $sIdxDllType = "struct*"
    Else
        $sIdxDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetRealND", $sArrDllType, $arr, $sIdxDllType, $idx, "double", $value), "cveSetRealND", @error)
EndFunc   ;==>_cveSetRealND

Func _cveGet1D($arr, $idx0, $value)
    ; CVAPI(void) cveGet1D(CvArr* arr, int idx0, CvScalar* value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGet1D", $sArrDllType, $arr, "int", $idx0, $sValueDllType, $value), "cveGet1D", @error)
EndFunc   ;==>_cveGet1D

Func _cveGet2D($arr, $idx0, $idx1, $value)
    ; CVAPI(void) cveGet2D(CvArr* arr, int idx0, int idx1, CvScalar* value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGet2D", $sArrDllType, $arr, "int", $idx0, "int", $idx1, $sValueDllType, $value), "cveGet2D", @error)
EndFunc   ;==>_cveGet2D

Func _cveGet3D($arr, $idx0, $idx1, $idx2, $value)
    ; CVAPI(void) cveGet3D(CvArr* arr, int idx0, int idx1, int idx2, CvScalar* value);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGet3D", $sArrDllType, $arr, "int", $idx0, "int", $idx1, "int", $idx2, $sValueDllType, $value), "cveGet3D", @error)
EndFunc   ;==>_cveGet3D

Func _cveGetReal1D($arr, $idx0)
    ; CVAPI(double) cveGetReal1D(CvArr* arr, int idx0);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetReal1D", $sArrDllType, $arr, "int", $idx0), "cveGetReal1D", @error)
EndFunc   ;==>_cveGetReal1D

Func _cveGetReal2D($arr, $idx0, $idx1)
    ; CVAPI(double) cveGetReal2D(CvArr* arr, int idx0, int idx1);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetReal2D", $sArrDllType, $arr, "int", $idx0, "int", $idx1), "cveGetReal2D", @error)
EndFunc   ;==>_cveGetReal2D

Func _cveGetReal3D($arr, $idx0, $idx1, $idx2)
    ; CVAPI(double) cveGetReal3D(CvArr* arr, int idx0, int idx1, int idx2);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetReal3D", $sArrDllType, $arr, "int", $idx0, "int", $idx1, "int", $idx2), "cveGetReal3D", @error)
EndFunc   ;==>_cveGetReal3D

Func _cveClearND($arr, $idx)
    ; CVAPI(void) cveClearND(CvArr* arr, int* idx);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sIdxDllType
    If IsDllStruct($idx) Then
        $sIdxDllType = "struct*"
    Else
        $sIdxDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveClearND", $sArrDllType, $arr, $sIdxDllType, $idx), "cveClearND", @error)
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

    Local $sBuildInformationDllType
    If IsDllStruct($buildInformation) Then
        $sBuildInformationDllType = "struct*"
    Else
        $sBuildInformationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetBuildInformation", $sBuildInformationDllType, $buildInformation), "cveGetBuildInformation", @error)

    If $bBuildInformationIsString Then
        _cveStringRelease($buildInformation)
    EndIf
EndFunc   ;==>_cveGetBuildInformation

Func _cveGetRawData($arr, $data, $step, $roiSize)
    ; CVAPI(void) cveGetRawData(CvArr* arr, uchar** data, int* step, CvSize* roiSize);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    ElseIf $data == Null Then
        $sDataDllType = "ptr"
    Else
        $sDataDllType = "ptr*"
    EndIf

    Local $sStepDllType
    If IsDllStruct($step) Then
        $sStepDllType = "struct*"
    Else
        $sStepDllType = "int*"
    EndIf

    Local $sRoiSizeDllType
    If IsDllStruct($roiSize) Then
        $sRoiSizeDllType = "struct*"
    Else
        $sRoiSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRawData", $sArrDllType, $arr, $sDataDllType, $data, $sStepDllType, $step, $sRoiSizeDllType, $roiSize), "cveGetRawData", @error)
EndFunc   ;==>_cveGetRawData

Func _cveGetMat($arr, $header, $coi, $allowNd)
    ; CVAPI(CvMat*) cveGetMat(CvArr* arr, CvMat* header, int* coi, int allowNd);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sHeaderDllType
    If IsDllStruct($header) Then
        $sHeaderDllType = "struct*"
    Else
        $sHeaderDllType = "ptr"
    EndIf

    Local $sCoiDllType
    If IsDllStruct($coi) Then
        $sCoiDllType = "struct*"
    Else
        $sCoiDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetMat", $sArrDllType, $arr, $sHeaderDllType, $header, $sCoiDllType, $coi, "int", $allowNd), "cveGetMat", @error)
EndFunc   ;==>_cveGetMat

Func _cveGetImage($arr, $imageHeader)
    ; CVAPI(IplImage*) cveGetImage(CvArr* arr, IplImage* imageHeader);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sImageHeaderDllType
    If IsDllStruct($imageHeader) Then
        $sImageHeaderDllType = "struct*"
    Else
        $sImageHeaderDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetImage", $sArrDllType, $arr, $sImageHeaderDllType, $imageHeader), "cveGetImage", @error)
EndFunc   ;==>_cveGetImage

Func _cveCheckArr($arr, $flags, $minVal, $maxVal)
    ; CVAPI(int) cveCheckArr(CvArr* arr, int flags, double minVal, double maxVal);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCheckArr", $sArrDllType, $arr, "int", $flags, "double", $minVal, "double", $maxVal), "cveCheckArr", @error)
EndFunc   ;==>_cveCheckArr

Func _cveReshape($arr, $header, $newCn, $newRows)
    ; CVAPI(CvMat*) cveReshape(CvArr* arr, CvMat* header, int newCn, int newRows);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sHeaderDllType
    If IsDllStruct($header) Then
        $sHeaderDllType = "struct*"
    Else
        $sHeaderDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReshape", $sArrDllType, $arr, $sHeaderDllType, $header, "int", $newCn, "int", $newRows), "cveReshape", @error)
EndFunc   ;==>_cveReshape

Func _cveGetDiag($arr, $submat, $diag)
    ; CVAPI(CvMat*) cveGetDiag(CvArr* arr, CvMat* submat, int diag);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sSubmatDllType
    If IsDllStruct($submat) Then
        $sSubmatDllType = "struct*"
    Else
        $sSubmatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGetDiag", $sArrDllType, $arr, $sSubmatDllType, $submat, "int", $diag), "cveGetDiag", @error)
EndFunc   ;==>_cveGetDiag

Func _cveConvertScale($arr, $dst, $scale, $shift)
    ; CVAPI(void) cveConvertScale(CvArr* arr, CvArr* dst, double scale, double shift);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertScale", $sArrDllType, $arr, $sDstDllType, $dst, "double", $scale, "double", $shift), "cveConvertScale", @error)
EndFunc   ;==>_cveConvertScale

Func _cveReleaseImage($image)
    ; CVAPI(void) cveReleaseImage(IplImage** image);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    ElseIf $image == Null Then
        $sImageDllType = "ptr"
    Else
        $sImageDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReleaseImage", $sImageDllType, $image), "cveReleaseImage", @error)
EndFunc   ;==>_cveReleaseImage

Func _cveSVDecomp($src, $w, $u, $vt, $flags = 0)
    ; CVAPI(void) cveSVDecomp(cv::_InputArray* src, cv::_OutputArray* w, cv::_OutputArray* u, cv::_OutputArray* vt, int flags);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sWDllType
    If IsDllStruct($w) Then
        $sWDllType = "struct*"
    Else
        $sWDllType = "ptr"
    EndIf

    Local $sUDllType
    If IsDllStruct($u) Then
        $sUDllType = "struct*"
    Else
        $sUDllType = "ptr"
    EndIf

    Local $sVtDllType
    If IsDllStruct($vt) Then
        $sVtDllType = "struct*"
    Else
        $sVtDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVDecomp", $sSrcDllType, $src, $sWDllType, $w, $sUDllType, $u, $sVtDllType, $vt, "int", $flags), "cveSVDecomp", @error)
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

    Local $sWDllType
    If IsDllStruct($w) Then
        $sWDllType = "struct*"
    Else
        $sWDllType = "ptr"
    EndIf

    Local $sUDllType
    If IsDllStruct($u) Then
        $sUDllType = "struct*"
    Else
        $sUDllType = "ptr"
    EndIf

    Local $sVtDllType
    If IsDllStruct($vt) Then
        $sVtDllType = "struct*"
    Else
        $sVtDllType = "ptr"
    EndIf

    Local $sRhsDllType
    If IsDllStruct($rhs) Then
        $sRhsDllType = "struct*"
    Else
        $sRhsDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVBackSubst", $sWDllType, $w, $sUDllType, $u, $sVtDllType, $vt, $sRhsDllType, $rhs, $sDstDllType, $dst), "cveSVBackSubst", @error)
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

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    Local $sEigenvectorsDllType
    If IsDllStruct($eigenvectors) Then
        $sEigenvectorsDllType = "struct*"
    Else
        $sEigenvectorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCACompute1", $sDataDllType, $data, $sMeanDllType, $mean, $sEigenvectorsDllType, $eigenvectors, "int", $maxComponents), "cvePCACompute1", @error)
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

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    Local $sEigenvectorsDllType
    If IsDllStruct($eigenvectors) Then
        $sEigenvectorsDllType = "struct*"
    Else
        $sEigenvectorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCACompute2", $sDataDllType, $data, $sMeanDllType, $mean, $sEigenvectorsDllType, $eigenvectors, "double", $retainedVariance), "cvePCACompute2", @error)
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

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    Local $sEigenvectorsDllType
    If IsDllStruct($eigenvectors) Then
        $sEigenvectorsDllType = "struct*"
    Else
        $sEigenvectorsDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCAProject", $sDataDllType, $data, $sMeanDllType, $mean, $sEigenvectorsDllType, $eigenvectors, $sResultDllType, $result), "cvePCAProject", @error)
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

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    Local $sEigenvectorsDllType
    If IsDllStruct($eigenvectors) Then
        $sEigenvectorsDllType = "struct*"
    Else
        $sEigenvectorsDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCABackProject", $sDataDllType, $data, $sMeanDllType, $mean, $sEigenvectorsDllType, $eigenvectors, $sResultDllType, $result), "cvePCABackProject", @error)
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

    Local $sRangeDllType
    If IsDllStruct($range) Then
        $sRangeDllType = "struct*"
    Else
        $sRangeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRangeAll", $sRangeDllType, $range), "cveGetRangeAll", @error)
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

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    Else
        $sAffineDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffine3dRotate", $sAffineDllType, $affine, "double", $r0, "double", $r1, "double", $r2), "cveAffine3dRotate", @error)
EndFunc   ;==>_cveAffine3dRotate

Func _cveAffine3dTranslate($affine, $t0, $t1, $t2)
    ; CVAPI(cv::Affine3d*) cveAffine3dTranslate(cv::Affine3d* affine, double t0, double t1, double t2);

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    Else
        $sAffineDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffine3dTranslate", $sAffineDllType, $affine, "double", $t0, "double", $t1, "double", $t2), "cveAffine3dTranslate", @error)
EndFunc   ;==>_cveAffine3dTranslate

Func _cveAffine3dGetValues($affine, $values)
    ; CVAPI(void) cveAffine3dGetValues(cv::Affine3d* affine, double* values);

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    Else
        $sAffineDllType = "ptr"
    EndIf

    Local $sValuesDllType
    If IsDllStruct($values) Then
        $sValuesDllType = "struct*"
    Else
        $sValuesDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffine3dGetValues", $sAffineDllType, $affine, $sValuesDllType, $values), "cveAffine3dGetValues", @error)
EndFunc   ;==>_cveAffine3dGetValues

Func _cveAffine3dRelease($affine)
    ; CVAPI(void) cveAffine3dRelease(cv::Affine3d** affine);

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    ElseIf $affine == Null Then
        $sAffineDllType = "ptr"
    Else
        $sAffineDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffine3dRelease", $sAffineDllType, $affine), "cveAffine3dRelease", @error)
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

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    Else
        $sRngDllType = "ptr"
    EndIf

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRngFill", $sRngDllType, $rng, $sMatDllType, $mat, "int", $distType, $sADllType, $a, $sBDllType, $b, "boolean", $saturateRange), "cveRngFill", @error)
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

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    Else
        $sRngDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveRngGaussian", $sRngDllType, $rng, "double", $sigma), "cveRngGaussian", @error)
EndFunc   ;==>_cveRngGaussian

Func _cveRngNext($rng)
    ; CVAPI(unsigned) cveRngNext(cv::RNG* rng);

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    Else
        $sRngDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveRngNext", $sRngDllType, $rng), "cveRngNext", @error)
EndFunc   ;==>_cveRngNext

Func _cveRngUniformInt($rng, $a, $b)
    ; CVAPI(int) cveRngUniformInt(cv::RNG* rng, int a, int b);

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    Else
        $sRngDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRngUniformInt", $sRngDllType, $rng, "int", $a, "int", $b), "cveRngUniformInt", @error)
EndFunc   ;==>_cveRngUniformInt

Func _cveRngUniformFloat($rng, $a, $b)
    ; CVAPI(float) cveRngUniformFloat(cv::RNG* rng, float a, float b);

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    Else
        $sRngDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRngUniformFloat", $sRngDllType, $rng, "float", $a, "float", $b), "cveRngUniformFloat", @error)
EndFunc   ;==>_cveRngUniformFloat

Func _cveRngUniformDouble($rng, $a, $b)
    ; CVAPI(double) cveRngUniformDouble(cv::RNG* rng, double a, double b);

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    Else
        $sRngDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveRngUniformDouble", $sRngDllType, $rng, "double", $a, "double", $b), "cveRngUniformDouble", @error)
EndFunc   ;==>_cveRngUniformDouble

Func _cveRngRelease($rng)
    ; CVAPI(void) cveRngRelease(cv::RNG** rng);

    Local $sRngDllType
    If IsDllStruct($rng) Then
        $sRngDllType = "struct*"
    ElseIf $rng == Null Then
        $sRngDllType = "ptr"
    Else
        $sRngDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRngRelease", $sRngDllType, $rng), "cveRngRelease", @error)
EndFunc   ;==>_cveRngRelease

Func _cveMomentsCreate()
    ; CVAPI(cv::Moments*) cveMomentsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMomentsCreate"), "cveMomentsCreate", @error)
EndFunc   ;==>_cveMomentsCreate

Func _cveMomentsRelease($moments)
    ; CVAPI(void) cveMomentsRelease(cv::Moments** moments);

    Local $sMomentsDllType
    If IsDllStruct($moments) Then
        $sMomentsDllType = "struct*"
    ElseIf $moments == Null Then
        $sMomentsDllType = "ptr"
    Else
        $sMomentsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsRelease", $sMomentsDllType, $moments), "cveMomentsRelease", @error)
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

    Local $sKeyDllType
    If IsDllStruct($key) Then
        $sKeyDllType = "struct*"
    Else
        $sKeyDllType = "ptr"
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

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetConfigDict", $sKeyDllType, $vecKey, $sValueDllType, $vecValue), "cveGetConfigDict", @error)

    If $bValueIsArray Then
        _VectorOfDoubleRelease($vecValue)
    EndIf

    If $bKeyIsArray Then
        _VectorOfCvStringRelease($vecKey)
    EndIf
EndFunc   ;==>_cveGetConfigDict