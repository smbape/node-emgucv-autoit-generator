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

    Local $bBackendNameIsString = IsString($backendName)
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
    Local $bBackendNamesIsArray = IsArray($backendNames)

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

    Local $bStringIsString = IsString($string)
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

    Local $bStringIsString = IsString($string)
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

Func _cveInputArrayGetDimsTyped($typeOfIa, $ia, $i)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    Local $retval = _cveInputArrayGetDims($iArrIa, $i)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayGetDimsTyped

Func _cveInputArrayGetDimsMat($ia, $i)
    ; cveInputArrayGetDims using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayGetDimsTyped("Mat", $ia, $i)

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

Func _cveInputArrayGetSizeTyped($typeOfIa, $ia, $size, $idx)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    _cveInputArrayGetSize($iArrIa, $size, $idx)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf
EndFunc   ;==>_cveInputArrayGetSizeTyped

Func _cveInputArrayGetSizeMat($ia, $size, $idx)
    ; cveInputArrayGetSize using cv::Mat instead of _*Array
    _cveInputArrayGetSizeTyped("Mat", $ia, $size, $idx)
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

Func _cveInputArrayGetDepthTyped($typeOfIa, $ia, $idx)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    Local $retval = _cveInputArrayGetDepth($iArrIa, $idx)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayGetDepthTyped

Func _cveInputArrayGetDepthMat($ia, $idx)
    ; cveInputArrayGetDepth using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayGetDepthTyped("Mat", $ia, $idx)

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

Func _cveInputArrayGetChannelsTyped($typeOfIa, $ia, $idx)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    Local $retval = _cveInputArrayGetChannels($iArrIa, $idx)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayGetChannelsTyped

Func _cveInputArrayGetChannelsMat($ia, $idx)
    ; cveInputArrayGetChannels using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayGetChannelsTyped("Mat", $ia, $idx)

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

Func _cveInputArrayIsEmptyTyped($typeOfIa, $ia)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    Local $retval = _cveInputArrayIsEmpty($iArrIa)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayIsEmptyTyped

Func _cveInputArrayIsEmptyMat($ia)
    ; cveInputArrayIsEmpty using cv::Mat instead of _*Array
    Local $retval = _cveInputArrayIsEmptyTyped("Mat", $ia)

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

Func _cveInputArrayReleaseTyped($typeOfArr, $arr)

    Local $iArrArr, $vectorArr, $iArrArrSize
    Local $bArrIsArray = IsArray($arr)
    Local $bArrCreate = IsDllStruct($arr) And $typeOfArr == "Scalar"

    If $typeOfArr == Default Then
        $iArrArr = $arr
    ElseIf $bArrIsArray Then
        $vectorArr = Call("_VectorOf" & $typeOfArr & "Create")

        $iArrArrSize = UBound($arr)
        For $i = 0 To $iArrArrSize - 1
            Call("_VectorOf" & $typeOfArr & "Push", $vectorArr, $arr[$i])
        Next

        $iArrArr = Call("_cveInputArrayFromVectorOf" & $typeOfArr, $vectorArr)
    Else
        If $bArrCreate Then
            $arr = Call("_cve" & $typeOfArr & "Create", $arr)
        EndIf
        $iArrArr = Call("_cveInputArrayFrom" & $typeOfArr, $arr)
    EndIf

    _cveInputArrayRelease($iArrArr)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveInputArrayRelease($iArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf
EndFunc   ;==>_cveInputArrayReleaseTyped

Func _cveInputArrayReleaseMat($arr)
    ; cveInputArrayRelease using cv::Mat instead of _*Array
    _cveInputArrayReleaseTyped("Mat", $arr)
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

Func _cveInputArrayGetMatTyped($typeOfIa, $ia, $idx, $mat)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    _cveInputArrayGetMat($iArrIa, $idx, $mat)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf
EndFunc   ;==>_cveInputArrayGetMatTyped

Func _cveInputArrayGetMatMat($ia, $idx, $mat)
    ; cveInputArrayGetMat using cv::Mat instead of _*Array
    _cveInputArrayGetMatTyped("Mat", $ia, $idx, $mat)
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

Func _cveInputArrayGetUMatTyped($typeOfIa, $ia, $idx, $umat)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    _cveInputArrayGetUMat($iArrIa, $idx, $umat)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf
EndFunc   ;==>_cveInputArrayGetUMatTyped

Func _cveInputArrayGetUMatMat($ia, $idx, $umat)
    ; cveInputArrayGetUMat using cv::Mat instead of _*Array
    _cveInputArrayGetUMatTyped("Mat", $ia, $idx, $umat)
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

Func _cveInputArrayGetGpuMatTyped($typeOfIa, $ia, $gpuMat)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    _cveInputArrayGetGpuMat($iArrIa, $gpuMat)

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf
EndFunc   ;==>_cveInputArrayGetGpuMatTyped

Func _cveInputArrayGetGpuMatMat($ia, $gpuMat)
    ; cveInputArrayGetGpuMat using cv::Mat instead of _*Array
    _cveInputArrayGetGpuMatTyped("Mat", $ia, $gpuMat)
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

Func _cveInputArrayCopyToTyped($typeOfIa, $ia, $typeOfArr, $arr, $typeOfMask, $mask)

    Local $iArrIa, $vectorIa, $iArrIaSize
    Local $bIaIsArray = IsArray($ia)
    Local $bIaCreate = IsDllStruct($ia) And $typeOfIa == "Scalar"

    If $typeOfIa == Default Then
        $iArrIa = $ia
    ElseIf $bIaIsArray Then
        $vectorIa = Call("_VectorOf" & $typeOfIa & "Create")

        $iArrIaSize = UBound($ia)
        For $i = 0 To $iArrIaSize - 1
            Call("_VectorOf" & $typeOfIa & "Push", $vectorIa, $ia[$i])
        Next

        $iArrIa = Call("_cveInputArrayFromVectorOf" & $typeOfIa, $vectorIa)
    Else
        If $bIaCreate Then
            $ia = Call("_cve" & $typeOfIa & "Create", $ia)
        EndIf
        $iArrIa = Call("_cveInputArrayFrom" & $typeOfIa, $ia)
    EndIf

    Local $oArrArr, $vectorArr, $iArrArrSize
    Local $bArrIsArray = IsArray($arr)
    Local $bArrCreate = IsDllStruct($arr) And $typeOfArr == "Scalar"

    If $typeOfArr == Default Then
        $oArrArr = $arr
    ElseIf $bArrIsArray Then
        $vectorArr = Call("_VectorOf" & $typeOfArr & "Create")

        $iArrArrSize = UBound($arr)
        For $i = 0 To $iArrArrSize - 1
            Call("_VectorOf" & $typeOfArr & "Push", $vectorArr, $arr[$i])
        Next

        $oArrArr = Call("_cveOutputArrayFromVectorOf" & $typeOfArr, $vectorArr)
    Else
        If $bArrCreate Then
            $arr = Call("_cve" & $typeOfArr & "Create", $arr)
        EndIf
        $oArrArr = Call("_cveOutputArrayFrom" & $typeOfArr, $arr)
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

    _cveInputArrayCopyTo($iArrIa, $oArrArr, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveOutputArrayRelease($oArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf

    If $bIaIsArray Then
        Call("_VectorOf" & $typeOfIa & "Release", $vectorIa)
    EndIf

    If $typeOfIa <> Default Then
        _cveInputArrayRelease($iArrIa)
        If $bIaCreate Then
            Call("_cve" & $typeOfIa & "Release", $ia)
        EndIf
    EndIf
EndFunc   ;==>_cveInputArrayCopyToTyped

Func _cveInputArrayCopyToMat($ia, $arr, $mask)
    ; cveInputArrayCopyTo using cv::Mat instead of _*Array
    _cveInputArrayCopyToTyped("Mat", $ia, "Mat", $arr, "Mat", $mask)
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

Func _cveOutputArrayReleaseTyped($typeOfArr, $arr)

    Local $oArrArr, $vectorArr, $iArrArrSize
    Local $bArrIsArray = IsArray($arr)
    Local $bArrCreate = IsDllStruct($arr) And $typeOfArr == "Scalar"

    If $typeOfArr == Default Then
        $oArrArr = $arr
    ElseIf $bArrIsArray Then
        $vectorArr = Call("_VectorOf" & $typeOfArr & "Create")

        $iArrArrSize = UBound($arr)
        For $i = 0 To $iArrArrSize - 1
            Call("_VectorOf" & $typeOfArr & "Push", $vectorArr, $arr[$i])
        Next

        $oArrArr = Call("_cveOutputArrayFromVectorOf" & $typeOfArr, $vectorArr)
    Else
        If $bArrCreate Then
            $arr = Call("_cve" & $typeOfArr & "Create", $arr)
        EndIf
        $oArrArr = Call("_cveOutputArrayFrom" & $typeOfArr, $arr)
    EndIf

    _cveOutputArrayRelease($oArrArr)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveOutputArrayRelease($oArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf
EndFunc   ;==>_cveOutputArrayReleaseTyped

Func _cveOutputArrayReleaseMat($arr)
    ; cveOutputArrayRelease using cv::Mat instead of _*Array
    _cveOutputArrayReleaseTyped("Mat", $arr)
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

Func _cveInputOutputArrayReleaseTyped($typeOfArr, $arr)

    Local $ioArrArr, $vectorArr, $iArrArrSize
    Local $bArrIsArray = IsArray($arr)
    Local $bArrCreate = IsDllStruct($arr) And $typeOfArr == "Scalar"

    If $typeOfArr == Default Then
        $ioArrArr = $arr
    ElseIf $bArrIsArray Then
        $vectorArr = Call("_VectorOf" & $typeOfArr & "Create")

        $iArrArrSize = UBound($arr)
        For $i = 0 To $iArrArrSize - 1
            Call("_VectorOf" & $typeOfArr & "Push", $vectorArr, $arr[$i])
        Next

        $ioArrArr = Call("_cveInputOutputArrayFromVectorOf" & $typeOfArr, $vectorArr)
    Else
        If $bArrCreate Then
            $arr = Call("_cve" & $typeOfArr & "Create", $arr)
        EndIf
        $ioArrArr = Call("_cveInputOutputArrayFrom" & $typeOfArr, $arr)
    EndIf

    _cveInputOutputArrayRelease($ioArrArr)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveInputOutputArrayRelease($ioArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf
EndFunc   ;==>_cveInputOutputArrayReleaseTyped

Func _cveInputOutputArrayReleaseMat($arr)
    ; cveInputOutputArrayRelease using cv::Mat instead of _*Array
    _cveInputOutputArrayReleaseTyped("Mat", $arr)
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

Func _cveMinMaxIdxTyped($typeOfSrc, $src, $minVal, $maxVal, $minIdx, $maxIdx, $typeOfMask, $mask)

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

    _cveMinMaxIdx($iArrSrc, $minVal, $maxVal, $minIdx, $maxIdx, $iArrMask)

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
EndFunc   ;==>_cveMinMaxIdxTyped

Func _cveMinMaxIdxMat($src, $minVal, $maxVal, $minIdx, $maxIdx, $mask)
    ; cveMinMaxIdx using cv::Mat instead of _*Array
    _cveMinMaxIdxTyped("Mat", $src, $minVal, $maxVal, $minIdx, $maxIdx, "Mat", $mask)
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

Func _cveMinMaxLocTyped($typeOfSrc, $src, $minVal, $maxVal, $minLoc, $macLoc, $typeOfMask = Default, $mask = _cveNoArray())

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

    _cveMinMaxLoc($iArrSrc, $minVal, $maxVal, $minLoc, $macLoc, $iArrMask)

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
EndFunc   ;==>_cveMinMaxLocTyped

Func _cveMinMaxLocMat($src, $minVal, $maxVal, $minLoc, $macLoc, $mask = _cveNoArrayMat())
    ; cveMinMaxLoc using cv::Mat instead of _*Array
    _cveMinMaxLocTyped("Mat", $src, $minVal, $maxVal, $minLoc, $macLoc, "Mat", $mask)
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

Func _cveBitwiseAndTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask, $mask)

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

    _cveBitwiseAnd($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseAndTyped

Func _cveBitwiseAndMat($src1, $src2, $dst, $mask)
    ; cveBitwiseAnd using cv::Mat instead of _*Array
    _cveBitwiseAndTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask)
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

Func _cveBitwiseNotTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask, $mask)

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

    _cveBitwiseNot($iArrSrc, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseNotTyped

Func _cveBitwiseNotMat($src, $dst, $mask)
    ; cveBitwiseNot using cv::Mat instead of _*Array
    _cveBitwiseNotTyped("Mat", $src, "Mat", $dst, "Mat", $mask)
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

Func _cveBitwiseOrTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask, $mask)

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

    _cveBitwiseOr($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseOrTyped

Func _cveBitwiseOrMat($src1, $src2, $dst, $mask)
    ; cveBitwiseOr using cv::Mat instead of _*Array
    _cveBitwiseOrTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask)
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

Func _cveBitwiseXorTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask, $mask)

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

    _cveBitwiseXor($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask)

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
EndFunc   ;==>_cveBitwiseXorTyped

Func _cveBitwiseXorMat($src1, $src2, $dst, $mask)
    ; cveBitwiseXor using cv::Mat instead of _*Array
    _cveBitwiseXorTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask)
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

Func _cveAddTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask = Default, $mask = _cveNoArray(), $dtype = -1)

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

    _cveAdd($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $dtype)

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
EndFunc   ;==>_cveAddTyped

Func _cveAddMat($src1, $src2, $dst, $mask = _cveNoArrayMat(), $dtype = -1)
    ; cveAdd using cv::Mat instead of _*Array
    _cveAddTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask, $dtype)
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

Func _cveSubtractTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask = Default, $mask = _cveNoArray(), $dtype = -1)

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

    _cveSubtract($iArrSrc1, $iArrSrc2, $oArrDst, $iArrMask, $dtype)

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
EndFunc   ;==>_cveSubtractTyped

Func _cveSubtractMat($src1, $src2, $dst, $mask = _cveNoArrayMat(), $dtype = -1)
    ; cveSubtract using cv::Mat instead of _*Array
    _cveSubtractTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask, $dtype)
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

Func _cveDivideTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $scale = 1, $dtype = -1)

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

    _cveDivide($iArrSrc1, $iArrSrc2, $oArrDst, $scale, $dtype)

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
EndFunc   ;==>_cveDivideTyped

Func _cveDivideMat($src1, $src2, $dst, $scale = 1, $dtype = -1)
    ; cveDivide using cv::Mat instead of _*Array
    _cveDivideTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $scale, $dtype)
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

Func _cveMultiplyTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $scale = 1, $dtype = -1)

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

    _cveMultiply($iArrSrc1, $iArrSrc2, $oArrDst, $scale, $dtype)

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
EndFunc   ;==>_cveMultiplyTyped

Func _cveMultiplyMat($src1, $src2, $dst, $scale = 1, $dtype = -1)
    ; cveMultiply using cv::Mat instead of _*Array
    _cveMultiplyTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $scale, $dtype)
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

Func _cveCountNonZeroTyped($typeOfSrc, $src)

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

    _cveCountNonZero($iArrSrc)

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveCountNonZeroTyped

Func _cveCountNonZeroMat($src)
    ; cveCountNonZero using cv::Mat instead of _*Array
    _cveCountNonZeroTyped("Mat", $src)
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

Func _cveFindNonZeroTyped($typeOfSrc, $src, $typeOfIdx, $idx)

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

    Local $oArrIdx, $vectorIdx, $iArrIdxSize
    Local $bIdxIsArray = IsArray($idx)
    Local $bIdxCreate = IsDllStruct($idx) And $typeOfIdx == "Scalar"

    If $typeOfIdx == Default Then
        $oArrIdx = $idx
    ElseIf $bIdxIsArray Then
        $vectorIdx = Call("_VectorOf" & $typeOfIdx & "Create")

        $iArrIdxSize = UBound($idx)
        For $i = 0 To $iArrIdxSize - 1
            Call("_VectorOf" & $typeOfIdx & "Push", $vectorIdx, $idx[$i])
        Next

        $oArrIdx = Call("_cveOutputArrayFromVectorOf" & $typeOfIdx, $vectorIdx)
    Else
        If $bIdxCreate Then
            $idx = Call("_cve" & $typeOfIdx & "Create", $idx)
        EndIf
        $oArrIdx = Call("_cveOutputArrayFrom" & $typeOfIdx, $idx)
    EndIf

    _cveFindNonZero($iArrSrc, $oArrIdx)

    If $bIdxIsArray Then
        Call("_VectorOf" & $typeOfIdx & "Release", $vectorIdx)
    EndIf

    If $typeOfIdx <> Default Then
        _cveOutputArrayRelease($oArrIdx)
        If $bIdxCreate Then
            Call("_cve" & $typeOfIdx & "Release", $idx)
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
EndFunc   ;==>_cveFindNonZeroTyped

Func _cveFindNonZeroMat($src, $idx)
    ; cveFindNonZero using cv::Mat instead of _*Array
    _cveFindNonZeroTyped("Mat", $src, "Mat", $idx)
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

Func _cveMinTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst)

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

    _cveMin($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveMinTyped

Func _cveMinMat($src1, $src2, $dst)
    ; cveMin using cv::Mat instead of _*Array
    _cveMinTyped("Mat", $src1, "Mat", $src2, "Mat", $dst)
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

Func _cveMaxTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst)

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

    _cveMax($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveMaxTyped

Func _cveMaxMat($src1, $src2, $dst)
    ; cveMax using cv::Mat instead of _*Array
    _cveMaxTyped("Mat", $src1, "Mat", $src2, "Mat", $dst)
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

Func _cveAbsDiffTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst)

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

    _cveAbsDiff($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveAbsDiffTyped

Func _cveAbsDiffMat($src1, $src2, $dst)
    ; cveAbsDiff using cv::Mat instead of _*Array
    _cveAbsDiffTyped("Mat", $src1, "Mat", $src2, "Mat", $dst)
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

Func _cveInRangeTyped($typeOfSrc1, $src1, $typeOfLowerb, $lowerb, $typeOfUpperb, $upperb, $typeOfDst, $dst)

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

    Local $iArrLowerb, $vectorLowerb, $iArrLowerbSize
    Local $bLowerbIsArray = IsArray($lowerb)
    Local $bLowerbCreate = IsDllStruct($lowerb) And $typeOfLowerb == "Scalar"

    If $typeOfLowerb == Default Then
        $iArrLowerb = $lowerb
    ElseIf $bLowerbIsArray Then
        $vectorLowerb = Call("_VectorOf" & $typeOfLowerb & "Create")

        $iArrLowerbSize = UBound($lowerb)
        For $i = 0 To $iArrLowerbSize - 1
            Call("_VectorOf" & $typeOfLowerb & "Push", $vectorLowerb, $lowerb[$i])
        Next

        $iArrLowerb = Call("_cveInputArrayFromVectorOf" & $typeOfLowerb, $vectorLowerb)
    Else
        If $bLowerbCreate Then
            $lowerb = Call("_cve" & $typeOfLowerb & "Create", $lowerb)
        EndIf
        $iArrLowerb = Call("_cveInputArrayFrom" & $typeOfLowerb, $lowerb)
    EndIf

    Local $iArrUpperb, $vectorUpperb, $iArrUpperbSize
    Local $bUpperbIsArray = IsArray($upperb)
    Local $bUpperbCreate = IsDllStruct($upperb) And $typeOfUpperb == "Scalar"

    If $typeOfUpperb == Default Then
        $iArrUpperb = $upperb
    ElseIf $bUpperbIsArray Then
        $vectorUpperb = Call("_VectorOf" & $typeOfUpperb & "Create")

        $iArrUpperbSize = UBound($upperb)
        For $i = 0 To $iArrUpperbSize - 1
            Call("_VectorOf" & $typeOfUpperb & "Push", $vectorUpperb, $upperb[$i])
        Next

        $iArrUpperb = Call("_cveInputArrayFromVectorOf" & $typeOfUpperb, $vectorUpperb)
    Else
        If $bUpperbCreate Then
            $upperb = Call("_cve" & $typeOfUpperb & "Create", $upperb)
        EndIf
        $iArrUpperb = Call("_cveInputArrayFrom" & $typeOfUpperb, $upperb)
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

    _cveInRange($iArrSrc1, $iArrLowerb, $iArrUpperb, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bUpperbIsArray Then
        Call("_VectorOf" & $typeOfUpperb & "Release", $vectorUpperb)
    EndIf

    If $typeOfUpperb <> Default Then
        _cveInputArrayRelease($iArrUpperb)
        If $bUpperbCreate Then
            Call("_cve" & $typeOfUpperb & "Release", $upperb)
        EndIf
    EndIf

    If $bLowerbIsArray Then
        Call("_VectorOf" & $typeOfLowerb & "Release", $vectorLowerb)
    EndIf

    If $typeOfLowerb <> Default Then
        _cveInputArrayRelease($iArrLowerb)
        If $bLowerbCreate Then
            Call("_cve" & $typeOfLowerb & "Release", $lowerb)
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
EndFunc   ;==>_cveInRangeTyped

Func _cveInRangeMat($src1, $lowerb, $upperb, $dst)
    ; cveInRange using cv::Mat instead of _*Array
    _cveInRangeTyped("Mat", $src1, "Mat", $lowerb, "Mat", $upperb, "Mat", $dst)
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

Func _cveSqrtTyped($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveSqrt($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveSqrtTyped

Func _cveSqrtMat($src, $dst)
    ; cveSqrt using cv::Mat instead of _*Array
    _cveSqrtTyped("Mat", $src, "Mat", $dst)
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

Func _cveCompareTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $compop)

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

    _cveCompare($iArrSrc1, $iArrSrc2, $oArrDst, $compop)

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
EndFunc   ;==>_cveCompareTyped

Func _cveCompareMat($src1, $src2, $dst, $compop)
    ; cveCompare using cv::Mat instead of _*Array
    _cveCompareTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $compop)
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

Func _cveFlipTyped($typeOfSrc, $src, $typeOfDst, $dst, $flipCode)

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

    _cveFlip($iArrSrc, $oArrDst, $flipCode)

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
EndFunc   ;==>_cveFlipTyped

Func _cveFlipMat($src, $dst, $flipCode)
    ; cveFlip using cv::Mat instead of _*Array
    _cveFlipTyped("Mat", $src, "Mat", $dst, $flipCode)
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

Func _cveRotateTyped($typeOfSrc, $src, $typeOfDst, $dst, $rotateCode)

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

    _cveRotate($iArrSrc, $oArrDst, $rotateCode)

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
EndFunc   ;==>_cveRotateTyped

Func _cveRotateMat($src, $dst, $rotateCode)
    ; cveRotate using cv::Mat instead of _*Array
    _cveRotateTyped("Mat", $src, "Mat", $dst, $rotateCode)
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

Func _cveTransposeTyped($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveTranspose($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveTransposeTyped

Func _cveTransposeMat($src, $dst)
    ; cveTranspose using cv::Mat instead of _*Array
    _cveTransposeTyped("Mat", $src, "Mat", $dst)
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

Func _cveLUTTyped($typeOfSrc, $src, $typeOfLut, $lut, $typeOfDst, $dst)

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

    _cveLUT($iArrSrc, $iArrLut, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bLutIsArray Then
        Call("_VectorOf" & $typeOfLut & "Release", $vectorLut)
    EndIf

    If $typeOfLut <> Default Then
        _cveInputArrayRelease($iArrLut)
        If $bLutCreate Then
            Call("_cve" & $typeOfLut & "Release", $lut)
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
EndFunc   ;==>_cveLUTTyped

Func _cveLUTMat($src, $lut, $dst)
    ; cveLUT using cv::Mat instead of _*Array
    _cveLUTTyped("Mat", $src, "Mat", $lut, "Mat", $dst)
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

Func _cveSumTyped($typeOfSrc, $src, $result)

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

    _cveSum($iArrSrc, $result)

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveSumTyped

Func _cveSumMat($src, $result)
    ; cveSum using cv::Mat instead of _*Array
    _cveSumTyped("Mat", $src, $result)
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

Func _cveMeanTyped($typeOfSrc, $src, $typeOfMask, $mask, $result)

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

    _cveMean($iArrSrc, $iArrMask, $result)

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
EndFunc   ;==>_cveMeanTyped

Func _cveMeanMat($src, $mask, $result)
    ; cveMean using cv::Mat instead of _*Array
    _cveMeanTyped("Mat", $src, "Mat", $mask, $result)
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

Func _cveMeanStdDevTyped($typeOfSrc, $src, $typeOfMean, $mean, $typeOfStddev, $stddev, $typeOfMask = Default, $mask = _cveNoArray())

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

    Local $oArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $oArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $oArrMean = Call("_cveOutputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $oArrMean = Call("_cveOutputArrayFrom" & $typeOfMean, $mean)
    EndIf

    Local $oArrStddev, $vectorStddev, $iArrStddevSize
    Local $bStddevIsArray = IsArray($stddev)
    Local $bStddevCreate = IsDllStruct($stddev) And $typeOfStddev == "Scalar"

    If $typeOfStddev == Default Then
        $oArrStddev = $stddev
    ElseIf $bStddevIsArray Then
        $vectorStddev = Call("_VectorOf" & $typeOfStddev & "Create")

        $iArrStddevSize = UBound($stddev)
        For $i = 0 To $iArrStddevSize - 1
            Call("_VectorOf" & $typeOfStddev & "Push", $vectorStddev, $stddev[$i])
        Next

        $oArrStddev = Call("_cveOutputArrayFromVectorOf" & $typeOfStddev, $vectorStddev)
    Else
        If $bStddevCreate Then
            $stddev = Call("_cve" & $typeOfStddev & "Create", $stddev)
        EndIf
        $oArrStddev = Call("_cveOutputArrayFrom" & $typeOfStddev, $stddev)
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

    _cveMeanStdDev($iArrSrc, $oArrMean, $oArrStddev, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bStddevIsArray Then
        Call("_VectorOf" & $typeOfStddev & "Release", $vectorStddev)
    EndIf

    If $typeOfStddev <> Default Then
        _cveOutputArrayRelease($oArrStddev)
        If $bStddevCreate Then
            Call("_cve" & $typeOfStddev & "Release", $stddev)
        EndIf
    EndIf

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveOutputArrayRelease($oArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
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
EndFunc   ;==>_cveMeanStdDevTyped

Func _cveMeanStdDevMat($src, $mean, $stddev, $mask = _cveNoArrayMat())
    ; cveMeanStdDev using cv::Mat instead of _*Array
    _cveMeanStdDevTyped("Mat", $src, "Mat", $mean, "Mat", $stddev, "Mat", $mask)
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

Func _cveTraceTyped($typeOfMtx, $mtx, $result)

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

    _cveTrace($iArrMtx, $result)

    If $bMtxIsArray Then
        Call("_VectorOf" & $typeOfMtx & "Release", $vectorMtx)
    EndIf

    If $typeOfMtx <> Default Then
        _cveInputArrayRelease($iArrMtx)
        If $bMtxCreate Then
            Call("_cve" & $typeOfMtx & "Release", $mtx)
        EndIf
    EndIf
EndFunc   ;==>_cveTraceTyped

Func _cveTraceMat($mtx, $result)
    ; cveTrace using cv::Mat instead of _*Array
    _cveTraceTyped("Mat", $mtx, $result)
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

Func _cveDeterminantTyped($typeOfMtx, $mtx)

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

    Local $retval = _cveDeterminant($iArrMtx)

    If $bMtxIsArray Then
        Call("_VectorOf" & $typeOfMtx & "Release", $vectorMtx)
    EndIf

    If $typeOfMtx <> Default Then
        _cveInputArrayRelease($iArrMtx)
        If $bMtxCreate Then
            Call("_cve" & $typeOfMtx & "Release", $mtx)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveDeterminantTyped

Func _cveDeterminantMat($mtx)
    ; cveDeterminant using cv::Mat instead of _*Array
    Local $retval = _cveDeterminantTyped("Mat", $mtx)

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

Func _cveNormTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $normType = $CV_NORM_L2, $typeOfMask = Default, $mask = _cveNoArray())

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

    Local $retval = _cveNorm($iArrSrc1, $iArrSrc2, $normType, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
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

    Return $retval
EndFunc   ;==>_cveNormTyped

Func _cveNormMat($src1, $src2, $normType = $CV_NORM_L2, $mask = _cveNoArrayMat())
    ; cveNorm using cv::Mat instead of _*Array
    Local $retval = _cveNormTyped("Mat", $src1, "Mat", $src2, $normType, "Mat", $mask)

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

Func _cveCheckRangeTyped($typeOfArr, $arr, $quiet, $index, $minVal = -$CV_DBL_MAX, $maxVal = $CV_DBL_MAX)

    Local $iArrArr, $vectorArr, $iArrArrSize
    Local $bArrIsArray = IsArray($arr)
    Local $bArrCreate = IsDllStruct($arr) And $typeOfArr == "Scalar"

    If $typeOfArr == Default Then
        $iArrArr = $arr
    ElseIf $bArrIsArray Then
        $vectorArr = Call("_VectorOf" & $typeOfArr & "Create")

        $iArrArrSize = UBound($arr)
        For $i = 0 To $iArrArrSize - 1
            Call("_VectorOf" & $typeOfArr & "Push", $vectorArr, $arr[$i])
        Next

        $iArrArr = Call("_cveInputArrayFromVectorOf" & $typeOfArr, $vectorArr)
    Else
        If $bArrCreate Then
            $arr = Call("_cve" & $typeOfArr & "Create", $arr)
        EndIf
        $iArrArr = Call("_cveInputArrayFrom" & $typeOfArr, $arr)
    EndIf

    Local $retval = _cveCheckRange($iArrArr, $quiet, $index, $minVal, $maxVal)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveInputArrayRelease($iArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveCheckRangeTyped

Func _cveCheckRangeMat($arr, $quiet, $index, $minVal = -$CV_DBL_MAX, $maxVal = $CV_DBL_MAX)
    ; cveCheckRange using cv::Mat instead of _*Array
    Local $retval = _cveCheckRangeTyped("Mat", $arr, $quiet, $index, $minVal, $maxVal)

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

Func _cvePatchNaNsTyped($typeOfA, $a, $val = 0)

    Local $ioArrA, $vectorA, $iArrASize
    Local $bAIsArray = IsArray($a)
    Local $bACreate = IsDllStruct($a) And $typeOfA == "Scalar"

    If $typeOfA == Default Then
        $ioArrA = $a
    ElseIf $bAIsArray Then
        $vectorA = Call("_VectorOf" & $typeOfA & "Create")

        $iArrASize = UBound($a)
        For $i = 0 To $iArrASize - 1
            Call("_VectorOf" & $typeOfA & "Push", $vectorA, $a[$i])
        Next

        $ioArrA = Call("_cveInputOutputArrayFromVectorOf" & $typeOfA, $vectorA)
    Else
        If $bACreate Then
            $a = Call("_cve" & $typeOfA & "Create", $a)
        EndIf
        $ioArrA = Call("_cveInputOutputArrayFrom" & $typeOfA, $a)
    EndIf

    _cvePatchNaNs($ioArrA, $val)

    If $bAIsArray Then
        Call("_VectorOf" & $typeOfA & "Release", $vectorA)
    EndIf

    If $typeOfA <> Default Then
        _cveInputOutputArrayRelease($ioArrA)
        If $bACreate Then
            Call("_cve" & $typeOfA & "Release", $a)
        EndIf
    EndIf
EndFunc   ;==>_cvePatchNaNsTyped

Func _cvePatchNaNsMat($a, $val = 0)
    ; cvePatchNaNs using cv::Mat instead of _*Array
    _cvePatchNaNsTyped("Mat", $a, $val)
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

Func _cveGemmTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $alpha, $typeOfSrc3, $src3, $beta, $typeOfDst, $dst, $flags = 0)

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

    _cveGemm($iArrSrc1, $iArrSrc2, $alpha, $iArrSrc3, $beta, $oArrDst, $flags)

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
EndFunc   ;==>_cveGemmTyped

Func _cveGemmMat($src1, $src2, $alpha, $src3, $beta, $dst, $flags = 0)
    ; cveGemm using cv::Mat instead of _*Array
    _cveGemmTyped("Mat", $src1, "Mat", $src2, $alpha, "Mat", $src3, $beta, "Mat", $dst, $flags)
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

Func _cveScaleAddTyped($typeOfSrc1, $src1, $alpha, $typeOfSrc2, $src2, $typeOfDst, $dst)

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

    _cveScaleAdd($iArrSrc1, $alpha, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveScaleAddTyped

Func _cveScaleAddMat($src1, $alpha, $src2, $dst)
    ; cveScaleAdd using cv::Mat instead of _*Array
    _cveScaleAddTyped("Mat", $src1, $alpha, "Mat", $src2, "Mat", $dst)
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

Func _cveAddWeightedTyped($typeOfSrc1, $src1, $alpha, $typeOfSrc2, $src2, $beta, $gamma, $typeOfDst, $dst, $dtype = -1)

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

    _cveAddWeighted($iArrSrc1, $alpha, $iArrSrc2, $beta, $gamma, $oArrDst, $dtype)

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
EndFunc   ;==>_cveAddWeightedTyped

Func _cveAddWeightedMat($src1, $alpha, $src2, $beta, $gamma, $dst, $dtype = -1)
    ; cveAddWeighted using cv::Mat instead of _*Array
    _cveAddWeightedTyped("Mat", $src1, $alpha, "Mat", $src2, $beta, $gamma, "Mat", $dst, $dtype)
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

Func _cveConvertScaleAbsTyped($typeOfSrc, $src, $typeOfDst, $dst, $alpha = 1, $beta = 0)

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

    _cveConvertScaleAbs($iArrSrc, $oArrDst, $alpha, $beta)

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
EndFunc   ;==>_cveConvertScaleAbsTyped

Func _cveConvertScaleAbsMat($src, $dst, $alpha = 1, $beta = 0)
    ; cveConvertScaleAbs using cv::Mat instead of _*Array
    _cveConvertScaleAbsTyped("Mat", $src, "Mat", $dst, $alpha, $beta)
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

Func _cveReduceTyped($typeOfSrc, $src, $typeOfDst, $dst, $dim, $rtype, $dtype = -1)

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

    _cveReduce($iArrSrc, $oArrDst, $dim, $rtype, $dtype)

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
EndFunc   ;==>_cveReduceTyped

Func _cveReduceMat($src, $dst, $dim, $rtype, $dtype = -1)
    ; cveReduce using cv::Mat instead of _*Array
    _cveReduceTyped("Mat", $src, "Mat", $dst, $dim, $rtype, $dtype)
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

Func _cveRandShuffleTyped($typeOfDst, $dst, $iterFactor = 1.0, $rng = 0)

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveRandShuffle($ioArrDst, $iterFactor, $rng)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputOutputArrayRelease($ioArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveRandShuffleTyped

Func _cveRandShuffleMat($dst, $iterFactor = 1.0, $rng = 0)
    ; cveRandShuffle using cv::Mat instead of _*Array
    _cveRandShuffleTyped("Mat", $dst, $iterFactor, $rng)
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

Func _cvePowTyped($typeOfSrc, $src, $power, $typeOfDst, $dst)

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

    _cvePow($iArrSrc, $power, $oArrDst)

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
EndFunc   ;==>_cvePowTyped

Func _cvePowMat($src, $power, $dst)
    ; cvePow using cv::Mat instead of _*Array
    _cvePowTyped("Mat", $src, $power, "Mat", $dst)
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

Func _cveExpTyped($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveExp($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveExpTyped

Func _cveExpMat($src, $dst)
    ; cveExp using cv::Mat instead of _*Array
    _cveExpTyped("Mat", $src, "Mat", $dst)
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

Func _cveLogTyped($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveLog($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveLogTyped

Func _cveLogMat($src, $dst)
    ; cveLog using cv::Mat instead of _*Array
    _cveLogTyped("Mat", $src, "Mat", $dst)
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

Func _cveCartToPolarTyped($typeOfX, $x, $typeOfY, $y, $typeOfMagnitude, $magnitude, $typeOfAngle, $angle, $angleInDegrees = false)

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

    _cveCartToPolar($iArrX, $iArrY, $oArrMagnitude, $oArrAngle, $angleInDegrees)

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
EndFunc   ;==>_cveCartToPolarTyped

Func _cveCartToPolarMat($x, $y, $magnitude, $angle, $angleInDegrees = false)
    ; cveCartToPolar using cv::Mat instead of _*Array
    _cveCartToPolarTyped("Mat", $x, "Mat", $y, "Mat", $magnitude, "Mat", $angle, $angleInDegrees)
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

Func _cvePolarToCartTyped($typeOfMagnitude, $magnitude, $typeOfAngle, $angle, $typeOfX, $x, $typeOfY, $y, $angleInDegrees = false)

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

    _cvePolarToCart($iArrMagnitude, $iArrAngle, $oArrX, $oArrY, $angleInDegrees)

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
EndFunc   ;==>_cvePolarToCartTyped

Func _cvePolarToCartMat($magnitude, $angle, $x, $y, $angleInDegrees = false)
    ; cvePolarToCart using cv::Mat instead of _*Array
    _cvePolarToCartTyped("Mat", $magnitude, "Mat", $angle, "Mat", $x, "Mat", $y, $angleInDegrees)
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

Func _cveSetIdentityTyped($typeOfMtx, $mtx, $scalar)

    Local $ioArrMtx, $vectorMtx, $iArrMtxSize
    Local $bMtxIsArray = IsArray($mtx)
    Local $bMtxCreate = IsDllStruct($mtx) And $typeOfMtx == "Scalar"

    If $typeOfMtx == Default Then
        $ioArrMtx = $mtx
    ElseIf $bMtxIsArray Then
        $vectorMtx = Call("_VectorOf" & $typeOfMtx & "Create")

        $iArrMtxSize = UBound($mtx)
        For $i = 0 To $iArrMtxSize - 1
            Call("_VectorOf" & $typeOfMtx & "Push", $vectorMtx, $mtx[$i])
        Next

        $ioArrMtx = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMtx, $vectorMtx)
    Else
        If $bMtxCreate Then
            $mtx = Call("_cve" & $typeOfMtx & "Create", $mtx)
        EndIf
        $ioArrMtx = Call("_cveInputOutputArrayFrom" & $typeOfMtx, $mtx)
    EndIf

    _cveSetIdentity($ioArrMtx, $scalar)

    If $bMtxIsArray Then
        Call("_VectorOf" & $typeOfMtx & "Release", $vectorMtx)
    EndIf

    If $typeOfMtx <> Default Then
        _cveInputOutputArrayRelease($ioArrMtx)
        If $bMtxCreate Then
            Call("_cve" & $typeOfMtx & "Release", $mtx)
        EndIf
    EndIf
EndFunc   ;==>_cveSetIdentityTyped

Func _cveSetIdentityMat($mtx, $scalar)
    ; cveSetIdentity using cv::Mat instead of _*Array
    _cveSetIdentityTyped("Mat", $mtx, $scalar)
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

Func _cveSolveCubicTyped($typeOfCoeffs, $coeffs, $typeOfRoots, $roots)

    Local $iArrCoeffs, $vectorCoeffs, $iArrCoeffsSize
    Local $bCoeffsIsArray = IsArray($coeffs)
    Local $bCoeffsCreate = IsDllStruct($coeffs) And $typeOfCoeffs == "Scalar"

    If $typeOfCoeffs == Default Then
        $iArrCoeffs = $coeffs
    ElseIf $bCoeffsIsArray Then
        $vectorCoeffs = Call("_VectorOf" & $typeOfCoeffs & "Create")

        $iArrCoeffsSize = UBound($coeffs)
        For $i = 0 To $iArrCoeffsSize - 1
            Call("_VectorOf" & $typeOfCoeffs & "Push", $vectorCoeffs, $coeffs[$i])
        Next

        $iArrCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfCoeffs, $vectorCoeffs)
    Else
        If $bCoeffsCreate Then
            $coeffs = Call("_cve" & $typeOfCoeffs & "Create", $coeffs)
        EndIf
        $iArrCoeffs = Call("_cveInputArrayFrom" & $typeOfCoeffs, $coeffs)
    EndIf

    Local $oArrRoots, $vectorRoots, $iArrRootsSize
    Local $bRootsIsArray = IsArray($roots)
    Local $bRootsCreate = IsDllStruct($roots) And $typeOfRoots == "Scalar"

    If $typeOfRoots == Default Then
        $oArrRoots = $roots
    ElseIf $bRootsIsArray Then
        $vectorRoots = Call("_VectorOf" & $typeOfRoots & "Create")

        $iArrRootsSize = UBound($roots)
        For $i = 0 To $iArrRootsSize - 1
            Call("_VectorOf" & $typeOfRoots & "Push", $vectorRoots, $roots[$i])
        Next

        $oArrRoots = Call("_cveOutputArrayFromVectorOf" & $typeOfRoots, $vectorRoots)
    Else
        If $bRootsCreate Then
            $roots = Call("_cve" & $typeOfRoots & "Create", $roots)
        EndIf
        $oArrRoots = Call("_cveOutputArrayFrom" & $typeOfRoots, $roots)
    EndIf

    Local $retval = _cveSolveCubic($iArrCoeffs, $oArrRoots)

    If $bRootsIsArray Then
        Call("_VectorOf" & $typeOfRoots & "Release", $vectorRoots)
    EndIf

    If $typeOfRoots <> Default Then
        _cveOutputArrayRelease($oArrRoots)
        If $bRootsCreate Then
            Call("_cve" & $typeOfRoots & "Release", $roots)
        EndIf
    EndIf

    If $bCoeffsIsArray Then
        Call("_VectorOf" & $typeOfCoeffs & "Release", $vectorCoeffs)
    EndIf

    If $typeOfCoeffs <> Default Then
        _cveInputArrayRelease($iArrCoeffs)
        If $bCoeffsCreate Then
            Call("_cve" & $typeOfCoeffs & "Release", $coeffs)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSolveCubicTyped

Func _cveSolveCubicMat($coeffs, $roots)
    ; cveSolveCubic using cv::Mat instead of _*Array
    Local $retval = _cveSolveCubicTyped("Mat", $coeffs, "Mat", $roots)

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

Func _cveSolvePolyTyped($typeOfCoeffs, $coeffs, $typeOfRoots, $roots, $maxIters = 300)

    Local $iArrCoeffs, $vectorCoeffs, $iArrCoeffsSize
    Local $bCoeffsIsArray = IsArray($coeffs)
    Local $bCoeffsCreate = IsDllStruct($coeffs) And $typeOfCoeffs == "Scalar"

    If $typeOfCoeffs == Default Then
        $iArrCoeffs = $coeffs
    ElseIf $bCoeffsIsArray Then
        $vectorCoeffs = Call("_VectorOf" & $typeOfCoeffs & "Create")

        $iArrCoeffsSize = UBound($coeffs)
        For $i = 0 To $iArrCoeffsSize - 1
            Call("_VectorOf" & $typeOfCoeffs & "Push", $vectorCoeffs, $coeffs[$i])
        Next

        $iArrCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfCoeffs, $vectorCoeffs)
    Else
        If $bCoeffsCreate Then
            $coeffs = Call("_cve" & $typeOfCoeffs & "Create", $coeffs)
        EndIf
        $iArrCoeffs = Call("_cveInputArrayFrom" & $typeOfCoeffs, $coeffs)
    EndIf

    Local $oArrRoots, $vectorRoots, $iArrRootsSize
    Local $bRootsIsArray = IsArray($roots)
    Local $bRootsCreate = IsDllStruct($roots) And $typeOfRoots == "Scalar"

    If $typeOfRoots == Default Then
        $oArrRoots = $roots
    ElseIf $bRootsIsArray Then
        $vectorRoots = Call("_VectorOf" & $typeOfRoots & "Create")

        $iArrRootsSize = UBound($roots)
        For $i = 0 To $iArrRootsSize - 1
            Call("_VectorOf" & $typeOfRoots & "Push", $vectorRoots, $roots[$i])
        Next

        $oArrRoots = Call("_cveOutputArrayFromVectorOf" & $typeOfRoots, $vectorRoots)
    Else
        If $bRootsCreate Then
            $roots = Call("_cve" & $typeOfRoots & "Create", $roots)
        EndIf
        $oArrRoots = Call("_cveOutputArrayFrom" & $typeOfRoots, $roots)
    EndIf

    Local $retval = _cveSolvePoly($iArrCoeffs, $oArrRoots, $maxIters)

    If $bRootsIsArray Then
        Call("_VectorOf" & $typeOfRoots & "Release", $vectorRoots)
    EndIf

    If $typeOfRoots <> Default Then
        _cveOutputArrayRelease($oArrRoots)
        If $bRootsCreate Then
            Call("_cve" & $typeOfRoots & "Release", $roots)
        EndIf
    EndIf

    If $bCoeffsIsArray Then
        Call("_VectorOf" & $typeOfCoeffs & "Release", $vectorCoeffs)
    EndIf

    If $typeOfCoeffs <> Default Then
        _cveInputArrayRelease($iArrCoeffs)
        If $bCoeffsCreate Then
            Call("_cve" & $typeOfCoeffs & "Release", $coeffs)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSolvePolyTyped

Func _cveSolvePolyMat($coeffs, $roots, $maxIters = 300)
    ; cveSolvePoly using cv::Mat instead of _*Array
    Local $retval = _cveSolvePolyTyped("Mat", $coeffs, "Mat", $roots, $maxIters)

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

Func _cveSolveTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $flags = $CV_DECOMP_LU)

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

    _cveSolve($iArrSrc1, $iArrSrc2, $oArrDst, $flags)

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
EndFunc   ;==>_cveSolveTyped

Func _cveSolveMat($src1, $src2, $dst, $flags = $CV_DECOMP_LU)
    ; cveSolve using cv::Mat instead of _*Array
    _cveSolveTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, $flags)
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

Func _cveSortTyped($typeOfSrc, $src, $typeOfDst, $dst, $flags)

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

    _cveSort($iArrSrc, $oArrDst, $flags)

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
EndFunc   ;==>_cveSortTyped

Func _cveSortMat($src, $dst, $flags)
    ; cveSort using cv::Mat instead of _*Array
    _cveSortTyped("Mat", $src, "Mat", $dst, $flags)
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

Func _cveSortIdxTyped($typeOfSrc, $src, $typeOfDst, $dst, $flags)

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

    _cveSortIdx($iArrSrc, $oArrDst, $flags)

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
EndFunc   ;==>_cveSortIdxTyped

Func _cveSortIdxMat($src, $dst, $flags)
    ; cveSortIdx using cv::Mat instead of _*Array
    _cveSortIdxTyped("Mat", $src, "Mat", $dst, $flags)
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

Func _cveInvertTyped($typeOfSrc, $src, $typeOfDst, $dst, $flags = $CV_DECOMP_LU)

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

    _cveInvert($iArrSrc, $oArrDst, $flags)

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
EndFunc   ;==>_cveInvertTyped

Func _cveInvertMat($src, $dst, $flags = $CV_DECOMP_LU)
    ; cveInvert using cv::Mat instead of _*Array
    _cveInvertTyped("Mat", $src, "Mat", $dst, $flags)
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

Func _cveDftTyped($typeOfSrc, $src, $typeOfDst, $dst, $flags = 0, $nonzeroRows = 0)

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

    _cveDft($iArrSrc, $oArrDst, $flags, $nonzeroRows)

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
EndFunc   ;==>_cveDftTyped

Func _cveDftMat($src, $dst, $flags = 0, $nonzeroRows = 0)
    ; cveDft using cv::Mat instead of _*Array
    _cveDftTyped("Mat", $src, "Mat", $dst, $flags, $nonzeroRows)
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

Func _cveDctTyped($typeOfSrc, $src, $typeOfDst, $dst, $flags = 0)

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

    _cveDct($iArrSrc, $oArrDst, $flags)

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
EndFunc   ;==>_cveDctTyped

Func _cveDctMat($src, $dst, $flags = 0)
    ; cveDct using cv::Mat instead of _*Array
    _cveDctTyped("Mat", $src, "Mat", $dst, $flags)
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

Func _cveMulSpectrumsTyped($typeOfA, $a, $typeOfB, $b, $typeOfC, $c, $flags, $conjB = false)

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

    _cveMulSpectrums($iArrA, $iArrB, $oArrC, $flags, $conjB)

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
EndFunc   ;==>_cveMulSpectrumsTyped

Func _cveMulSpectrumsMat($a, $b, $c, $flags, $conjB = false)
    ; cveMulSpectrums using cv::Mat instead of _*Array
    _cveMulSpectrumsTyped("Mat", $a, "Mat", $b, "Mat", $c, $flags, $conjB)
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

Func _cveTransformTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfM, $m)

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

    Local $iArrM, $vectorM, $iArrMSize
    Local $bMIsArray = IsArray($m)
    Local $bMCreate = IsDllStruct($m) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $m
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($m)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $m[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $m = Call("_cve" & $typeOfM & "Create", $m)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $m)
    EndIf

    _cveTransform($iArrSrc, $oArrDst, $iArrM)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
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
EndFunc   ;==>_cveTransformTyped

Func _cveTransformMat($src, $dst, $m)
    ; cveTransform using cv::Mat instead of _*Array
    _cveTransformTyped("Mat", $src, "Mat", $dst, "Mat", $m)
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

Func _cveMahalanobisTyped($typeOfV1, $v1, $typeOfV2, $v2, $typeOfIcovar, $icovar)

    Local $iArrV1, $vectorV1, $iArrV1Size
    Local $bV1IsArray = IsArray($v1)
    Local $bV1Create = IsDllStruct($v1) And $typeOfV1 == "Scalar"

    If $typeOfV1 == Default Then
        $iArrV1 = $v1
    ElseIf $bV1IsArray Then
        $vectorV1 = Call("_VectorOf" & $typeOfV1 & "Create")

        $iArrV1Size = UBound($v1)
        For $i = 0 To $iArrV1Size - 1
            Call("_VectorOf" & $typeOfV1 & "Push", $vectorV1, $v1[$i])
        Next

        $iArrV1 = Call("_cveInputArrayFromVectorOf" & $typeOfV1, $vectorV1)
    Else
        If $bV1Create Then
            $v1 = Call("_cve" & $typeOfV1 & "Create", $v1)
        EndIf
        $iArrV1 = Call("_cveInputArrayFrom" & $typeOfV1, $v1)
    EndIf

    Local $iArrV2, $vectorV2, $iArrV2Size
    Local $bV2IsArray = IsArray($v2)
    Local $bV2Create = IsDllStruct($v2) And $typeOfV2 == "Scalar"

    If $typeOfV2 == Default Then
        $iArrV2 = $v2
    ElseIf $bV2IsArray Then
        $vectorV2 = Call("_VectorOf" & $typeOfV2 & "Create")

        $iArrV2Size = UBound($v2)
        For $i = 0 To $iArrV2Size - 1
            Call("_VectorOf" & $typeOfV2 & "Push", $vectorV2, $v2[$i])
        Next

        $iArrV2 = Call("_cveInputArrayFromVectorOf" & $typeOfV2, $vectorV2)
    Else
        If $bV2Create Then
            $v2 = Call("_cve" & $typeOfV2 & "Create", $v2)
        EndIf
        $iArrV2 = Call("_cveInputArrayFrom" & $typeOfV2, $v2)
    EndIf

    Local $iArrIcovar, $vectorIcovar, $iArrIcovarSize
    Local $bIcovarIsArray = IsArray($icovar)
    Local $bIcovarCreate = IsDllStruct($icovar) And $typeOfIcovar == "Scalar"

    If $typeOfIcovar == Default Then
        $iArrIcovar = $icovar
    ElseIf $bIcovarIsArray Then
        $vectorIcovar = Call("_VectorOf" & $typeOfIcovar & "Create")

        $iArrIcovarSize = UBound($icovar)
        For $i = 0 To $iArrIcovarSize - 1
            Call("_VectorOf" & $typeOfIcovar & "Push", $vectorIcovar, $icovar[$i])
        Next

        $iArrIcovar = Call("_cveInputArrayFromVectorOf" & $typeOfIcovar, $vectorIcovar)
    Else
        If $bIcovarCreate Then
            $icovar = Call("_cve" & $typeOfIcovar & "Create", $icovar)
        EndIf
        $iArrIcovar = Call("_cveInputArrayFrom" & $typeOfIcovar, $icovar)
    EndIf

    _cveMahalanobis($iArrV1, $iArrV2, $iArrIcovar)

    If $bIcovarIsArray Then
        Call("_VectorOf" & $typeOfIcovar & "Release", $vectorIcovar)
    EndIf

    If $typeOfIcovar <> Default Then
        _cveInputArrayRelease($iArrIcovar)
        If $bIcovarCreate Then
            Call("_cve" & $typeOfIcovar & "Release", $icovar)
        EndIf
    EndIf

    If $bV2IsArray Then
        Call("_VectorOf" & $typeOfV2 & "Release", $vectorV2)
    EndIf

    If $typeOfV2 <> Default Then
        _cveInputArrayRelease($iArrV2)
        If $bV2Create Then
            Call("_cve" & $typeOfV2 & "Release", $v2)
        EndIf
    EndIf

    If $bV1IsArray Then
        Call("_VectorOf" & $typeOfV1 & "Release", $vectorV1)
    EndIf

    If $typeOfV1 <> Default Then
        _cveInputArrayRelease($iArrV1)
        If $bV1Create Then
            Call("_cve" & $typeOfV1 & "Release", $v1)
        EndIf
    EndIf
EndFunc   ;==>_cveMahalanobisTyped

Func _cveMahalanobisMat($v1, $v2, $icovar)
    ; cveMahalanobis using cv::Mat instead of _*Array
    _cveMahalanobisTyped("Mat", $v1, "Mat", $v2, "Mat", $icovar)
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

Func _cveCalcCovarMatrixTyped($typeOfSamples, $samples, $typeOfCovar, $covar, $typeOfMean, $mean, $flags, $ctype = $CV_64F)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $oArrCovar, $vectorCovar, $iArrCovarSize
    Local $bCovarIsArray = IsArray($covar)
    Local $bCovarCreate = IsDllStruct($covar) And $typeOfCovar == "Scalar"

    If $typeOfCovar == Default Then
        $oArrCovar = $covar
    ElseIf $bCovarIsArray Then
        $vectorCovar = Call("_VectorOf" & $typeOfCovar & "Create")

        $iArrCovarSize = UBound($covar)
        For $i = 0 To $iArrCovarSize - 1
            Call("_VectorOf" & $typeOfCovar & "Push", $vectorCovar, $covar[$i])
        Next

        $oArrCovar = Call("_cveOutputArrayFromVectorOf" & $typeOfCovar, $vectorCovar)
    Else
        If $bCovarCreate Then
            $covar = Call("_cve" & $typeOfCovar & "Create", $covar)
        EndIf
        $oArrCovar = Call("_cveOutputArrayFrom" & $typeOfCovar, $covar)
    EndIf

    Local $ioArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $ioArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $ioArrMean = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $ioArrMean = Call("_cveInputOutputArrayFrom" & $typeOfMean, $mean)
    EndIf

    _cveCalcCovarMatrix($iArrSamples, $oArrCovar, $ioArrMean, $flags, $ctype)

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveInputOutputArrayRelease($ioArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
        EndIf
    EndIf

    If $bCovarIsArray Then
        Call("_VectorOf" & $typeOfCovar & "Release", $vectorCovar)
    EndIf

    If $typeOfCovar <> Default Then
        _cveOutputArrayRelease($oArrCovar)
        If $bCovarCreate Then
            Call("_cve" & $typeOfCovar & "Release", $covar)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcCovarMatrixTyped

Func _cveCalcCovarMatrixMat($samples, $covar, $mean, $flags, $ctype = $CV_64F)
    ; cveCalcCovarMatrix using cv::Mat instead of _*Array
    _cveCalcCovarMatrixTyped("Mat", $samples, "Mat", $covar, "Mat", $mean, $flags, $ctype)
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

Func _cveNormalizeTyped($typeOfSrc, $src, $typeOfDst, $dst, $alpha, $beta, $normType, $dType = -1, $typeOfMask = Default, $mask = _cveNoArray())

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

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveNormalize($iArrSrc, $ioArrDst, $alpha, $beta, $normType, $dType, $iArrMask)

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
        _cveInputOutputArrayRelease($ioArrDst)
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
EndFunc   ;==>_cveNormalizeTyped

Func _cveNormalizeMat($src, $dst, $alpha, $beta, $normType, $dType = -1, $mask = _cveNoArrayMat())
    ; cveNormalize using cv::Mat instead of _*Array
    _cveNormalizeTyped("Mat", $src, "Mat", $dst, $alpha, $beta, $normType, $dType, "Mat", $mask)
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

Func _cvePerspectiveTransformTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfM, $m)

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

    Local $iArrM, $vectorM, $iArrMSize
    Local $bMIsArray = IsArray($m)
    Local $bMCreate = IsDllStruct($m) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $m
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($m)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $m[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $m = Call("_cve" & $typeOfM & "Create", $m)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $m)
    EndIf

    _cvePerspectiveTransform($iArrSrc, $oArrDst, $iArrM)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
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
EndFunc   ;==>_cvePerspectiveTransformTyped

Func _cvePerspectiveTransformMat($src, $dst, $m)
    ; cvePerspectiveTransform using cv::Mat instead of _*Array
    _cvePerspectiveTransformTyped("Mat", $src, "Mat", $dst, "Mat", $m)
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

Func _cveMulTransposedTyped($typeOfSrc, $src, $typeOfDst, $dst, $aTa, $typeOfDelta = Default, $delta = _cveNoArray(), $scale = 1, $dtype = -1)

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

    Local $iArrDelta, $vectorDelta, $iArrDeltaSize
    Local $bDeltaIsArray = IsArray($delta)
    Local $bDeltaCreate = IsDllStruct($delta) And $typeOfDelta == "Scalar"

    If $typeOfDelta == Default Then
        $iArrDelta = $delta
    ElseIf $bDeltaIsArray Then
        $vectorDelta = Call("_VectorOf" & $typeOfDelta & "Create")

        $iArrDeltaSize = UBound($delta)
        For $i = 0 To $iArrDeltaSize - 1
            Call("_VectorOf" & $typeOfDelta & "Push", $vectorDelta, $delta[$i])
        Next

        $iArrDelta = Call("_cveInputArrayFromVectorOf" & $typeOfDelta, $vectorDelta)
    Else
        If $bDeltaCreate Then
            $delta = Call("_cve" & $typeOfDelta & "Create", $delta)
        EndIf
        $iArrDelta = Call("_cveInputArrayFrom" & $typeOfDelta, $delta)
    EndIf

    _cveMulTransposed($iArrSrc, $oArrDst, $aTa, $iArrDelta, $scale, $dtype)

    If $bDeltaIsArray Then
        Call("_VectorOf" & $typeOfDelta & "Release", $vectorDelta)
    EndIf

    If $typeOfDelta <> Default Then
        _cveInputArrayRelease($iArrDelta)
        If $bDeltaCreate Then
            Call("_cve" & $typeOfDelta & "Release", $delta)
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
EndFunc   ;==>_cveMulTransposedTyped

Func _cveMulTransposedMat($src, $dst, $aTa, $delta = _cveNoArrayMat(), $scale = 1, $dtype = -1)
    ; cveMulTransposed using cv::Mat instead of _*Array
    _cveMulTransposedTyped("Mat", $src, "Mat", $dst, $aTa, "Mat", $delta, $scale, $dtype)
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

Func _cveSplitTyped($typeOfSrc, $src, $typeOfMv, $mv)

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

    Local $oArrMv, $vectorMv, $iArrMvSize
    Local $bMvIsArray = IsArray($mv)
    Local $bMvCreate = IsDllStruct($mv) And $typeOfMv == "Scalar"

    If $typeOfMv == Default Then
        $oArrMv = $mv
    ElseIf $bMvIsArray Then
        $vectorMv = Call("_VectorOf" & $typeOfMv & "Create")

        $iArrMvSize = UBound($mv)
        For $i = 0 To $iArrMvSize - 1
            Call("_VectorOf" & $typeOfMv & "Push", $vectorMv, $mv[$i])
        Next

        $oArrMv = Call("_cveOutputArrayFromVectorOf" & $typeOfMv, $vectorMv)
    Else
        If $bMvCreate Then
            $mv = Call("_cve" & $typeOfMv & "Create", $mv)
        EndIf
        $oArrMv = Call("_cveOutputArrayFrom" & $typeOfMv, $mv)
    EndIf

    _cveSplit($iArrSrc, $oArrMv)

    If $bMvIsArray Then
        Call("_VectorOf" & $typeOfMv & "Release", $vectorMv)
    EndIf

    If $typeOfMv <> Default Then
        _cveOutputArrayRelease($oArrMv)
        If $bMvCreate Then
            Call("_cve" & $typeOfMv & "Release", $mv)
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
EndFunc   ;==>_cveSplitTyped

Func _cveSplitMat($src, $mv)
    ; cveSplit using cv::Mat instead of _*Array
    _cveSplitTyped("Mat", $src, "Mat", $mv)
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

Func _cveMergeTyped($typeOfMv, $mv, $typeOfDst, $dst)

    Local $iArrMv, $vectorMv, $iArrMvSize
    Local $bMvIsArray = IsArray($mv)
    Local $bMvCreate = IsDllStruct($mv) And $typeOfMv == "Scalar"

    If $typeOfMv == Default Then
        $iArrMv = $mv
    ElseIf $bMvIsArray Then
        $vectorMv = Call("_VectorOf" & $typeOfMv & "Create")

        $iArrMvSize = UBound($mv)
        For $i = 0 To $iArrMvSize - 1
            Call("_VectorOf" & $typeOfMv & "Push", $vectorMv, $mv[$i])
        Next

        $iArrMv = Call("_cveInputArrayFromVectorOf" & $typeOfMv, $vectorMv)
    Else
        If $bMvCreate Then
            $mv = Call("_cve" & $typeOfMv & "Create", $mv)
        EndIf
        $iArrMv = Call("_cveInputArrayFrom" & $typeOfMv, $mv)
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

    _cveMerge($iArrMv, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bMvIsArray Then
        Call("_VectorOf" & $typeOfMv & "Release", $vectorMv)
    EndIf

    If $typeOfMv <> Default Then
        _cveInputArrayRelease($iArrMv)
        If $bMvCreate Then
            Call("_cve" & $typeOfMv & "Release", $mv)
        EndIf
    EndIf
EndFunc   ;==>_cveMergeTyped

Func _cveMergeMat($mv, $dst)
    ; cveMerge using cv::Mat instead of _*Array
    _cveMergeTyped("Mat", $mv, "Mat", $dst)
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

Func _cveMixChannelsTyped($typeOfSrc, $src, $typeOfDst, $dst, $fromTo, $npairs)

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

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveMixChannels($iArrSrc, $ioArrDst, $fromTo, $npairs)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputOutputArrayRelease($ioArrDst)
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
EndFunc   ;==>_cveMixChannelsTyped

Func _cveMixChannelsMat($src, $dst, $fromTo, $npairs)
    ; cveMixChannels using cv::Mat instead of _*Array
    _cveMixChannelsTyped("Mat", $src, "Mat", $dst, $fromTo, $npairs)
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

Func _cveExtractChannelTyped($typeOfSrc, $src, $typeOfDst, $dst, $coi)

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

    _cveExtractChannel($iArrSrc, $oArrDst, $coi)

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
EndFunc   ;==>_cveExtractChannelTyped

Func _cveExtractChannelMat($src, $dst, $coi)
    ; cveExtractChannel using cv::Mat instead of _*Array
    _cveExtractChannelTyped("Mat", $src, "Mat", $dst, $coi)
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

Func _cveInsertChannelTyped($typeOfSrc, $src, $typeOfDst, $dst, $coi)

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

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveInsertChannel($iArrSrc, $ioArrDst, $coi)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputOutputArrayRelease($ioArrDst)
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
EndFunc   ;==>_cveInsertChannelTyped

Func _cveInsertChannelMat($src, $dst, $coi)
    ; cveInsertChannel using cv::Mat instead of _*Array
    _cveInsertChannelTyped("Mat", $src, "Mat", $dst, $coi)
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

Func _cveKmeansTyped($typeOfData, $data, $k, $typeOfBestLabels, $bestLabels, $criteria, $attempts, $flags, $typeOfCenters = Default, $centers = _cveNoArray())

    Local $iArrData, $vectorData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)
    Local $bDataCreate = IsDllStruct($data) And $typeOfData == "Scalar"

    If $typeOfData == Default Then
        $iArrData = $data
    ElseIf $bDataIsArray Then
        $vectorData = Call("_VectorOf" & $typeOfData & "Create")

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            Call("_VectorOf" & $typeOfData & "Push", $vectorData, $data[$i])
        Next

        $iArrData = Call("_cveInputArrayFromVectorOf" & $typeOfData, $vectorData)
    Else
        If $bDataCreate Then
            $data = Call("_cve" & $typeOfData & "Create", $data)
        EndIf
        $iArrData = Call("_cveInputArrayFrom" & $typeOfData, $data)
    EndIf

    Local $ioArrBestLabels, $vectorBestLabels, $iArrBestLabelsSize
    Local $bBestLabelsIsArray = IsArray($bestLabels)
    Local $bBestLabelsCreate = IsDllStruct($bestLabels) And $typeOfBestLabels == "Scalar"

    If $typeOfBestLabels == Default Then
        $ioArrBestLabels = $bestLabels
    ElseIf $bBestLabelsIsArray Then
        $vectorBestLabels = Call("_VectorOf" & $typeOfBestLabels & "Create")

        $iArrBestLabelsSize = UBound($bestLabels)
        For $i = 0 To $iArrBestLabelsSize - 1
            Call("_VectorOf" & $typeOfBestLabels & "Push", $vectorBestLabels, $bestLabels[$i])
        Next

        $ioArrBestLabels = Call("_cveInputOutputArrayFromVectorOf" & $typeOfBestLabels, $vectorBestLabels)
    Else
        If $bBestLabelsCreate Then
            $bestLabels = Call("_cve" & $typeOfBestLabels & "Create", $bestLabels)
        EndIf
        $ioArrBestLabels = Call("_cveInputOutputArrayFrom" & $typeOfBestLabels, $bestLabels)
    EndIf

    Local $oArrCenters, $vectorCenters, $iArrCentersSize
    Local $bCentersIsArray = IsArray($centers)
    Local $bCentersCreate = IsDllStruct($centers) And $typeOfCenters == "Scalar"

    If $typeOfCenters == Default Then
        $oArrCenters = $centers
    ElseIf $bCentersIsArray Then
        $vectorCenters = Call("_VectorOf" & $typeOfCenters & "Create")

        $iArrCentersSize = UBound($centers)
        For $i = 0 To $iArrCentersSize - 1
            Call("_VectorOf" & $typeOfCenters & "Push", $vectorCenters, $centers[$i])
        Next

        $oArrCenters = Call("_cveOutputArrayFromVectorOf" & $typeOfCenters, $vectorCenters)
    Else
        If $bCentersCreate Then
            $centers = Call("_cve" & $typeOfCenters & "Create", $centers)
        EndIf
        $oArrCenters = Call("_cveOutputArrayFrom" & $typeOfCenters, $centers)
    EndIf

    Local $retval = _cveKmeans($iArrData, $k, $ioArrBestLabels, $criteria, $attempts, $flags, $oArrCenters)

    If $bCentersIsArray Then
        Call("_VectorOf" & $typeOfCenters & "Release", $vectorCenters)
    EndIf

    If $typeOfCenters <> Default Then
        _cveOutputArrayRelease($oArrCenters)
        If $bCentersCreate Then
            Call("_cve" & $typeOfCenters & "Release", $centers)
        EndIf
    EndIf

    If $bBestLabelsIsArray Then
        Call("_VectorOf" & $typeOfBestLabels & "Release", $vectorBestLabels)
    EndIf

    If $typeOfBestLabels <> Default Then
        _cveInputOutputArrayRelease($ioArrBestLabels)
        If $bBestLabelsCreate Then
            Call("_cve" & $typeOfBestLabels & "Release", $bestLabels)
        EndIf
    EndIf

    If $bDataIsArray Then
        Call("_VectorOf" & $typeOfData & "Release", $vectorData)
    EndIf

    If $typeOfData <> Default Then
        _cveInputArrayRelease($iArrData)
        If $bDataCreate Then
            Call("_cve" & $typeOfData & "Release", $data)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveKmeansTyped

Func _cveKmeansMat($data, $k, $bestLabels, $criteria, $attempts, $flags, $centers = _cveNoArrayMat())
    ; cveKmeans using cv::Mat instead of _*Array
    Local $retval = _cveKmeansTyped("Mat", $data, $k, "Mat", $bestLabels, $criteria, $attempts, $flags, "Mat", $centers)

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

Func _cveHConcatTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst)

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

    _cveHConcat($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveHConcatTyped

Func _cveHConcatMat($src1, $src2, $dst)
    ; cveHConcat using cv::Mat instead of _*Array
    _cveHConcatTyped("Mat", $src1, "Mat", $src2, "Mat", $dst)
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

Func _cveVConcatTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst)

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

    _cveVConcat($iArrSrc1, $iArrSrc2, $oArrDst)

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
EndFunc   ;==>_cveVConcatTyped

Func _cveVConcatMat($src1, $src2, $dst)
    ; cveVConcat using cv::Mat instead of _*Array
    _cveVConcatTyped("Mat", $src1, "Mat", $src2, "Mat", $dst)
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

Func _cveHConcat2Typed($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveHConcat2($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveHConcat2Typed

Func _cveHConcat2Mat($src, $dst)
    ; cveHConcat2 using cv::Mat instead of _*Array
    _cveHConcat2Typed("Mat", $src, "Mat", $dst)
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

Func _cveVConcat2Typed($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveVConcat2($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveVConcat2Typed

Func _cveVConcat2Mat($src, $dst)
    ; cveVConcat2 using cv::Mat instead of _*Array
    _cveVConcat2Typed("Mat", $src, "Mat", $dst)
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

Func _cvePSNRTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2)

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

    Local $retval = _cvePSNR($iArrSrc1, $iArrSrc2)

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
EndFunc   ;==>_cvePSNRTyped

Func _cvePSNRMat($src1, $src2)
    ; cvePSNR using cv::Mat instead of _*Array
    Local $retval = _cvePSNRTyped("Mat", $src1, "Mat", $src2)

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

Func _cveEigenTyped($typeOfSrc, $src, $typeOfEigenValues, $eigenValues, $typeOfEigenVectors = Default, $eigenVectors = _cveNoArray())

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

    Local $oArrEigenValues, $vectorEigenValues, $iArrEigenValuesSize
    Local $bEigenValuesIsArray = IsArray($eigenValues)
    Local $bEigenValuesCreate = IsDllStruct($eigenValues) And $typeOfEigenValues == "Scalar"

    If $typeOfEigenValues == Default Then
        $oArrEigenValues = $eigenValues
    ElseIf $bEigenValuesIsArray Then
        $vectorEigenValues = Call("_VectorOf" & $typeOfEigenValues & "Create")

        $iArrEigenValuesSize = UBound($eigenValues)
        For $i = 0 To $iArrEigenValuesSize - 1
            Call("_VectorOf" & $typeOfEigenValues & "Push", $vectorEigenValues, $eigenValues[$i])
        Next

        $oArrEigenValues = Call("_cveOutputArrayFromVectorOf" & $typeOfEigenValues, $vectorEigenValues)
    Else
        If $bEigenValuesCreate Then
            $eigenValues = Call("_cve" & $typeOfEigenValues & "Create", $eigenValues)
        EndIf
        $oArrEigenValues = Call("_cveOutputArrayFrom" & $typeOfEigenValues, $eigenValues)
    EndIf

    Local $oArrEigenVectors, $vectorEigenVectors, $iArrEigenVectorsSize
    Local $bEigenVectorsIsArray = IsArray($eigenVectors)
    Local $bEigenVectorsCreate = IsDllStruct($eigenVectors) And $typeOfEigenVectors == "Scalar"

    If $typeOfEigenVectors == Default Then
        $oArrEigenVectors = $eigenVectors
    ElseIf $bEigenVectorsIsArray Then
        $vectorEigenVectors = Call("_VectorOf" & $typeOfEigenVectors & "Create")

        $iArrEigenVectorsSize = UBound($eigenVectors)
        For $i = 0 To $iArrEigenVectorsSize - 1
            Call("_VectorOf" & $typeOfEigenVectors & "Push", $vectorEigenVectors, $eigenVectors[$i])
        Next

        $oArrEigenVectors = Call("_cveOutputArrayFromVectorOf" & $typeOfEigenVectors, $vectorEigenVectors)
    Else
        If $bEigenVectorsCreate Then
            $eigenVectors = Call("_cve" & $typeOfEigenVectors & "Create", $eigenVectors)
        EndIf
        $oArrEigenVectors = Call("_cveOutputArrayFrom" & $typeOfEigenVectors, $eigenVectors)
    EndIf

    Local $retval = _cveEigen($iArrSrc, $oArrEigenValues, $oArrEigenVectors)

    If $bEigenVectorsIsArray Then
        Call("_VectorOf" & $typeOfEigenVectors & "Release", $vectorEigenVectors)
    EndIf

    If $typeOfEigenVectors <> Default Then
        _cveOutputArrayRelease($oArrEigenVectors)
        If $bEigenVectorsCreate Then
            Call("_cve" & $typeOfEigenVectors & "Release", $eigenVectors)
        EndIf
    EndIf

    If $bEigenValuesIsArray Then
        Call("_VectorOf" & $typeOfEigenValues & "Release", $vectorEigenValues)
    EndIf

    If $typeOfEigenValues <> Default Then
        _cveOutputArrayRelease($oArrEigenValues)
        If $bEigenValuesCreate Then
            Call("_cve" & $typeOfEigenValues & "Release", $eigenValues)
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
EndFunc   ;==>_cveEigenTyped

Func _cveEigenMat($src, $eigenValues, $eigenVectors = _cveNoArrayMat())
    ; cveEigen using cv::Mat instead of _*Array
    Local $retval = _cveEigenTyped("Mat", $src, "Mat", $eigenValues, "Mat", $eigenVectors)

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

    Local $bNameIsString = IsString($name)
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

    Local $bFilenameIsString = IsString($filename)
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

    Local $bDefaultNameIsString = IsString($defaultName)
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

Func _cveRandnTyped($typeOfDst, $dst, $typeOfMean, $mean, $typeOfStddev, $stddev)

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $iArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $iArrMean = Call("_cveInputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $iArrMean = Call("_cveInputArrayFrom" & $typeOfMean, $mean)
    EndIf

    Local $iArrStddev, $vectorStddev, $iArrStddevSize
    Local $bStddevIsArray = IsArray($stddev)
    Local $bStddevCreate = IsDllStruct($stddev) And $typeOfStddev == "Scalar"

    If $typeOfStddev == Default Then
        $iArrStddev = $stddev
    ElseIf $bStddevIsArray Then
        $vectorStddev = Call("_VectorOf" & $typeOfStddev & "Create")

        $iArrStddevSize = UBound($stddev)
        For $i = 0 To $iArrStddevSize - 1
            Call("_VectorOf" & $typeOfStddev & "Push", $vectorStddev, $stddev[$i])
        Next

        $iArrStddev = Call("_cveInputArrayFromVectorOf" & $typeOfStddev, $vectorStddev)
    Else
        If $bStddevCreate Then
            $stddev = Call("_cve" & $typeOfStddev & "Create", $stddev)
        EndIf
        $iArrStddev = Call("_cveInputArrayFrom" & $typeOfStddev, $stddev)
    EndIf

    _cveRandn($ioArrDst, $iArrMean, $iArrStddev)

    If $bStddevIsArray Then
        Call("_VectorOf" & $typeOfStddev & "Release", $vectorStddev)
    EndIf

    If $typeOfStddev <> Default Then
        _cveInputArrayRelease($iArrStddev)
        If $bStddevCreate Then
            Call("_cve" & $typeOfStddev & "Release", $stddev)
        EndIf
    EndIf

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveInputArrayRelease($iArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputOutputArrayRelease($ioArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveRandnTyped

Func _cveRandnMat($dst, $mean, $stddev)
    ; cveRandn using cv::Mat instead of _*Array
    _cveRandnTyped("Mat", $dst, "Mat", $mean, "Mat", $stddev)
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

Func _cveRanduTyped($typeOfDst, $dst, $typeOfLow, $low, $typeOfHigh, $high)

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrLow, $vectorLow, $iArrLowSize
    Local $bLowIsArray = IsArray($low)
    Local $bLowCreate = IsDllStruct($low) And $typeOfLow == "Scalar"

    If $typeOfLow == Default Then
        $iArrLow = $low
    ElseIf $bLowIsArray Then
        $vectorLow = Call("_VectorOf" & $typeOfLow & "Create")

        $iArrLowSize = UBound($low)
        For $i = 0 To $iArrLowSize - 1
            Call("_VectorOf" & $typeOfLow & "Push", $vectorLow, $low[$i])
        Next

        $iArrLow = Call("_cveInputArrayFromVectorOf" & $typeOfLow, $vectorLow)
    Else
        If $bLowCreate Then
            $low = Call("_cve" & $typeOfLow & "Create", $low)
        EndIf
        $iArrLow = Call("_cveInputArrayFrom" & $typeOfLow, $low)
    EndIf

    Local $iArrHigh, $vectorHigh, $iArrHighSize
    Local $bHighIsArray = IsArray($high)
    Local $bHighCreate = IsDllStruct($high) And $typeOfHigh == "Scalar"

    If $typeOfHigh == Default Then
        $iArrHigh = $high
    ElseIf $bHighIsArray Then
        $vectorHigh = Call("_VectorOf" & $typeOfHigh & "Create")

        $iArrHighSize = UBound($high)
        For $i = 0 To $iArrHighSize - 1
            Call("_VectorOf" & $typeOfHigh & "Push", $vectorHigh, $high[$i])
        Next

        $iArrHigh = Call("_cveInputArrayFromVectorOf" & $typeOfHigh, $vectorHigh)
    Else
        If $bHighCreate Then
            $high = Call("_cve" & $typeOfHigh & "Create", $high)
        EndIf
        $iArrHigh = Call("_cveInputArrayFrom" & $typeOfHigh, $high)
    EndIf

    _cveRandu($ioArrDst, $iArrLow, $iArrHigh)

    If $bHighIsArray Then
        Call("_VectorOf" & $typeOfHigh & "Release", $vectorHigh)
    EndIf

    If $typeOfHigh <> Default Then
        _cveInputArrayRelease($iArrHigh)
        If $bHighCreate Then
            Call("_cve" & $typeOfHigh & "Release", $high)
        EndIf
    EndIf

    If $bLowIsArray Then
        Call("_VectorOf" & $typeOfLow & "Release", $vectorLow)
    EndIf

    If $typeOfLow <> Default Then
        _cveInputArrayRelease($iArrLow)
        If $bLowCreate Then
            Call("_cve" & $typeOfLow & "Release", $low)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputOutputArrayRelease($ioArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveRanduTyped

Func _cveRanduMat($dst, $low, $high)
    ; cveRandu using cv::Mat instead of _*Array
    _cveRanduTyped("Mat", $dst, "Mat", $low, "Mat", $high)
EndFunc   ;==>_cveRanduMat

Func _cveFileStorageCreate($source, $flags, $encoding)
    ; CVAPI(cv::FileStorage*) cveFileStorageCreate(const cv::String* source, int flags, const cv::String* encoding);

    Local $bSourceIsString = IsString($source)
    If $bSourceIsString Then
        $source = _cveStringCreateFromStr($source)
    EndIf

    Local $sSourceDllType
    If IsDllStruct($source) Then
        $sSourceDllType = "struct*"
    Else
        $sSourceDllType = "ptr"
    EndIf

    Local $bEncodingIsString = IsString($encoding)
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

    Local $bResultIsString = IsString($result)
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

    Local $bNameIsString = IsString($name)
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

    Local $bNameIsString = IsString($name)
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

    Local $bNameIsString = IsString($name)
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

    Local $bNameIsString = IsString($name)
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

    Local $bNameIsString = IsString($name)
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    Local $bValueIsString = IsString($value)
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

    Local $bValueIsString = IsString($value)
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

    Local $bNodeNameIsString = IsString($nodeName)
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

    Local $bNameIsString = IsString($name)
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
    Local $bKeysIsArray = IsArray($keys)

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

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    Local $bDefaultStrIsString = IsString($defaultStr)
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

    Local $bBuildInformationIsString = IsString($buildInformation)
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

Func _cveSVDecompTyped($typeOfSrc, $src, $typeOfW, $w, $typeOfU, $u, $typeOfVt, $vt, $flags = 0)

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

    Local $oArrW, $vectorW, $iArrWSize
    Local $bWIsArray = IsArray($w)
    Local $bWCreate = IsDllStruct($w) And $typeOfW == "Scalar"

    If $typeOfW == Default Then
        $oArrW = $w
    ElseIf $bWIsArray Then
        $vectorW = Call("_VectorOf" & $typeOfW & "Create")

        $iArrWSize = UBound($w)
        For $i = 0 To $iArrWSize - 1
            Call("_VectorOf" & $typeOfW & "Push", $vectorW, $w[$i])
        Next

        $oArrW = Call("_cveOutputArrayFromVectorOf" & $typeOfW, $vectorW)
    Else
        If $bWCreate Then
            $w = Call("_cve" & $typeOfW & "Create", $w)
        EndIf
        $oArrW = Call("_cveOutputArrayFrom" & $typeOfW, $w)
    EndIf

    Local $oArrU, $vectorU, $iArrUSize
    Local $bUIsArray = IsArray($u)
    Local $bUCreate = IsDllStruct($u) And $typeOfU == "Scalar"

    If $typeOfU == Default Then
        $oArrU = $u
    ElseIf $bUIsArray Then
        $vectorU = Call("_VectorOf" & $typeOfU & "Create")

        $iArrUSize = UBound($u)
        For $i = 0 To $iArrUSize - 1
            Call("_VectorOf" & $typeOfU & "Push", $vectorU, $u[$i])
        Next

        $oArrU = Call("_cveOutputArrayFromVectorOf" & $typeOfU, $vectorU)
    Else
        If $bUCreate Then
            $u = Call("_cve" & $typeOfU & "Create", $u)
        EndIf
        $oArrU = Call("_cveOutputArrayFrom" & $typeOfU, $u)
    EndIf

    Local $oArrVt, $vectorVt, $iArrVtSize
    Local $bVtIsArray = IsArray($vt)
    Local $bVtCreate = IsDllStruct($vt) And $typeOfVt == "Scalar"

    If $typeOfVt == Default Then
        $oArrVt = $vt
    ElseIf $bVtIsArray Then
        $vectorVt = Call("_VectorOf" & $typeOfVt & "Create")

        $iArrVtSize = UBound($vt)
        For $i = 0 To $iArrVtSize - 1
            Call("_VectorOf" & $typeOfVt & "Push", $vectorVt, $vt[$i])
        Next

        $oArrVt = Call("_cveOutputArrayFromVectorOf" & $typeOfVt, $vectorVt)
    Else
        If $bVtCreate Then
            $vt = Call("_cve" & $typeOfVt & "Create", $vt)
        EndIf
        $oArrVt = Call("_cveOutputArrayFrom" & $typeOfVt, $vt)
    EndIf

    _cveSVDecomp($iArrSrc, $oArrW, $oArrU, $oArrVt, $flags)

    If $bVtIsArray Then
        Call("_VectorOf" & $typeOfVt & "Release", $vectorVt)
    EndIf

    If $typeOfVt <> Default Then
        _cveOutputArrayRelease($oArrVt)
        If $bVtCreate Then
            Call("_cve" & $typeOfVt & "Release", $vt)
        EndIf
    EndIf

    If $bUIsArray Then
        Call("_VectorOf" & $typeOfU & "Release", $vectorU)
    EndIf

    If $typeOfU <> Default Then
        _cveOutputArrayRelease($oArrU)
        If $bUCreate Then
            Call("_cve" & $typeOfU & "Release", $u)
        EndIf
    EndIf

    If $bWIsArray Then
        Call("_VectorOf" & $typeOfW & "Release", $vectorW)
    EndIf

    If $typeOfW <> Default Then
        _cveOutputArrayRelease($oArrW)
        If $bWCreate Then
            Call("_cve" & $typeOfW & "Release", $w)
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
EndFunc   ;==>_cveSVDecompTyped

Func _cveSVDecompMat($src, $w, $u, $vt, $flags = 0)
    ; cveSVDecomp using cv::Mat instead of _*Array
    _cveSVDecompTyped("Mat", $src, "Mat", $w, "Mat", $u, "Mat", $vt, $flags)
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

Func _cveSVBackSubstTyped($typeOfW, $w, $typeOfU, $u, $typeOfVt, $vt, $typeOfRhs, $rhs, $typeOfDst, $dst)

    Local $iArrW, $vectorW, $iArrWSize
    Local $bWIsArray = IsArray($w)
    Local $bWCreate = IsDllStruct($w) And $typeOfW == "Scalar"

    If $typeOfW == Default Then
        $iArrW = $w
    ElseIf $bWIsArray Then
        $vectorW = Call("_VectorOf" & $typeOfW & "Create")

        $iArrWSize = UBound($w)
        For $i = 0 To $iArrWSize - 1
            Call("_VectorOf" & $typeOfW & "Push", $vectorW, $w[$i])
        Next

        $iArrW = Call("_cveInputArrayFromVectorOf" & $typeOfW, $vectorW)
    Else
        If $bWCreate Then
            $w = Call("_cve" & $typeOfW & "Create", $w)
        EndIf
        $iArrW = Call("_cveInputArrayFrom" & $typeOfW, $w)
    EndIf

    Local $iArrU, $vectorU, $iArrUSize
    Local $bUIsArray = IsArray($u)
    Local $bUCreate = IsDllStruct($u) And $typeOfU == "Scalar"

    If $typeOfU == Default Then
        $iArrU = $u
    ElseIf $bUIsArray Then
        $vectorU = Call("_VectorOf" & $typeOfU & "Create")

        $iArrUSize = UBound($u)
        For $i = 0 To $iArrUSize - 1
            Call("_VectorOf" & $typeOfU & "Push", $vectorU, $u[$i])
        Next

        $iArrU = Call("_cveInputArrayFromVectorOf" & $typeOfU, $vectorU)
    Else
        If $bUCreate Then
            $u = Call("_cve" & $typeOfU & "Create", $u)
        EndIf
        $iArrU = Call("_cveInputArrayFrom" & $typeOfU, $u)
    EndIf

    Local $iArrVt, $vectorVt, $iArrVtSize
    Local $bVtIsArray = IsArray($vt)
    Local $bVtCreate = IsDllStruct($vt) And $typeOfVt == "Scalar"

    If $typeOfVt == Default Then
        $iArrVt = $vt
    ElseIf $bVtIsArray Then
        $vectorVt = Call("_VectorOf" & $typeOfVt & "Create")

        $iArrVtSize = UBound($vt)
        For $i = 0 To $iArrVtSize - 1
            Call("_VectorOf" & $typeOfVt & "Push", $vectorVt, $vt[$i])
        Next

        $iArrVt = Call("_cveInputArrayFromVectorOf" & $typeOfVt, $vectorVt)
    Else
        If $bVtCreate Then
            $vt = Call("_cve" & $typeOfVt & "Create", $vt)
        EndIf
        $iArrVt = Call("_cveInputArrayFrom" & $typeOfVt, $vt)
    EndIf

    Local $iArrRhs, $vectorRhs, $iArrRhsSize
    Local $bRhsIsArray = IsArray($rhs)
    Local $bRhsCreate = IsDllStruct($rhs) And $typeOfRhs == "Scalar"

    If $typeOfRhs == Default Then
        $iArrRhs = $rhs
    ElseIf $bRhsIsArray Then
        $vectorRhs = Call("_VectorOf" & $typeOfRhs & "Create")

        $iArrRhsSize = UBound($rhs)
        For $i = 0 To $iArrRhsSize - 1
            Call("_VectorOf" & $typeOfRhs & "Push", $vectorRhs, $rhs[$i])
        Next

        $iArrRhs = Call("_cveInputArrayFromVectorOf" & $typeOfRhs, $vectorRhs)
    Else
        If $bRhsCreate Then
            $rhs = Call("_cve" & $typeOfRhs & "Create", $rhs)
        EndIf
        $iArrRhs = Call("_cveInputArrayFrom" & $typeOfRhs, $rhs)
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

    _cveSVBackSubst($iArrW, $iArrU, $iArrVt, $iArrRhs, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bRhsIsArray Then
        Call("_VectorOf" & $typeOfRhs & "Release", $vectorRhs)
    EndIf

    If $typeOfRhs <> Default Then
        _cveInputArrayRelease($iArrRhs)
        If $bRhsCreate Then
            Call("_cve" & $typeOfRhs & "Release", $rhs)
        EndIf
    EndIf

    If $bVtIsArray Then
        Call("_VectorOf" & $typeOfVt & "Release", $vectorVt)
    EndIf

    If $typeOfVt <> Default Then
        _cveInputArrayRelease($iArrVt)
        If $bVtCreate Then
            Call("_cve" & $typeOfVt & "Release", $vt)
        EndIf
    EndIf

    If $bUIsArray Then
        Call("_VectorOf" & $typeOfU & "Release", $vectorU)
    EndIf

    If $typeOfU <> Default Then
        _cveInputArrayRelease($iArrU)
        If $bUCreate Then
            Call("_cve" & $typeOfU & "Release", $u)
        EndIf
    EndIf

    If $bWIsArray Then
        Call("_VectorOf" & $typeOfW & "Release", $vectorW)
    EndIf

    If $typeOfW <> Default Then
        _cveInputArrayRelease($iArrW)
        If $bWCreate Then
            Call("_cve" & $typeOfW & "Release", $w)
        EndIf
    EndIf
EndFunc   ;==>_cveSVBackSubstTyped

Func _cveSVBackSubstMat($w, $u, $vt, $rhs, $dst)
    ; cveSVBackSubst using cv::Mat instead of _*Array
    _cveSVBackSubstTyped("Mat", $w, "Mat", $u, "Mat", $vt, "Mat", $rhs, "Mat", $dst)
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

Func _cvePCACompute1Typed($typeOfData, $data, $typeOfMean, $mean, $typeOfEigenvectors, $eigenvectors, $maxComponents)

    Local $iArrData, $vectorData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)
    Local $bDataCreate = IsDllStruct($data) And $typeOfData == "Scalar"

    If $typeOfData == Default Then
        $iArrData = $data
    ElseIf $bDataIsArray Then
        $vectorData = Call("_VectorOf" & $typeOfData & "Create")

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            Call("_VectorOf" & $typeOfData & "Push", $vectorData, $data[$i])
        Next

        $iArrData = Call("_cveInputArrayFromVectorOf" & $typeOfData, $vectorData)
    Else
        If $bDataCreate Then
            $data = Call("_cve" & $typeOfData & "Create", $data)
        EndIf
        $iArrData = Call("_cveInputArrayFrom" & $typeOfData, $data)
    EndIf

    Local $ioArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $ioArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $ioArrMean = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $ioArrMean = Call("_cveInputOutputArrayFrom" & $typeOfMean, $mean)
    EndIf

    Local $oArrEigenvectors, $vectorEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = IsArray($eigenvectors)
    Local $bEigenvectorsCreate = IsDllStruct($eigenvectors) And $typeOfEigenvectors == "Scalar"

    If $typeOfEigenvectors == Default Then
        $oArrEigenvectors = $eigenvectors
    ElseIf $bEigenvectorsIsArray Then
        $vectorEigenvectors = Call("_VectorOf" & $typeOfEigenvectors & "Create")

        $iArrEigenvectorsSize = UBound($eigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            Call("_VectorOf" & $typeOfEigenvectors & "Push", $vectorEigenvectors, $eigenvectors[$i])
        Next

        $oArrEigenvectors = Call("_cveOutputArrayFromVectorOf" & $typeOfEigenvectors, $vectorEigenvectors)
    Else
        If $bEigenvectorsCreate Then
            $eigenvectors = Call("_cve" & $typeOfEigenvectors & "Create", $eigenvectors)
        EndIf
        $oArrEigenvectors = Call("_cveOutputArrayFrom" & $typeOfEigenvectors, $eigenvectors)
    EndIf

    _cvePCACompute1($iArrData, $ioArrMean, $oArrEigenvectors, $maxComponents)

    If $bEigenvectorsIsArray Then
        Call("_VectorOf" & $typeOfEigenvectors & "Release", $vectorEigenvectors)
    EndIf

    If $typeOfEigenvectors <> Default Then
        _cveOutputArrayRelease($oArrEigenvectors)
        If $bEigenvectorsCreate Then
            Call("_cve" & $typeOfEigenvectors & "Release", $eigenvectors)
        EndIf
    EndIf

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveInputOutputArrayRelease($ioArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
        EndIf
    EndIf

    If $bDataIsArray Then
        Call("_VectorOf" & $typeOfData & "Release", $vectorData)
    EndIf

    If $typeOfData <> Default Then
        _cveInputArrayRelease($iArrData)
        If $bDataCreate Then
            Call("_cve" & $typeOfData & "Release", $data)
        EndIf
    EndIf
EndFunc   ;==>_cvePCACompute1Typed

Func _cvePCACompute1Mat($data, $mean, $eigenvectors, $maxComponents)
    ; cvePCACompute1 using cv::Mat instead of _*Array
    _cvePCACompute1Typed("Mat", $data, "Mat", $mean, "Mat", $eigenvectors, $maxComponents)
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

Func _cvePCACompute2Typed($typeOfData, $data, $typeOfMean, $mean, $typeOfEigenvectors, $eigenvectors, $retainedVariance)

    Local $iArrData, $vectorData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)
    Local $bDataCreate = IsDllStruct($data) And $typeOfData == "Scalar"

    If $typeOfData == Default Then
        $iArrData = $data
    ElseIf $bDataIsArray Then
        $vectorData = Call("_VectorOf" & $typeOfData & "Create")

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            Call("_VectorOf" & $typeOfData & "Push", $vectorData, $data[$i])
        Next

        $iArrData = Call("_cveInputArrayFromVectorOf" & $typeOfData, $vectorData)
    Else
        If $bDataCreate Then
            $data = Call("_cve" & $typeOfData & "Create", $data)
        EndIf
        $iArrData = Call("_cveInputArrayFrom" & $typeOfData, $data)
    EndIf

    Local $ioArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $ioArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $ioArrMean = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $ioArrMean = Call("_cveInputOutputArrayFrom" & $typeOfMean, $mean)
    EndIf

    Local $oArrEigenvectors, $vectorEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = IsArray($eigenvectors)
    Local $bEigenvectorsCreate = IsDllStruct($eigenvectors) And $typeOfEigenvectors == "Scalar"

    If $typeOfEigenvectors == Default Then
        $oArrEigenvectors = $eigenvectors
    ElseIf $bEigenvectorsIsArray Then
        $vectorEigenvectors = Call("_VectorOf" & $typeOfEigenvectors & "Create")

        $iArrEigenvectorsSize = UBound($eigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            Call("_VectorOf" & $typeOfEigenvectors & "Push", $vectorEigenvectors, $eigenvectors[$i])
        Next

        $oArrEigenvectors = Call("_cveOutputArrayFromVectorOf" & $typeOfEigenvectors, $vectorEigenvectors)
    Else
        If $bEigenvectorsCreate Then
            $eigenvectors = Call("_cve" & $typeOfEigenvectors & "Create", $eigenvectors)
        EndIf
        $oArrEigenvectors = Call("_cveOutputArrayFrom" & $typeOfEigenvectors, $eigenvectors)
    EndIf

    _cvePCACompute2($iArrData, $ioArrMean, $oArrEigenvectors, $retainedVariance)

    If $bEigenvectorsIsArray Then
        Call("_VectorOf" & $typeOfEigenvectors & "Release", $vectorEigenvectors)
    EndIf

    If $typeOfEigenvectors <> Default Then
        _cveOutputArrayRelease($oArrEigenvectors)
        If $bEigenvectorsCreate Then
            Call("_cve" & $typeOfEigenvectors & "Release", $eigenvectors)
        EndIf
    EndIf

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveInputOutputArrayRelease($ioArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
        EndIf
    EndIf

    If $bDataIsArray Then
        Call("_VectorOf" & $typeOfData & "Release", $vectorData)
    EndIf

    If $typeOfData <> Default Then
        _cveInputArrayRelease($iArrData)
        If $bDataCreate Then
            Call("_cve" & $typeOfData & "Release", $data)
        EndIf
    EndIf
EndFunc   ;==>_cvePCACompute2Typed

Func _cvePCACompute2Mat($data, $mean, $eigenvectors, $retainedVariance)
    ; cvePCACompute2 using cv::Mat instead of _*Array
    _cvePCACompute2Typed("Mat", $data, "Mat", $mean, "Mat", $eigenvectors, $retainedVariance)
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

Func _cvePCAProjectTyped($typeOfData, $data, $typeOfMean, $mean, $typeOfEigenvectors, $eigenvectors, $typeOfResult, $result)

    Local $iArrData, $vectorData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)
    Local $bDataCreate = IsDllStruct($data) And $typeOfData == "Scalar"

    If $typeOfData == Default Then
        $iArrData = $data
    ElseIf $bDataIsArray Then
        $vectorData = Call("_VectorOf" & $typeOfData & "Create")

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            Call("_VectorOf" & $typeOfData & "Push", $vectorData, $data[$i])
        Next

        $iArrData = Call("_cveInputArrayFromVectorOf" & $typeOfData, $vectorData)
    Else
        If $bDataCreate Then
            $data = Call("_cve" & $typeOfData & "Create", $data)
        EndIf
        $iArrData = Call("_cveInputArrayFrom" & $typeOfData, $data)
    EndIf

    Local $iArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $iArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $iArrMean = Call("_cveInputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $iArrMean = Call("_cveInputArrayFrom" & $typeOfMean, $mean)
    EndIf

    Local $iArrEigenvectors, $vectorEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = IsArray($eigenvectors)
    Local $bEigenvectorsCreate = IsDllStruct($eigenvectors) And $typeOfEigenvectors == "Scalar"

    If $typeOfEigenvectors == Default Then
        $iArrEigenvectors = $eigenvectors
    ElseIf $bEigenvectorsIsArray Then
        $vectorEigenvectors = Call("_VectorOf" & $typeOfEigenvectors & "Create")

        $iArrEigenvectorsSize = UBound($eigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            Call("_VectorOf" & $typeOfEigenvectors & "Push", $vectorEigenvectors, $eigenvectors[$i])
        Next

        $iArrEigenvectors = Call("_cveInputArrayFromVectorOf" & $typeOfEigenvectors, $vectorEigenvectors)
    Else
        If $bEigenvectorsCreate Then
            $eigenvectors = Call("_cve" & $typeOfEigenvectors & "Create", $eigenvectors)
        EndIf
        $iArrEigenvectors = Call("_cveInputArrayFrom" & $typeOfEigenvectors, $eigenvectors)
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

    _cvePCAProject($iArrData, $iArrMean, $iArrEigenvectors, $oArrResult)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bEigenvectorsIsArray Then
        Call("_VectorOf" & $typeOfEigenvectors & "Release", $vectorEigenvectors)
    EndIf

    If $typeOfEigenvectors <> Default Then
        _cveInputArrayRelease($iArrEigenvectors)
        If $bEigenvectorsCreate Then
            Call("_cve" & $typeOfEigenvectors & "Release", $eigenvectors)
        EndIf
    EndIf

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveInputArrayRelease($iArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
        EndIf
    EndIf

    If $bDataIsArray Then
        Call("_VectorOf" & $typeOfData & "Release", $vectorData)
    EndIf

    If $typeOfData <> Default Then
        _cveInputArrayRelease($iArrData)
        If $bDataCreate Then
            Call("_cve" & $typeOfData & "Release", $data)
        EndIf
    EndIf
EndFunc   ;==>_cvePCAProjectTyped

Func _cvePCAProjectMat($data, $mean, $eigenvectors, $result)
    ; cvePCAProject using cv::Mat instead of _*Array
    _cvePCAProjectTyped("Mat", $data, "Mat", $mean, "Mat", $eigenvectors, "Mat", $result)
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

Func _cvePCABackProjectTyped($typeOfData, $data, $typeOfMean, $mean, $typeOfEigenvectors, $eigenvectors, $typeOfResult, $result)

    Local $iArrData, $vectorData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)
    Local $bDataCreate = IsDllStruct($data) And $typeOfData == "Scalar"

    If $typeOfData == Default Then
        $iArrData = $data
    ElseIf $bDataIsArray Then
        $vectorData = Call("_VectorOf" & $typeOfData & "Create")

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            Call("_VectorOf" & $typeOfData & "Push", $vectorData, $data[$i])
        Next

        $iArrData = Call("_cveInputArrayFromVectorOf" & $typeOfData, $vectorData)
    Else
        If $bDataCreate Then
            $data = Call("_cve" & $typeOfData & "Create", $data)
        EndIf
        $iArrData = Call("_cveInputArrayFrom" & $typeOfData, $data)
    EndIf

    Local $iArrMean, $vectorMean, $iArrMeanSize
    Local $bMeanIsArray = IsArray($mean)
    Local $bMeanCreate = IsDllStruct($mean) And $typeOfMean == "Scalar"

    If $typeOfMean == Default Then
        $iArrMean = $mean
    ElseIf $bMeanIsArray Then
        $vectorMean = Call("_VectorOf" & $typeOfMean & "Create")

        $iArrMeanSize = UBound($mean)
        For $i = 0 To $iArrMeanSize - 1
            Call("_VectorOf" & $typeOfMean & "Push", $vectorMean, $mean[$i])
        Next

        $iArrMean = Call("_cveInputArrayFromVectorOf" & $typeOfMean, $vectorMean)
    Else
        If $bMeanCreate Then
            $mean = Call("_cve" & $typeOfMean & "Create", $mean)
        EndIf
        $iArrMean = Call("_cveInputArrayFrom" & $typeOfMean, $mean)
    EndIf

    Local $iArrEigenvectors, $vectorEigenvectors, $iArrEigenvectorsSize
    Local $bEigenvectorsIsArray = IsArray($eigenvectors)
    Local $bEigenvectorsCreate = IsDllStruct($eigenvectors) And $typeOfEigenvectors == "Scalar"

    If $typeOfEigenvectors == Default Then
        $iArrEigenvectors = $eigenvectors
    ElseIf $bEigenvectorsIsArray Then
        $vectorEigenvectors = Call("_VectorOf" & $typeOfEigenvectors & "Create")

        $iArrEigenvectorsSize = UBound($eigenvectors)
        For $i = 0 To $iArrEigenvectorsSize - 1
            Call("_VectorOf" & $typeOfEigenvectors & "Push", $vectorEigenvectors, $eigenvectors[$i])
        Next

        $iArrEigenvectors = Call("_cveInputArrayFromVectorOf" & $typeOfEigenvectors, $vectorEigenvectors)
    Else
        If $bEigenvectorsCreate Then
            $eigenvectors = Call("_cve" & $typeOfEigenvectors & "Create", $eigenvectors)
        EndIf
        $iArrEigenvectors = Call("_cveInputArrayFrom" & $typeOfEigenvectors, $eigenvectors)
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

    _cvePCABackProject($iArrData, $iArrMean, $iArrEigenvectors, $oArrResult)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bEigenvectorsIsArray Then
        Call("_VectorOf" & $typeOfEigenvectors & "Release", $vectorEigenvectors)
    EndIf

    If $typeOfEigenvectors <> Default Then
        _cveInputArrayRelease($iArrEigenvectors)
        If $bEigenvectorsCreate Then
            Call("_cve" & $typeOfEigenvectors & "Release", $eigenvectors)
        EndIf
    EndIf

    If $bMeanIsArray Then
        Call("_VectorOf" & $typeOfMean & "Release", $vectorMean)
    EndIf

    If $typeOfMean <> Default Then
        _cveInputArrayRelease($iArrMean)
        If $bMeanCreate Then
            Call("_cve" & $typeOfMean & "Release", $mean)
        EndIf
    EndIf

    If $bDataIsArray Then
        Call("_VectorOf" & $typeOfData & "Release", $vectorData)
    EndIf

    If $typeOfData <> Default Then
        _cveInputArrayRelease($iArrData)
        If $bDataCreate Then
            Call("_cve" & $typeOfData & "Release", $data)
        EndIf
    EndIf
EndFunc   ;==>_cvePCABackProjectTyped

Func _cvePCABackProjectMat($data, $mean, $eigenvectors, $result)
    ; cvePCABackProject using cv::Mat instead of _*Array
    _cvePCABackProjectTyped("Mat", $data, "Mat", $mean, "Mat", $eigenvectors, "Mat", $result)
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

Func _cveRngFillTyped($rng, $typeOfMat, $mat, $distType, $typeOfA, $a, $typeOfB, $b, $saturateRange)

    Local $ioArrMat, $vectorMat, $iArrMatSize
    Local $bMatIsArray = IsArray($mat)
    Local $bMatCreate = IsDllStruct($mat) And $typeOfMat == "Scalar"

    If $typeOfMat == Default Then
        $ioArrMat = $mat
    ElseIf $bMatIsArray Then
        $vectorMat = Call("_VectorOf" & $typeOfMat & "Create")

        $iArrMatSize = UBound($mat)
        For $i = 0 To $iArrMatSize - 1
            Call("_VectorOf" & $typeOfMat & "Push", $vectorMat, $mat[$i])
        Next

        $ioArrMat = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMat, $vectorMat)
    Else
        If $bMatCreate Then
            $mat = Call("_cve" & $typeOfMat & "Create", $mat)
        EndIf
        $ioArrMat = Call("_cveInputOutputArrayFrom" & $typeOfMat, $mat)
    EndIf

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

    _cveRngFill($rng, $ioArrMat, $distType, $iArrA, $iArrB, $saturateRange)

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

    If $bMatIsArray Then
        Call("_VectorOf" & $typeOfMat & "Release", $vectorMat)
    EndIf

    If $typeOfMat <> Default Then
        _cveInputOutputArrayRelease($ioArrMat)
        If $bMatCreate Then
            Call("_cve" & $typeOfMat & "Release", $mat)
        EndIf
    EndIf
EndFunc   ;==>_cveRngFillTyped

Func _cveRngFillMat($rng, $mat, $distType, $a, $b, $saturateRange)
    ; cveRngFill using cv::Mat instead of _*Array
    _cveRngFillTyped($rng, "Mat", $mat, $distType, "Mat", $a, "Mat", $b, $saturateRange)
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
    Local $bKeyIsArray = IsArray($key)

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
    Local $bValueIsArray = IsArray($value)

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