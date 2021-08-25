#include-once
#include "..\..\CVEUtils.au3"

Func _cudaGetCudaEnabledDeviceCount()
    ; CVAPI(int) cudaGetCudaEnabledDeviceCount();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaGetCudaEnabledDeviceCount"), "cudaGetCudaEnabledDeviceCount", @error)
EndFunc   ;==>_cudaGetCudaEnabledDeviceCount

Func _cudaSetDevice($deviceId)
    ; CVAPI(void) cudaSetDevice(int deviceId);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSetDevice", "int", $deviceId), "cudaSetDevice", @error)
EndFunc   ;==>_cudaSetDevice

Func _cudaGetDevice()
    ; CVAPI(int) cudaGetDevice();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaGetDevice"), "cudaGetDevice", @error)
EndFunc   ;==>_cudaGetDevice

Func _cudaResetDevice()
    ; CVAPI(void) cudaResetDevice();
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaResetDevice"), "cudaResetDevice", @error)
EndFunc   ;==>_cudaResetDevice

Func _cudaDeviceInfoCreate($deviceId)
    ; CVAPI(cv::cuda::DeviceInfo*) cudaDeviceInfoCreate(int* deviceId);

    Local $sDeviceIdDllType
    If IsDllStruct($deviceId) Then
        $sDeviceIdDllType = "struct*"
    Else
        $sDeviceIdDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaDeviceInfoCreate", $sDeviceIdDllType, $deviceId), "cudaDeviceInfoCreate", @error)
EndFunc   ;==>_cudaDeviceInfoCreate

Func _cudaDeviceInfoRelease($di)
    ; CVAPI(void) cudaDeviceInfoRelease(cv::cuda::DeviceInfo** di);

    Local $sDiDllType
    If IsDllStruct($di) Then
        $sDiDllType = "struct*"
    ElseIf $di == Null Then
        $sDiDllType = "ptr"
    Else
        $sDiDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoRelease", $sDiDllType, $di), "cudaDeviceInfoRelease", @error)
EndFunc   ;==>_cudaDeviceInfoRelease

Func _cudaDeviceInfoDeviceName($device, $name, $maxSizeInBytes)
    ; CVAPI(void) cudaDeviceInfoDeviceName(cv::cuda::DeviceInfo* device, char* name, int maxSizeInBytes);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoDeviceName", $sDeviceDllType, $device, $sNameDllType, $name, "int", $maxSizeInBytes), "cudaDeviceInfoDeviceName", @error)
EndFunc   ;==>_cudaDeviceInfoDeviceName

Func _cudaDeviceInfoComputeCapability($device, $major, $minor)
    ; CVAPI(void) cudaDeviceInfoComputeCapability(cv::cuda::DeviceInfo* device, int* major, int* minor);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf

    Local $sMajorDllType
    If IsDllStruct($major) Then
        $sMajorDllType = "struct*"
    Else
        $sMajorDllType = "int*"
    EndIf

    Local $sMinorDllType
    If IsDllStruct($minor) Then
        $sMinorDllType = "struct*"
    Else
        $sMinorDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoComputeCapability", $sDeviceDllType, $device, $sMajorDllType, $major, $sMinorDllType, $minor), "cudaDeviceInfoComputeCapability", @error)
EndFunc   ;==>_cudaDeviceInfoComputeCapability

Func _cudaDeviceInfoMultiProcessorCount($device)
    ; CVAPI(int) cudaDeviceInfoMultiProcessorCount(cv::cuda::DeviceInfo* device);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaDeviceInfoMultiProcessorCount", $sDeviceDllType, $device), "cudaDeviceInfoMultiProcessorCount", @error)
EndFunc   ;==>_cudaDeviceInfoMultiProcessorCount

Func _cudaDeviceInfoFreeMemInfo($info, $free)
    ; CVAPI(void) cudaDeviceInfoFreeMemInfo(cv::cuda::DeviceInfo* info, size_t* free);

    Local $sInfoDllType
    If IsDllStruct($info) Then
        $sInfoDllType = "struct*"
    Else
        $sInfoDllType = "ptr"
    EndIf

    Local $sFreeDllType
    If IsDllStruct($free) Then
        $sFreeDllType = "struct*"
    Else
        $sFreeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoFreeMemInfo", $sInfoDllType, $info, $sFreeDllType, $free), "cudaDeviceInfoFreeMemInfo", @error)
EndFunc   ;==>_cudaDeviceInfoFreeMemInfo

Func _cudaDeviceInfoTotalMemInfo($info, $total)
    ; CVAPI(void) cudaDeviceInfoTotalMemInfo(cv::cuda::DeviceInfo* info, size_t* total);

    Local $sInfoDllType
    If IsDllStruct($info) Then
        $sInfoDllType = "struct*"
    Else
        $sInfoDllType = "ptr"
    EndIf

    Local $sTotalDllType
    If IsDllStruct($total) Then
        $sTotalDllType = "struct*"
    Else
        $sTotalDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoTotalMemInfo", $sInfoDllType, $info, $sTotalDllType, $total), "cudaDeviceInfoTotalMemInfo", @error)
EndFunc   ;==>_cudaDeviceInfoTotalMemInfo

Func _cudaDeviceInfoSupports($device, $feature)
    ; CVAPI(bool) cudaDeviceInfoSupports(cv::cuda::DeviceInfo* device, cv::cuda::FeatureSet feature);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaDeviceInfoSupports", $sDeviceDllType, $device, "int", $feature), "cudaDeviceInfoSupports", @error)
EndFunc   ;==>_cudaDeviceInfoSupports

Func _cudaDeviceInfoIsCompatible($device)
    ; CVAPI(bool) cudaDeviceInfoIsCompatible(cv::cuda::DeviceInfo* device);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaDeviceInfoIsCompatible", $sDeviceDllType, $device), "cudaDeviceInfoIsCompatible", @error)
EndFunc   ;==>_cudaDeviceInfoIsCompatible

Func _cudaPrintCudaDeviceInfo($device)
    ; CVAPI(void) cudaPrintCudaDeviceInfo(int device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPrintCudaDeviceInfo", "int", $device), "cudaPrintCudaDeviceInfo", @error)
EndFunc   ;==>_cudaPrintCudaDeviceInfo

Func _cudaPrintShortCudaDeviceInfo($device)
    ; CVAPI(void) cudaPrintShortCudaDeviceInfo(int device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPrintShortCudaDeviceInfo", "int", $device), "cudaPrintShortCudaDeviceInfo", @error)
EndFunc   ;==>_cudaPrintShortCudaDeviceInfo

Func _cudaConvertFp16($src, $dst, $stream)
    ; CVAPI(void) cudaConvertFp16(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvertFp16", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaConvertFp16", @error)
EndFunc   ;==>_cudaConvertFp16

Func _cudaConvertFp16Typed($typeOfSrc, $src, $typeOfDst, $dst, $stream)

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

    _cudaConvertFp16($iArrSrc, $oArrDst, $stream)

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
EndFunc   ;==>_cudaConvertFp16Typed

Func _cudaConvertFp16Mat($src, $dst, $stream)
    ; cudaConvertFp16 using cv::Mat instead of _*Array
    _cudaConvertFp16Typed("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaConvertFp16Mat

Func _targetArchsBuildWith($featureSet)
    ; CVAPI(bool) targetArchsBuildWith(cv::cuda::FeatureSet featureSet);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsBuildWith", "int", $featureSet), "targetArchsBuildWith", @error)
EndFunc   ;==>_targetArchsBuildWith

Func _targetArchsHas($major, $minor)
    ; CVAPI(bool) targetArchsHas(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHas", "int", $major, "int", $minor), "targetArchsHas", @error)
EndFunc   ;==>_targetArchsHas

Func _targetArchsHasPtx($major, $minor)
    ; CVAPI(bool) targetArchsHasPtx(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHasPtx", "int", $major, "int", $minor), "targetArchsHasPtx", @error)
EndFunc   ;==>_targetArchsHasPtx

Func _targetArchsHasBin($major, $minor)
    ; CVAPI(bool) targetArchsHasBin(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHasBin", "int", $major, "int", $minor), "targetArchsHasBin", @error)
EndFunc   ;==>_targetArchsHasBin

Func _targetArchsHasEqualOrLessPtx($major, $minor)
    ; CVAPI(bool) targetArchsHasEqualOrLessPtx(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHasEqualOrLessPtx", "int", $major, "int", $minor), "targetArchsHasEqualOrLessPtx", @error)
EndFunc   ;==>_targetArchsHasEqualOrLessPtx

Func _targetArchsHasEqualOrGreater($major, $minor)
    ; CVAPI(bool) targetArchsHasEqualOrGreater(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHasEqualOrGreater", "int", $major, "int", $minor), "targetArchsHasEqualOrGreater", @error)
EndFunc   ;==>_targetArchsHasEqualOrGreater

Func _targetArchsHasEqualOrGreaterPtx($major, $minor)
    ; CVAPI(bool) targetArchsHasEqualOrGreaterPtx(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHasEqualOrGreaterPtx", "int", $major, "int", $minor), "targetArchsHasEqualOrGreaterPtx", @error)
EndFunc   ;==>_targetArchsHasEqualOrGreaterPtx

Func _targetArchsHasEqualOrGreaterBin($major, $minor)
    ; CVAPI(bool) targetArchsHasEqualOrGreaterBin(int major, int minor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsHasEqualOrGreaterBin", "int", $major, "int", $minor), "targetArchsHasEqualOrGreaterBin", @error)
EndFunc   ;==>_targetArchsHasEqualOrGreaterBin

Func _gpuMatCreateDefault()
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateDefault"), "gpuMatCreateDefault", @error)
EndFunc   ;==>_gpuMatCreateDefault

Func _gpuMatCreate($m, $rows, $cols, $type)
    ; CVAPI(void) gpuMatCreate(cv::cuda::GpuMat* m, int rows, int cols, int type);

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatCreate", $sMDllType, $m, "int", $rows, "int", $cols, "int", $type), "gpuMatCreate", @error)
EndFunc   ;==>_gpuMatCreate

Func _gpuMatCreateContinuous($rows, $cols, $type)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateContinuous(int rows, int cols, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateContinuous", "int", $rows, "int", $cols, "int", $type), "gpuMatCreateContinuous", @error)
EndFunc   ;==>_gpuMatCreateContinuous

Func _gpuMatIsContinuous($gpuMat)
    ; CVAPI(bool) gpuMatIsContinuous(cv::cuda::GpuMat* gpuMat);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "gpuMatIsContinuous", $sGpuMatDllType, $gpuMat), "gpuMatIsContinuous", @error)
EndFunc   ;==>_gpuMatIsContinuous

Func _gpuMatGetRegion($other, $rowRange, $colRange)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatGetRegion(cv::cuda::GpuMat* other, cv::Range* rowRange, cv::Range* colRange);

    Local $sOtherDllType
    If IsDllStruct($other) Then
        $sOtherDllType = "struct*"
    Else
        $sOtherDllType = "ptr"
    EndIf

    Local $sRowRangeDllType
    If IsDllStruct($rowRange) Then
        $sRowRangeDllType = "struct*"
    Else
        $sRowRangeDllType = "ptr"
    EndIf

    Local $sColRangeDllType
    If IsDllStruct($colRange) Then
        $sColRangeDllType = "struct*"
    Else
        $sColRangeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatGetRegion", $sOtherDllType, $other, $sRowRangeDllType, $rowRange, $sColRangeDllType, $colRange), "gpuMatGetRegion", @error)
EndFunc   ;==>_gpuMatGetRegion

Func _gpuMatRelease($mat)
    ; CVAPI(void) gpuMatRelease(cv::cuda::GpuMat** mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    ElseIf $mat == Null Then
        $sMatDllType = "ptr"
    Else
        $sMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatRelease", $sMatDllType, $mat), "gpuMatRelease", @error)
EndFunc   ;==>_gpuMatRelease

Func _gpuMatCreateFromInputArray($arr)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateFromInputArray(cv::_InputArray* arr);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateFromInputArray", $sArrDllType, $arr), "gpuMatCreateFromInputArray", @error)
EndFunc   ;==>_gpuMatCreateFromInputArray

Func _gpuMatCreateFromInputArrayTyped($typeOfArr, $arr)

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

    Local $retval = _gpuMatCreateFromInputArray($iArrArr)

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
EndFunc   ;==>_gpuMatCreateFromInputArrayTyped

Func _gpuMatCreateFromInputArrayMat($arr)
    ; gpuMatCreateFromInputArray using cv::Mat instead of _*Array
    Local $retval = _gpuMatCreateFromInputArrayTyped("Mat", $arr)

    Return $retval
EndFunc   ;==>_gpuMatCreateFromInputArrayMat

Func _gpuMatGetSize($gpuMat, $size)
    ; CVAPI(void) gpuMatGetSize(cv::cuda::GpuMat* gpuMat, CvSize* size);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatGetSize", $sGpuMatDllType, $gpuMat, $sSizeDllType, $size), "gpuMatGetSize", @error)
EndFunc   ;==>_gpuMatGetSize

Func _gpuMatIsEmpty($gpuMat)
    ; CVAPI(bool) gpuMatIsEmpty(cv::cuda::GpuMat* gpuMat);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "gpuMatIsEmpty", $sGpuMatDllType, $gpuMat), "gpuMatIsEmpty", @error)
EndFunc   ;==>_gpuMatIsEmpty

Func _gpuMatGetChannels($gpuMat)
    ; CVAPI(int) gpuMatGetChannels(cv::cuda::GpuMat* gpuMat);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetChannels", $sGpuMatDllType, $gpuMat), "gpuMatGetChannels", @error)
EndFunc   ;==>_gpuMatGetChannels

Func _gpuMatGetType($gpuMat)
    ; CVAPI(int) gpuMatGetType(cv::cuda::GpuMat* gpuMat);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetType", $sGpuMatDllType, $gpuMat), "gpuMatGetType", @error)
EndFunc   ;==>_gpuMatGetType

Func _gpuMatGetDepth($gpuMat)
    ; CVAPI(int) gpuMatGetDepth(cv::cuda::GpuMat* gpuMat);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetDepth", $sGpuMatDllType, $gpuMat), "gpuMatGetDepth", @error)
EndFunc   ;==>_gpuMatGetDepth

Func _gpuMatUpload($gpuMat, $arr, $stream)
    ; CVAPI(void) gpuMatUpload(cv::cuda::GpuMat* gpuMat, cv::_InputArray* arr, cv::cuda::Stream* stream);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatUpload", $sGpuMatDllType, $gpuMat, $sArrDllType, $arr, $sStreamDllType, $stream), "gpuMatUpload", @error)
EndFunc   ;==>_gpuMatUpload

Func _gpuMatUploadTyped($gpuMat, $typeOfArr, $arr, $stream)

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

    _gpuMatUpload($gpuMat, $iArrArr, $stream)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveInputArrayRelease($iArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf
EndFunc   ;==>_gpuMatUploadTyped

Func _gpuMatUploadMat($gpuMat, $arr, $stream)
    ; gpuMatUpload using cv::Mat instead of _*Array
    _gpuMatUploadTyped($gpuMat, "Mat", $arr, $stream)
EndFunc   ;==>_gpuMatUploadMat

Func _gpuMatDownload($gpuMat, $arr, $stream)
    ; CVAPI(void) gpuMatDownload(cv::cuda::GpuMat* gpuMat, cv::_OutputArray* arr, cv::cuda::Stream* stream);

    Local $sGpuMatDllType
    If IsDllStruct($gpuMat) Then
        $sGpuMatDllType = "struct*"
    Else
        $sGpuMatDllType = "ptr"
    EndIf

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatDownload", $sGpuMatDllType, $gpuMat, $sArrDllType, $arr, $sStreamDllType, $stream), "gpuMatDownload", @error)
EndFunc   ;==>_gpuMatDownload

Func _gpuMatDownloadTyped($gpuMat, $typeOfArr, $arr, $stream)

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

    _gpuMatDownload($gpuMat, $oArrArr, $stream)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveOutputArrayRelease($oArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf
EndFunc   ;==>_gpuMatDownloadTyped

Func _gpuMatDownloadMat($gpuMat, $arr, $stream)
    ; gpuMatDownload using cv::Mat instead of _*Array
    _gpuMatDownloadTyped($gpuMat, "Mat", $arr, $stream)
EndFunc   ;==>_gpuMatDownloadMat

Func _gpuMatConvertTo($src, $dst, $rtype, $alpha, $beta, $stream)
    ; CVAPI(void) gpuMatConvertTo(const cv::cuda::GpuMat* src, cv::_OutputArray* dst, int rtype, double alpha, double beta, cv::cuda::Stream* stream);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatConvertTo", $sSrcDllType, $src, $sDstDllType, $dst, "int", $rtype, "double", $alpha, "double", $beta, $sStreamDllType, $stream), "gpuMatConvertTo", @error)
EndFunc   ;==>_gpuMatConvertTo

Func _gpuMatConvertToTyped($src, $typeOfDst, $dst, $rtype, $alpha, $beta, $stream)

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

    _gpuMatConvertTo($src, $oArrDst, $rtype, $alpha, $beta, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_gpuMatConvertToTyped

Func _gpuMatConvertToMat($src, $dst, $rtype, $alpha, $beta, $stream)
    ; gpuMatConvertTo using cv::Mat instead of _*Array
    _gpuMatConvertToTyped($src, "Mat", $dst, $rtype, $alpha, $beta, $stream)
EndFunc   ;==>_gpuMatConvertToMat

Func _gpuMatCopyTo($src, $dst, $mask, $stream)
    ; CVAPI(void) gpuMatCopyTo(const cv::cuda::GpuMat* src, cv::_OutputArray* dst, const cv::_InputArray* mask, cv::cuda::Stream* stream);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatCopyTo", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask, $sStreamDllType, $stream), "gpuMatCopyTo", @error)
EndFunc   ;==>_gpuMatCopyTo

Func _gpuMatCopyToTyped($src, $typeOfDst, $dst, $typeOfMask, $mask, $stream)

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

    _gpuMatCopyTo($src, $oArrDst, $iArrMask, $stream)

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
EndFunc   ;==>_gpuMatCopyToTyped

Func _gpuMatCopyToMat($src, $dst, $mask, $stream)
    ; gpuMatCopyTo using cv::Mat instead of _*Array
    _gpuMatCopyToTyped($src, "Mat", $dst, "Mat", $mask, $stream)
EndFunc   ;==>_gpuMatCopyToMat

Func _gpuMatSetTo($mat, $s, $mask, $stream)
    ; CVAPI(void) gpuMatSetTo(cv::cuda::GpuMat* mat, const CvScalar* s, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sSDllType
    If IsDllStruct($s) Then
        $sSDllType = "struct*"
    Else
        $sSDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatSetTo", $sMatDllType, $mat, $sSDllType, $s, $sMaskDllType, $mask, $sStreamDllType, $stream), "gpuMatSetTo", @error)
EndFunc   ;==>_gpuMatSetTo

Func _gpuMatSetToTyped($mat, $s, $typeOfMask, $mask, $stream)

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

    _gpuMatSetTo($mat, $s, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf
EndFunc   ;==>_gpuMatSetToTyped

Func _gpuMatSetToMat($mat, $s, $mask, $stream)
    ; gpuMatSetTo using cv::Mat instead of _*Array
    _gpuMatSetToTyped($mat, $s, "Mat", $mask, $stream)
EndFunc   ;==>_gpuMatSetToMat

Func _gpuMatReshape($src, $dst, $cn, $rows)
    ; CVAPI(void) gpuMatReshape(const cv::cuda::GpuMat* src, cv::cuda::GpuMat* dst, int cn, int rows);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatReshape", $sSrcDllType, $src, $sDstDllType, $dst, "int", $cn, "int", $rows), "gpuMatReshape", @error)
EndFunc   ;==>_gpuMatReshape

Func _gpuMatGetSubRect($arr, $rect)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatGetSubRect(const cv::cuda::GpuMat* arr, CvRect* rect);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatGetSubRect", $sArrDllType, $arr, $sRectDllType, $rect), "gpuMatGetSubRect", @error)
EndFunc   ;==>_gpuMatGetSubRect

Func _streamCreate()
    ; CVAPI(cv::cuda::Stream*) streamCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "streamCreate"), "streamCreate", @error)
EndFunc   ;==>_streamCreate

Func _streamCreateWithFlag($flag)
    ; CVAPI(cv::cuda::Stream*) streamCreateWithFlag(int flag);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "streamCreateWithFlag", "int", $flag), "streamCreateWithFlag", @error)
EndFunc   ;==>_streamCreateWithFlag

Func _streamRelease($stream)
    ; CVAPI(void) streamRelease(cv::cuda::Stream** stream);

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    ElseIf $stream == Null Then
        $sStreamDllType = "ptr"
    Else
        $sStreamDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "streamRelease", $sStreamDllType, $stream), "streamRelease", @error)
EndFunc   ;==>_streamRelease

Func _streamWaitForCompletion($stream)
    ; CVAPI(void) streamWaitForCompletion(cv::cuda::Stream* stream);

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "streamWaitForCompletion", $sStreamDllType, $stream), "streamWaitForCompletion", @error)
EndFunc   ;==>_streamWaitForCompletion

Func _streamQueryIfComplete($stream)
    ; CVAPI(bool) streamQueryIfComplete(cv::cuda::Stream* stream);

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "streamQueryIfComplete", $sStreamDllType, $stream), "streamQueryIfComplete", @error)
EndFunc   ;==>_streamQueryIfComplete