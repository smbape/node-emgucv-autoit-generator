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

    Local $bDeviceIdDllType
    If VarGetType($deviceId) == "DLLStruct" Then
        $bDeviceIdDllType = "struct*"
    Else
        $bDeviceIdDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaDeviceInfoCreate", $bDeviceIdDllType, $deviceId), "cudaDeviceInfoCreate", @error)
EndFunc   ;==>_cudaDeviceInfoCreate

Func _cudaDeviceInfoRelease($di)
    ; CVAPI(void) cudaDeviceInfoRelease(cv::cuda::DeviceInfo** di);

    Local $bDiDllType
    If VarGetType($di) == "DLLStruct" Then
        $bDiDllType = "struct*"
    Else
        $bDiDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoRelease", $bDiDllType, $di), "cudaDeviceInfoRelease", @error)
EndFunc   ;==>_cudaDeviceInfoRelease

Func _cudaDeviceInfoDeviceName($device, $name, $maxSizeInBytes)
    ; CVAPI(void) cudaDeviceInfoDeviceName(cv::cuda::DeviceInfo* device, char* name, int maxSizeInBytes);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf

    Local $bNameDllType
    If VarGetType($name) == "DLLStruct" Then
        $bNameDllType = "struct*"
    Else
        $bNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoDeviceName", $bDeviceDllType, $device, $bNameDllType, $name, "int", $maxSizeInBytes), "cudaDeviceInfoDeviceName", @error)
EndFunc   ;==>_cudaDeviceInfoDeviceName

Func _cudaDeviceInfoComputeCapability($device, $major, $minor)
    ; CVAPI(void) cudaDeviceInfoComputeCapability(cv::cuda::DeviceInfo* device, int* major, int* minor);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf

    Local $bMajorDllType
    If VarGetType($major) == "DLLStruct" Then
        $bMajorDllType = "struct*"
    Else
        $bMajorDllType = "int*"
    EndIf

    Local $bMinorDllType
    If VarGetType($minor) == "DLLStruct" Then
        $bMinorDllType = "struct*"
    Else
        $bMinorDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoComputeCapability", $bDeviceDllType, $device, $bMajorDllType, $major, $bMinorDllType, $minor), "cudaDeviceInfoComputeCapability", @error)
EndFunc   ;==>_cudaDeviceInfoComputeCapability

Func _cudaDeviceInfoMultiProcessorCount($device)
    ; CVAPI(int) cudaDeviceInfoMultiProcessorCount(cv::cuda::DeviceInfo* device);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaDeviceInfoMultiProcessorCount", $bDeviceDllType, $device), "cudaDeviceInfoMultiProcessorCount", @error)
EndFunc   ;==>_cudaDeviceInfoMultiProcessorCount

Func _cudaDeviceInfoFreeMemInfo($info, $free)
    ; CVAPI(void) cudaDeviceInfoFreeMemInfo(cv::cuda::DeviceInfo* info, size_t* free);

    Local $bInfoDllType
    If VarGetType($info) == "DLLStruct" Then
        $bInfoDllType = "struct*"
    Else
        $bInfoDllType = "ptr"
    EndIf

    Local $bFreeDllType
    If VarGetType($free) == "DLLStruct" Then
        $bFreeDllType = "struct*"
    Else
        $bFreeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoFreeMemInfo", $bInfoDllType, $info, $bFreeDllType, $free), "cudaDeviceInfoFreeMemInfo", @error)
EndFunc   ;==>_cudaDeviceInfoFreeMemInfo

Func _cudaDeviceInfoTotalMemInfo($info, $total)
    ; CVAPI(void) cudaDeviceInfoTotalMemInfo(cv::cuda::DeviceInfo* info, size_t* total);

    Local $bInfoDllType
    If VarGetType($info) == "DLLStruct" Then
        $bInfoDllType = "struct*"
    Else
        $bInfoDllType = "ptr"
    EndIf

    Local $bTotalDllType
    If VarGetType($total) == "DLLStruct" Then
        $bTotalDllType = "struct*"
    Else
        $bTotalDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoTotalMemInfo", $bInfoDllType, $info, $bTotalDllType, $total), "cudaDeviceInfoTotalMemInfo", @error)
EndFunc   ;==>_cudaDeviceInfoTotalMemInfo

Func _cudaDeviceInfoSupports($device, $feature)
    ; CVAPI(bool) cudaDeviceInfoSupports(cv::cuda::DeviceInfo* device, cv::cuda::FeatureSet feature);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaDeviceInfoSupports", $bDeviceDllType, $device, "int", $feature), "cudaDeviceInfoSupports", @error)
EndFunc   ;==>_cudaDeviceInfoSupports

Func _cudaDeviceInfoIsCompatible($device)
    ; CVAPI(bool) cudaDeviceInfoIsCompatible(cv::cuda::DeviceInfo* device);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaDeviceInfoIsCompatible", $bDeviceDllType, $device), "cudaDeviceInfoIsCompatible", @error)
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

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvertFp16", $bSrcDllType, $src, $bDstDllType, $dst, $bStreamDllType, $stream), "cudaConvertFp16", @error)
EndFunc   ;==>_cudaConvertFp16

Func _cudaConvertFp16Mat($matSrc, $matDst, $stream)
    ; cudaConvertFp16 using cv::Mat instead of _*Array

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

    _cudaConvertFp16($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatCreate", $bMDllType, $m, "int", $rows, "int", $cols, "int", $type), "gpuMatCreate", @error)
EndFunc   ;==>_gpuMatCreate

Func _gpuMatCreateContinuous($rows, $cols, $type)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateContinuous(int rows, int cols, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateContinuous", "int", $rows, "int", $cols, "int", $type), "gpuMatCreateContinuous", @error)
EndFunc   ;==>_gpuMatCreateContinuous

Func _gpuMatIsContinuous($gpuMat)
    ; CVAPI(bool) gpuMatIsContinuous(cv::cuda::GpuMat* gpuMat);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "gpuMatIsContinuous", $bGpuMatDllType, $gpuMat), "gpuMatIsContinuous", @error)
EndFunc   ;==>_gpuMatIsContinuous

Func _gpuMatGetRegion($other, $rowRange, $colRange)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatGetRegion(cv::cuda::GpuMat* other, cv::Range* rowRange, cv::Range* colRange);

    Local $bOtherDllType
    If VarGetType($other) == "DLLStruct" Then
        $bOtherDllType = "struct*"
    Else
        $bOtherDllType = "ptr"
    EndIf

    Local $bRowRangeDllType
    If VarGetType($rowRange) == "DLLStruct" Then
        $bRowRangeDllType = "struct*"
    Else
        $bRowRangeDllType = "ptr"
    EndIf

    Local $bColRangeDllType
    If VarGetType($colRange) == "DLLStruct" Then
        $bColRangeDllType = "struct*"
    Else
        $bColRangeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatGetRegion", $bOtherDllType, $other, $bRowRangeDllType, $rowRange, $bColRangeDllType, $colRange), "gpuMatGetRegion", @error)
EndFunc   ;==>_gpuMatGetRegion

Func _gpuMatRelease($mat)
    ; CVAPI(void) gpuMatRelease(cv::cuda::GpuMat** mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatRelease", $bMatDllType, $mat), "gpuMatRelease", @error)
EndFunc   ;==>_gpuMatRelease

Func _gpuMatCreateFromInputArray($arr)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateFromInputArray(cv::_InputArray* arr);

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateFromInputArray", $bArrDllType, $arr), "gpuMatCreateFromInputArray", @error)
EndFunc   ;==>_gpuMatCreateFromInputArray

Func _gpuMatCreateFromInputArrayMat($matArr)
    ; gpuMatCreateFromInputArray using cv::Mat instead of _*Array

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

    Local $retval = _gpuMatCreateFromInputArray($iArrArr)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveInputArrayRelease($iArrArr)

    Return $retval
EndFunc   ;==>_gpuMatCreateFromInputArrayMat

Func _gpuMatGetSize($gpuMat, $size)
    ; CVAPI(void) gpuMatGetSize(cv::cuda::GpuMat* gpuMat, CvSize* size);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatGetSize", $bGpuMatDllType, $gpuMat, $bSizeDllType, $size), "gpuMatGetSize", @error)
EndFunc   ;==>_gpuMatGetSize

Func _gpuMatIsEmpty($gpuMat)
    ; CVAPI(bool) gpuMatIsEmpty(cv::cuda::GpuMat* gpuMat);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "gpuMatIsEmpty", $bGpuMatDllType, $gpuMat), "gpuMatIsEmpty", @error)
EndFunc   ;==>_gpuMatIsEmpty

Func _gpuMatGetChannels($gpuMat)
    ; CVAPI(int) gpuMatGetChannels(cv::cuda::GpuMat* gpuMat);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetChannels", $bGpuMatDllType, $gpuMat), "gpuMatGetChannels", @error)
EndFunc   ;==>_gpuMatGetChannels

Func _gpuMatGetType($gpuMat)
    ; CVAPI(int) gpuMatGetType(cv::cuda::GpuMat* gpuMat);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetType", $bGpuMatDllType, $gpuMat), "gpuMatGetType", @error)
EndFunc   ;==>_gpuMatGetType

Func _gpuMatGetDepth($gpuMat)
    ; CVAPI(int) gpuMatGetDepth(cv::cuda::GpuMat* gpuMat);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetDepth", $bGpuMatDllType, $gpuMat), "gpuMatGetDepth", @error)
EndFunc   ;==>_gpuMatGetDepth

Func _gpuMatUpload($gpuMat, $arr, $stream)
    ; CVAPI(void) gpuMatUpload(cv::cuda::GpuMat* gpuMat, cv::_InputArray* arr, cv::cuda::Stream* stream);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatUpload", $bGpuMatDllType, $gpuMat, $bArrDllType, $arr, $bStreamDllType, $stream), "gpuMatUpload", @error)
EndFunc   ;==>_gpuMatUpload

Func _gpuMatUploadMat($gpuMat, $matArr, $stream)
    ; gpuMatUpload using cv::Mat instead of _*Array

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

    _gpuMatUpload($gpuMat, $iArrArr, $stream)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveInputArrayRelease($iArrArr)
EndFunc   ;==>_gpuMatUploadMat

Func _gpuMatDownload($gpuMat, $arr, $stream)
    ; CVAPI(void) gpuMatDownload(cv::cuda::GpuMat* gpuMat, cv::_OutputArray* arr, cv::cuda::Stream* stream);

    Local $bGpuMatDllType
    If VarGetType($gpuMat) == "DLLStruct" Then
        $bGpuMatDllType = "struct*"
    Else
        $bGpuMatDllType = "ptr"
    EndIf

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatDownload", $bGpuMatDllType, $gpuMat, $bArrDllType, $arr, $bStreamDllType, $stream), "gpuMatDownload", @error)
EndFunc   ;==>_gpuMatDownload

Func _gpuMatDownloadMat($gpuMat, $matArr, $stream)
    ; gpuMatDownload using cv::Mat instead of _*Array

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

    _gpuMatDownload($gpuMat, $oArrArr, $stream)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveOutputArrayRelease($oArrArr)
EndFunc   ;==>_gpuMatDownloadMat

Func _gpuMatConvertTo($src, $dst, $rtype, $alpha, $beta, $stream)
    ; CVAPI(void) gpuMatConvertTo(const cv::cuda::GpuMat* src, cv::_OutputArray* dst, int rtype, double alpha, double beta, cv::cuda::Stream* stream);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatConvertTo", $bSrcDllType, $src, $bDstDllType, $dst, "int", $rtype, "double", $alpha, "double", $beta, $bStreamDllType, $stream), "gpuMatConvertTo", @error)
EndFunc   ;==>_gpuMatConvertTo

Func _gpuMatConvertToMat($src, $matDst, $rtype, $alpha, $beta, $stream)
    ; gpuMatConvertTo using cv::Mat instead of _*Array

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

    _gpuMatConvertTo($src, $oArrDst, $rtype, $alpha, $beta, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_gpuMatConvertToMat

Func _gpuMatCopyTo($src, $dst, $mask, $stream)
    ; CVAPI(void) gpuMatCopyTo(const cv::cuda::GpuMat* src, cv::_OutputArray* dst, const cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatCopyTo", $bSrcDllType, $src, $bDstDllType, $dst, $bMaskDllType, $mask, $bStreamDllType, $stream), "gpuMatCopyTo", @error)
EndFunc   ;==>_gpuMatCopyTo

Func _gpuMatCopyToMat($src, $matDst, $matMask, $stream)
    ; gpuMatCopyTo using cv::Mat instead of _*Array

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

    _gpuMatCopyTo($src, $oArrDst, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_gpuMatCopyToMat

Func _gpuMatSetTo($mat, $s, $mask, $stream)
    ; CVAPI(void) gpuMatSetTo(cv::cuda::GpuMat* mat, const CvScalar* s, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bSDllType
    If VarGetType($s) == "DLLStruct" Then
        $bSDllType = "struct*"
    Else
        $bSDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatSetTo", $bMatDllType, $mat, $bSDllType, $s, $bMaskDllType, $mask, $bStreamDllType, $stream), "gpuMatSetTo", @error)
EndFunc   ;==>_gpuMatSetTo

Func _gpuMatSetToMat($mat, $s, $matMask, $stream)
    ; gpuMatSetTo using cv::Mat instead of _*Array

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

    _gpuMatSetTo($mat, $s, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)
EndFunc   ;==>_gpuMatSetToMat

Func _gpuMatReshape($src, $dst, $cn, $rows)
    ; CVAPI(void) gpuMatReshape(const cv::cuda::GpuMat* src, cv::cuda::GpuMat* dst, int cn, int rows);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatReshape", $bSrcDllType, $src, $bDstDllType, $dst, "int", $cn, "int", $rows), "gpuMatReshape", @error)
EndFunc   ;==>_gpuMatReshape

Func _gpuMatGetSubRect($arr, $rect)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatGetSubRect(const cv::cuda::GpuMat* arr, CvRect* rect);

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr"
    EndIf

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatGetSubRect", $bArrDllType, $arr, $bRectDllType, $rect), "gpuMatGetSubRect", @error)
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

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "streamRelease", $bStreamDllType, $stream), "streamRelease", @error)
EndFunc   ;==>_streamRelease

Func _streamWaitForCompletion($stream)
    ; CVAPI(void) streamWaitForCompletion(cv::cuda::Stream* stream);

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "streamWaitForCompletion", $bStreamDllType, $stream), "streamWaitForCompletion", @error)
EndFunc   ;==>_streamWaitForCompletion

Func _streamQueryIfComplete($stream)
    ; CVAPI(bool) streamQueryIfComplete(cv::cuda::Stream* stream);

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "streamQueryIfComplete", $bStreamDllType, $stream), "streamQueryIfComplete", @error)
EndFunc   ;==>_streamQueryIfComplete