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

Func _cudaDeviceInfoCreate(ByRef $deviceId)
    ; CVAPI(cv::cuda::DeviceInfo*) cudaDeviceInfoCreate(int* deviceId);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaDeviceInfoCreate", "struct*", $deviceId), "cudaDeviceInfoCreate", @error)
EndFunc   ;==>_cudaDeviceInfoCreate

Func _cudaDeviceInfoRelease(ByRef $di)
    ; CVAPI(void) cudaDeviceInfoRelease(cv::cuda::DeviceInfo** di);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoRelease", "ptr*", $di), "cudaDeviceInfoRelease", @error)
EndFunc   ;==>_cudaDeviceInfoRelease

Func _cudaDeviceInfoDeviceName(ByRef $device, ByRef $name, $maxSizeInBytes)
    ; CVAPI(void) cudaDeviceInfoDeviceName(cv::cuda::DeviceInfo* device, char* name, int maxSizeInBytes);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoDeviceName", "ptr", $device, "struct*", $name, "int", $maxSizeInBytes), "cudaDeviceInfoDeviceName", @error)
EndFunc   ;==>_cudaDeviceInfoDeviceName

Func _cudaDeviceInfoComputeCapability(ByRef $device, ByRef $major, ByRef $minor)
    ; CVAPI(void) cudaDeviceInfoComputeCapability(cv::cuda::DeviceInfo* device, int* major, int* minor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoComputeCapability", "ptr", $device, "struct*", $major, "struct*", $minor), "cudaDeviceInfoComputeCapability", @error)
EndFunc   ;==>_cudaDeviceInfoComputeCapability

Func _cudaDeviceInfoMultiProcessorCount(ByRef $device)
    ; CVAPI(int) cudaDeviceInfoMultiProcessorCount(cv::cuda::DeviceInfo* device);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaDeviceInfoMultiProcessorCount", "ptr", $device), "cudaDeviceInfoMultiProcessorCount", @error)
EndFunc   ;==>_cudaDeviceInfoMultiProcessorCount

Func _cudaDeviceInfoFreeMemInfo(ByRef $info, ByRef $free)
    ; CVAPI(void) cudaDeviceInfoFreeMemInfo(cv::cuda::DeviceInfo* info, size_t* free);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoFreeMemInfo", "ptr", $info, "struct*", $free), "cudaDeviceInfoFreeMemInfo", @error)
EndFunc   ;==>_cudaDeviceInfoFreeMemInfo

Func _cudaDeviceInfoTotalMemInfo(ByRef $info, ByRef $total)
    ; CVAPI(void) cudaDeviceInfoTotalMemInfo(cv::cuda::DeviceInfo* info, size_t* total);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDeviceInfoTotalMemInfo", "ptr", $info, "struct*", $total), "cudaDeviceInfoTotalMemInfo", @error)
EndFunc   ;==>_cudaDeviceInfoTotalMemInfo

Func _cudaDeviceInfoSupports(ByRef $device, $feature)
    ; CVAPI(bool) cudaDeviceInfoSupports(cv::cuda::DeviceInfo* device, cv::cuda::FeatureSet feature);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaDeviceInfoSupports", "ptr", $device, "cv::cuda::FeatureSet", $feature), "cudaDeviceInfoSupports", @error)
EndFunc   ;==>_cudaDeviceInfoSupports

Func _cudaDeviceInfoIsCompatible(ByRef $device)
    ; CVAPI(bool) cudaDeviceInfoIsCompatible(cv::cuda::DeviceInfo* device);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaDeviceInfoIsCompatible", "ptr", $device), "cudaDeviceInfoIsCompatible", @error)
EndFunc   ;==>_cudaDeviceInfoIsCompatible

Func _cudaPrintCudaDeviceInfo($device)
    ; CVAPI(void) cudaPrintCudaDeviceInfo(int device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPrintCudaDeviceInfo", "int", $device), "cudaPrintCudaDeviceInfo", @error)
EndFunc   ;==>_cudaPrintCudaDeviceInfo

Func _cudaPrintShortCudaDeviceInfo($device)
    ; CVAPI(void) cudaPrintShortCudaDeviceInfo(int device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPrintShortCudaDeviceInfo", "int", $device), "cudaPrintShortCudaDeviceInfo", @error)
EndFunc   ;==>_cudaPrintShortCudaDeviceInfo

Func _cudaConvertFp16(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaConvertFp16(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaConvertFp16", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaConvertFp16", @error)
EndFunc   ;==>_cudaConvertFp16

Func _cudaConvertFp16Mat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "targetArchsBuildWith", "cv::cuda::FeatureSet", $featureSet), "targetArchsBuildWith", @error)
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

Func _gpuMatCreate(ByRef $m, $rows, $cols, $type)
    ; CVAPI(void) gpuMatCreate(cv::cuda::GpuMat* m, int rows, int cols, int type);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatCreate", "ptr", $m, "int", $rows, "int", $cols, "int", $type), "gpuMatCreate", @error)
EndFunc   ;==>_gpuMatCreate

Func _gpuMatCreateContinuous($rows, $cols, $type)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateContinuous(int rows, int cols, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateContinuous", "int", $rows, "int", $cols, "int", $type), "gpuMatCreateContinuous", @error)
EndFunc   ;==>_gpuMatCreateContinuous

Func _gpuMatIsContinuous(ByRef $gpuMat)
    ; CVAPI(bool) gpuMatIsContinuous(cv::cuda::GpuMat* gpuMat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "gpuMatIsContinuous", "ptr", $gpuMat), "gpuMatIsContinuous", @error)
EndFunc   ;==>_gpuMatIsContinuous

Func _gpuMatGetRegion(ByRef $other, ByRef $rowRange, ByRef $colRange)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatGetRegion(cv::cuda::GpuMat* other, cv::Range* rowRange, cv::Range* colRange);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatGetRegion", "ptr", $other, "ptr", $rowRange, "ptr", $colRange), "gpuMatGetRegion", @error)
EndFunc   ;==>_gpuMatGetRegion

Func _gpuMatRelease(ByRef $mat)
    ; CVAPI(void) gpuMatRelease(cv::cuda::GpuMat** mat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatRelease", "ptr*", $mat), "gpuMatRelease", @error)
EndFunc   ;==>_gpuMatRelease

Func _gpuMatCreateFromInputArray(ByRef $arr)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatCreateFromInputArray(cv::_InputArray* arr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatCreateFromInputArray", "ptr", $arr), "gpuMatCreateFromInputArray", @error)
EndFunc   ;==>_gpuMatCreateFromInputArray

Func _gpuMatCreateFromInputArrayMat(ByRef $matArr)
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

Func _gpuMatGetSize(ByRef $gpuMat, ByRef $size)
    ; CVAPI(void) gpuMatGetSize(cv::cuda::GpuMat* gpuMat, CvSize* size);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatGetSize", "ptr", $gpuMat, "struct*", $size), "gpuMatGetSize", @error)
EndFunc   ;==>_gpuMatGetSize

Func _gpuMatIsEmpty(ByRef $gpuMat)
    ; CVAPI(bool) gpuMatIsEmpty(cv::cuda::GpuMat* gpuMat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "gpuMatIsEmpty", "ptr", $gpuMat), "gpuMatIsEmpty", @error)
EndFunc   ;==>_gpuMatIsEmpty

Func _gpuMatGetChannels(ByRef $gpuMat)
    ; CVAPI(int) gpuMatGetChannels(cv::cuda::GpuMat* gpuMat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetChannels", "ptr", $gpuMat), "gpuMatGetChannels", @error)
EndFunc   ;==>_gpuMatGetChannels

Func _gpuMatGetType(ByRef $gpuMat)
    ; CVAPI(int) gpuMatGetType(cv::cuda::GpuMat* gpuMat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetType", "ptr", $gpuMat), "gpuMatGetType", @error)
EndFunc   ;==>_gpuMatGetType

Func _gpuMatGetDepth(ByRef $gpuMat)
    ; CVAPI(int) gpuMatGetDepth(cv::cuda::GpuMat* gpuMat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "gpuMatGetDepth", "ptr", $gpuMat), "gpuMatGetDepth", @error)
EndFunc   ;==>_gpuMatGetDepth

Func _gpuMatUpload(ByRef $gpuMat, ByRef $arr, ByRef $stream)
    ; CVAPI(void) gpuMatUpload(cv::cuda::GpuMat* gpuMat, cv::_InputArray* arr, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatUpload", "ptr", $gpuMat, "ptr", $arr, "ptr", $stream), "gpuMatUpload", @error)
EndFunc   ;==>_gpuMatUpload

Func _gpuMatUploadMat(ByRef $gpuMat, ByRef $matArr, ByRef $stream)
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

Func _gpuMatDownload(ByRef $gpuMat, ByRef $arr, ByRef $stream)
    ; CVAPI(void) gpuMatDownload(cv::cuda::GpuMat* gpuMat, cv::_OutputArray* arr, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatDownload", "ptr", $gpuMat, "ptr", $arr, "ptr", $stream), "gpuMatDownload", @error)
EndFunc   ;==>_gpuMatDownload

Func _gpuMatDownloadMat(ByRef $gpuMat, ByRef $matArr, ByRef $stream)
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

Func _gpuMatConvertTo($src, ByRef $dst, $rtype, $alpha, $beta, ByRef $stream)
    ; CVAPI(void) gpuMatConvertTo(const cv::cuda::GpuMat* src, cv::_OutputArray* dst, int rtype, double alpha, double beta, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatConvertTo", "ptr", $src, "ptr", $dst, "int", $rtype, "double", $alpha, "double", $beta, "ptr", $stream), "gpuMatConvertTo", @error)
EndFunc   ;==>_gpuMatConvertTo

Func _gpuMatConvertToMat($src, ByRef $matDst, $rtype, $alpha, $beta, ByRef $stream)
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

Func _gpuMatCopyTo($src, ByRef $dst, $mask, ByRef $stream)
    ; CVAPI(void) gpuMatCopyTo(const cv::cuda::GpuMat* src, cv::_OutputArray* dst, const cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatCopyTo", "ptr", $src, "ptr", $dst, "ptr", $mask, "ptr", $stream), "gpuMatCopyTo", @error)
EndFunc   ;==>_gpuMatCopyTo

Func _gpuMatCopyToMat($src, ByRef $matDst, ByRef $matMask, ByRef $stream)
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

Func _gpuMatSetTo(ByRef $mat, $s, ByRef $mask, ByRef $stream)
    ; CVAPI(void) gpuMatSetTo(cv::cuda::GpuMat* mat, const CvScalar* s, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatSetTo", "ptr", $mat, "ptr", $s, "ptr", $mask, "ptr", $stream), "gpuMatSetTo", @error)
EndFunc   ;==>_gpuMatSetTo

Func _gpuMatSetToMat(ByRef $mat, $s, ByRef $matMask, ByRef $stream)
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

Func _gpuMatReshape($src, ByRef $dst, $cn, $rows)
    ; CVAPI(void) gpuMatReshape(const cv::cuda::GpuMat* src, cv::cuda::GpuMat* dst, int cn, int rows);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "gpuMatReshape", "ptr", $src, "ptr", $dst, "int", $cn, "int", $rows), "gpuMatReshape", @error)
EndFunc   ;==>_gpuMatReshape

Func _gpuMatGetSubRect($arr, ByRef $rect)
    ; CVAPI(cv::cuda::GpuMat*) gpuMatGetSubRect(const cv::cuda::GpuMat* arr, CvRect* rect);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "gpuMatGetSubRect", "ptr", $arr, "struct*", $rect), "gpuMatGetSubRect", @error)
EndFunc   ;==>_gpuMatGetSubRect

Func _streamCreate()
    ; CVAPI(cv::cuda::Stream*) streamCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "streamCreate"), "streamCreate", @error)
EndFunc   ;==>_streamCreate

Func _streamCreateWithFlag($flag)
    ; CVAPI(cv::cuda::Stream*) streamCreateWithFlag(int flag);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "streamCreateWithFlag", "int", $flag), "streamCreateWithFlag", @error)
EndFunc   ;==>_streamCreateWithFlag

Func _streamRelease(ByRef $stream)
    ; CVAPI(void) streamRelease(cv::cuda::Stream** stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "streamRelease", "ptr*", $stream), "streamRelease", @error)
EndFunc   ;==>_streamRelease

Func _streamWaitForCompletion(ByRef $stream)
    ; CVAPI(void) streamWaitForCompletion(cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "streamWaitForCompletion", "ptr", $stream), "streamWaitForCompletion", @error)
EndFunc   ;==>_streamWaitForCompletion

Func _streamQueryIfComplete(ByRef $stream)
    ; CVAPI(bool) streamQueryIfComplete(cv::cuda::Stream* stream);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "streamQueryIfComplete", "ptr", $stream), "streamQueryIfComplete", @error)
EndFunc   ;==>_streamQueryIfComplete