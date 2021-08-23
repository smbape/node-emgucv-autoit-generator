#include-once
#include "..\..\CVEUtils.au3"

Func _cveHfsSegmentCreate($height, $width, $segEgbThresholdI, $minRegionSizeI, $segEgbThresholdII, $minRegionSizeII, $spatialWeight, $slicSpixelSize, $numSlicIter, $algorithmPtr, $sharedPtr)
    ; CVAPI(cv::hfs::HfsSegment*) cveHfsSegmentCreate(int height, int width, float segEgbThresholdI, int minRegionSizeI, float segEgbThresholdII, int minRegionSizeII, float spatialWeight, int slicSpixelSize, int numSlicIter, cv::Algorithm** algorithmPtr, cv::Ptr<cv::hfs::HfsSegment>** sharedPtr);

    Local $sAlgorithmPtrDllType
    If IsDllStruct($algorithmPtr) Then
        $sAlgorithmPtrDllType = "struct*"
    ElseIf $algorithmPtr == Null Then
        $sAlgorithmPtrDllType = "ptr"
    Else
        $sAlgorithmPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHfsSegmentCreate", "int", $height, "int", $width, "float", $segEgbThresholdI, "int", $minRegionSizeI, "float", $segEgbThresholdII, "int", $minRegionSizeII, "float", $spatialWeight, "int", $slicSpixelSize, "int", $numSlicIter, $sAlgorithmPtrDllType, $algorithmPtr, $sSharedPtrDllType, $sharedPtr), "cveHfsSegmentCreate", @error)
EndFunc   ;==>_cveHfsSegmentCreate

Func _cveHfsSegmentRelease($hfsSegmentPtr)
    ; CVAPI(void) cveHfsSegmentRelease(cv::Ptr<cv::hfs::HfsSegment>** hfsSegmentPtr);

    Local $sHfsSegmentPtrDllType
    If IsDllStruct($hfsSegmentPtr) Then
        $sHfsSegmentPtrDllType = "struct*"
    ElseIf $hfsSegmentPtr == Null Then
        $sHfsSegmentPtrDllType = "ptr"
    Else
        $sHfsSegmentPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHfsSegmentRelease", $sHfsSegmentPtrDllType, $hfsSegmentPtr), "cveHfsSegmentRelease", @error)
EndFunc   ;==>_cveHfsSegmentRelease

Func _cveHfsPerformSegment($hfsSegment, $src, $dst, $ifDraw, $useGpu)
    ; CVAPI(void) cveHfsPerformSegment(cv::hfs::HfsSegment* hfsSegment, cv::_InputArray* src, cv::Mat* dst, bool ifDraw, bool useGpu);

    Local $sHfsSegmentDllType
    If IsDllStruct($hfsSegment) Then
        $sHfsSegmentDllType = "struct*"
    Else
        $sHfsSegmentDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHfsPerformSegment", $sHfsSegmentDllType, $hfsSegment, $sSrcDllType, $src, $sDstDllType, $dst, "boolean", $ifDraw, "boolean", $useGpu), "cveHfsPerformSegment", @error)
EndFunc   ;==>_cveHfsPerformSegment

Func _cveHfsPerformSegmentMat($hfsSegment, $matSrc, $dst, $ifDraw, $useGpu)
    ; cveHfsPerformSegment using cv::Mat instead of _*Array

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

    _cveHfsPerformSegment($hfsSegment, $iArrSrc, $dst, $ifDraw, $useGpu)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveHfsPerformSegmentMat