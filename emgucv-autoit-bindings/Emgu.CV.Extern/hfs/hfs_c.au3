#include-once
#include "..\..\CVEUtils.au3"

Func _cveHfsSegmentCreate($height, $width, $segEgbThresholdI, $minRegionSizeI, $segEgbThresholdII, $minRegionSizeII, $spatialWeight, $slicSpixelSize, $numSlicIter, $algorithmPtr, $sharedPtr)
    ; CVAPI(cv::hfs::HfsSegment*) cveHfsSegmentCreate(int height, int width, float segEgbThresholdI, int minRegionSizeI, float segEgbThresholdII, int minRegionSizeII, float spatialWeight, int slicSpixelSize, int numSlicIter, cv::Algorithm** algorithmPtr, cv::Ptr<cv::hfs::HfsSegment>** sharedPtr);

    Local $bAlgorithmPtrDllType
    If VarGetType($algorithmPtr) == "DLLStruct" Then
        $bAlgorithmPtrDllType = "struct*"
    Else
        $bAlgorithmPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHfsSegmentCreate", "int", $height, "int", $width, "float", $segEgbThresholdI, "int", $minRegionSizeI, "float", $segEgbThresholdII, "int", $minRegionSizeII, "float", $spatialWeight, "int", $slicSpixelSize, "int", $numSlicIter, $bAlgorithmPtrDllType, $algorithmPtr, $bSharedPtrDllType, $sharedPtr), "cveHfsSegmentCreate", @error)
EndFunc   ;==>_cveHfsSegmentCreate

Func _cveHfsSegmentRelease($hfsSegmentPtr)
    ; CVAPI(void) cveHfsSegmentRelease(cv::Ptr<cv::hfs::HfsSegment>** hfsSegmentPtr);

    Local $bHfsSegmentPtrDllType
    If VarGetType($hfsSegmentPtr) == "DLLStruct" Then
        $bHfsSegmentPtrDllType = "struct*"
    Else
        $bHfsSegmentPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHfsSegmentRelease", $bHfsSegmentPtrDllType, $hfsSegmentPtr), "cveHfsSegmentRelease", @error)
EndFunc   ;==>_cveHfsSegmentRelease

Func _cveHfsPerformSegment($hfsSegment, $src, $dst, $ifDraw, $useGpu)
    ; CVAPI(void) cveHfsPerformSegment(cv::hfs::HfsSegment* hfsSegment, cv::_InputArray* src, cv::Mat* dst, bool ifDraw, bool useGpu);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHfsPerformSegment", "ptr", $hfsSegment, "ptr", $src, "ptr", $dst, "boolean", $ifDraw, "boolean", $useGpu), "cveHfsPerformSegment", @error)
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