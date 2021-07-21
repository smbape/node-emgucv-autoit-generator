#include-once
#include "..\..\CVEUtils.au3"

Func _cveLineDescriptorBinaryDescriptorCreate($sharedPtr)
    ; CVAPI(cv::line_descriptor::BinaryDescriptor*) cveLineDescriptorBinaryDescriptorCreate(cv::Ptr<cv::line_descriptor::BinaryDescriptor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineDescriptorBinaryDescriptorCreate", $bSharedPtrDllType, $sharedPtr), "cveLineDescriptorBinaryDescriptorCreate", @error)
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorCreate

Func _cveLineDescriptorBinaryDescriptorDetect($descriptor, $image, $keypoints, $mask)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorDetect(cv::line_descriptor::BinaryDescriptor* descriptor, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keypoints, cv::Mat* mask);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyLineCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyLinePush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorDetect", $bDescriptorDllType, $descriptor, $bImageDllType, $image, $bKeypointsDllType, $vecKeypoints, $bMaskDllType, $mask), "cveLineDescriptorBinaryDescriptorDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyLineRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorDetect

Func _cveLineDescriptorBinaryDescriptorCompute($descriptor, $image, $keylines, $descriptors, $returnFloatDescr)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorCompute(cv::line_descriptor::BinaryDescriptor* descriptor, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keylines, cv::Mat* descriptors, bool returnFloatDescr);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $vecKeylines, $iArrKeylinesSize
    Local $bKeylinesIsArray = VarGetType($keylines) == "Array"

    If $bKeylinesIsArray Then
        $vecKeylines = _VectorOfKeyLineCreate()

        $iArrKeylinesSize = UBound($keylines)
        For $i = 0 To $iArrKeylinesSize - 1
            _VectorOfKeyLinePush($vecKeylines, $keylines[$i])
        Next
    Else
        $vecKeylines = $keylines
    EndIf

    Local $bKeylinesDllType
    If VarGetType($keylines) == "DLLStruct" Then
        $bKeylinesDllType = "struct*"
    Else
        $bKeylinesDllType = "ptr"
    EndIf

    Local $bDescriptorsDllType
    If VarGetType($descriptors) == "DLLStruct" Then
        $bDescriptorsDllType = "struct*"
    Else
        $bDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorCompute", $bDescriptorDllType, $descriptor, $bImageDllType, $image, $bKeylinesDllType, $vecKeylines, $bDescriptorsDllType, $descriptors, "boolean", $returnFloatDescr), "cveLineDescriptorBinaryDescriptorCompute", @error)

    If $bKeylinesIsArray Then
        _VectorOfKeyLineRelease($vecKeylines)
    EndIf
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorCompute

Func _cveLineDescriptorBinaryDescriptorRelease($sharedPtr)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorRelease(cv::Ptr<cv::line_descriptor::BinaryDescriptor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorRelease", $bSharedPtrDllType, $sharedPtr), "cveLineDescriptorBinaryDescriptorRelease", @error)
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorRelease

Func _cveLineDescriptorLSDDetectorCreate($sharedPtr)
    ; CVAPI(cv::line_descriptor::LSDDetector*) cveLineDescriptorLSDDetectorCreate(cv::Ptr<cv::line_descriptor::LSDDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineDescriptorLSDDetectorCreate", $bSharedPtrDllType, $sharedPtr), "cveLineDescriptorLSDDetectorCreate", @error)
EndFunc   ;==>_cveLineDescriptorLSDDetectorCreate

Func _cveLineDescriptorLSDDetectorDetect($detector, $image, $keypoints, $scale, $numOctaves, $mask)
    ; CVAPI(void) cveLineDescriptorLSDDetectorDetect(cv::line_descriptor::LSDDetector* detector, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keypoints, int scale, int numOctaves, cv::Mat* mask);

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyLineCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyLinePush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorLSDDetectorDetect", $bDetectorDllType, $detector, $bImageDllType, $image, $bKeypointsDllType, $vecKeypoints, "int", $scale, "int", $numOctaves, $bMaskDllType, $mask), "cveLineDescriptorLSDDetectorDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyLineRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveLineDescriptorLSDDetectorDetect

Func _cveLineDescriptorLSDDetectorRelease($sharedPtr)
    ; CVAPI(void) cveLineDescriptorLSDDetectorRelease(cv::Ptr<cv::line_descriptor::LSDDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorLSDDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveLineDescriptorLSDDetectorRelease", @error)
EndFunc   ;==>_cveLineDescriptorLSDDetectorRelease