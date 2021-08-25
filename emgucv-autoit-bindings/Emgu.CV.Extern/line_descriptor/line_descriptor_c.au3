#include-once
#include "..\..\CVEUtils.au3"

Func _cveLineDescriptorBinaryDescriptorCreate($sharedPtr)
    ; CVAPI(cv::line_descriptor::BinaryDescriptor*) cveLineDescriptorBinaryDescriptorCreate(cv::Ptr<cv::line_descriptor::BinaryDescriptor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineDescriptorBinaryDescriptorCreate", $sSharedPtrDllType, $sharedPtr), "cveLineDescriptorBinaryDescriptorCreate", @error)
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorCreate

Func _cveLineDescriptorBinaryDescriptorDetect($descriptor, $image, $keypoints, $mask)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorDetect(cv::line_descriptor::BinaryDescriptor* descriptor, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keypoints, cv::Mat* mask);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyLineCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyLinePush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorDetect", $sDescriptorDllType, $descriptor, $sImageDllType, $image, $sKeypointsDllType, $vecKeypoints, $sMaskDllType, $mask), "cveLineDescriptorBinaryDescriptorDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyLineRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorDetect

Func _cveLineDescriptorBinaryDescriptorCompute($descriptor, $image, $keylines, $descriptors, $returnFloatDescr)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorCompute(cv::line_descriptor::BinaryDescriptor* descriptor, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keylines, cv::Mat* descriptors, bool returnFloatDescr);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeylines, $iArrKeylinesSize
    Local $bKeylinesIsArray = IsArray($keylines)

    If $bKeylinesIsArray Then
        $vecKeylines = _VectorOfKeyLineCreate()

        $iArrKeylinesSize = UBound($keylines)
        For $i = 0 To $iArrKeylinesSize - 1
            _VectorOfKeyLinePush($vecKeylines, $keylines[$i])
        Next
    Else
        $vecKeylines = $keylines
    EndIf

    Local $sKeylinesDllType
    If IsDllStruct($keylines) Then
        $sKeylinesDllType = "struct*"
    Else
        $sKeylinesDllType = "ptr"
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorCompute", $sDescriptorDllType, $descriptor, $sImageDllType, $image, $sKeylinesDllType, $vecKeylines, $sDescriptorsDllType, $descriptors, "boolean", $returnFloatDescr), "cveLineDescriptorBinaryDescriptorCompute", @error)

    If $bKeylinesIsArray Then
        _VectorOfKeyLineRelease($vecKeylines)
    EndIf
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorCompute

Func _cveLineDescriptorBinaryDescriptorRelease($sharedPtr)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorRelease(cv::Ptr<cv::line_descriptor::BinaryDescriptor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorRelease", $sSharedPtrDllType, $sharedPtr), "cveLineDescriptorBinaryDescriptorRelease", @error)
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorRelease

Func _cveLineDescriptorLSDDetectorCreate($sharedPtr)
    ; CVAPI(cv::line_descriptor::LSDDetector*) cveLineDescriptorLSDDetectorCreate(cv::Ptr<cv::line_descriptor::LSDDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineDescriptorLSDDetectorCreate", $sSharedPtrDllType, $sharedPtr), "cveLineDescriptorLSDDetectorCreate", @error)
EndFunc   ;==>_cveLineDescriptorLSDDetectorCreate

Func _cveLineDescriptorLSDDetectorDetect($detector, $image, $keypoints, $scale, $numOctaves, $mask)
    ; CVAPI(void) cveLineDescriptorLSDDetectorDetect(cv::line_descriptor::LSDDetector* detector, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keypoints, int scale, int numOctaves, cv::Mat* mask);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyLineCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyLinePush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorLSDDetectorDetect", $sDetectorDllType, $detector, $sImageDllType, $image, $sKeypointsDllType, $vecKeypoints, "int", $scale, "int", $numOctaves, $sMaskDllType, $mask), "cveLineDescriptorLSDDetectorDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyLineRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveLineDescriptorLSDDetectorDetect

Func _cveLineDescriptorLSDDetectorRelease($sharedPtr)
    ; CVAPI(void) cveLineDescriptorLSDDetectorRelease(cv::Ptr<cv::line_descriptor::LSDDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorLSDDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveLineDescriptorLSDDetectorRelease", @error)
EndFunc   ;==>_cveLineDescriptorLSDDetectorRelease