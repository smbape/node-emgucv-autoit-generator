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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorDetect", "ptr", $descriptor, "ptr", $image, "ptr", $vecKeypoints, "ptr", $mask), "cveLineDescriptorBinaryDescriptorDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyLineRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorDetect

Func _cveLineDescriptorBinaryDescriptorCompute($descriptor, $image, $keylines, $descriptors, $returnFloatDescr)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorCompute(cv::line_descriptor::BinaryDescriptor* descriptor, cv::Mat* image, std::vector<cv::line_descriptor::KeyLine>* keylines, cv::Mat* descriptors, bool returnFloatDescr);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorCompute", "ptr", $descriptor, "ptr", $image, "ptr", $vecKeylines, "ptr", $descriptors, "boolean", $returnFloatDescr), "cveLineDescriptorBinaryDescriptorCompute", @error)

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorLSDDetectorDetect", "ptr", $detector, "ptr", $image, "ptr", $vecKeypoints, "int", $scale, "int", $numOctaves, "ptr", $mask), "cveLineDescriptorLSDDetectorDetect", @error)

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