#include-once
#include "..\..\CVEUtils.au3"

Func _cveLineDescriptorBinaryDescriptorCreate(ByRef $sharedPtr)
    ; CVAPI(cv::line_descriptor::BinaryDescriptor*) cveLineDescriptorBinaryDescriptorCreate(cv::Ptr<cv::line_descriptor::BinaryDescriptor>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineDescriptorBinaryDescriptorCreate", "ptr*", $sharedPtr), "cveLineDescriptorBinaryDescriptorCreate", @error)
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorCreate

Func _cveLineDescriptorBinaryDescriptorDetect(ByRef $descriptor, ByRef $image, ByRef $keypoints, ByRef $mask)
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

Func _cveLineDescriptorBinaryDescriptorCompute(ByRef $descriptor, ByRef $image, ByRef $keylines, ByRef $descriptors, $returnFloatDescr)
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

Func _cveLineDescriptorBinaryDescriptorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveLineDescriptorBinaryDescriptorRelease(cv::Ptr<cv::line_descriptor::BinaryDescriptor>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorBinaryDescriptorRelease", "ptr*", $sharedPtr), "cveLineDescriptorBinaryDescriptorRelease", @error)
EndFunc   ;==>_cveLineDescriptorBinaryDescriptorRelease

Func _cveLineDescriptorLSDDetectorCreate(ByRef $sharedPtr)
    ; CVAPI(cv::line_descriptor::LSDDetector*) cveLineDescriptorLSDDetectorCreate(cv::Ptr<cv::line_descriptor::LSDDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineDescriptorLSDDetectorCreate", "ptr*", $sharedPtr), "cveLineDescriptorLSDDetectorCreate", @error)
EndFunc   ;==>_cveLineDescriptorLSDDetectorCreate

Func _cveLineDescriptorLSDDetectorDetect(ByRef $detector, ByRef $image, ByRef $keypoints, $scale, $numOctaves, ByRef $mask)
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

Func _cveLineDescriptorLSDDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveLineDescriptorLSDDetectorRelease(cv::Ptr<cv::line_descriptor::LSDDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineDescriptorLSDDetectorRelease", "ptr*", $sharedPtr), "cveLineDescriptorLSDDetectorRelease", @error)
EndFunc   ;==>_cveLineDescriptorLSDDetectorRelease