#include-once
#include "..\..\CVEUtils.au3"

Func _cveDPMDetectorCreate(ByRef $filenames, ByRef $classNames, ByRef $sharedPtr)
    ; CVAPI(DPMDetector*) cveDPMDetectorCreate(std::vector<cv::String>* filenames, std::vector<cv::String>* classNames, cv::Ptr<cv::dpm::DPMDetector>** sharedPtr);

    Local $vecFilenames, $iArrFilenamesSize
    Local $bFilenamesIsArray = VarGetType($filenames) == "Array"

    If $bFilenamesIsArray Then
        $vecFilenames = _VectorOfCvStringCreate()

        $iArrFilenamesSize = UBound($filenames)
        For $i = 0 To $iArrFilenamesSize - 1
            _VectorOfCvStringPush($vecFilenames, $filenames[$i])
        Next
    Else
        $vecFilenames = $filenames
    EndIf

    Local $vecClassNames, $iArrClassNamesSize
    Local $bClassNamesIsArray = VarGetType($classNames) == "Array"

    If $bClassNamesIsArray Then
        $vecClassNames = _VectorOfCvStringCreate()

        $iArrClassNamesSize = UBound($classNames)
        For $i = 0 To $iArrClassNamesSize - 1
            _VectorOfCvStringPush($vecClassNames, $classNames[$i])
        Next
    Else
        $vecClassNames = $classNames
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDPMDetectorCreate", "ptr", $vecFilenames, "ptr", $vecClassNames, "ptr*", $sharedPtr), "cveDPMDetectorCreate", @error)

    If $bClassNamesIsArray Then
        _VectorOfCvStringRelease($vecClassNames)
    EndIf

    If $bFilenamesIsArray Then
        _VectorOfCvStringRelease($vecFilenames)
    EndIf

    Return $retval
EndFunc   ;==>_cveDPMDetectorCreate

Func _cveDPMDetectorDetect(ByRef $dpm, ByRef $image, ByRef $rects, ByRef $scores, ByRef $classIds)
    ; CVAPI(void) cveDPMDetectorDetect(DPMDetector* dpm, cv::Mat* image, std::vector<CvRect>* rects, std::vector<float>* scores, std::vector<int>* classIds);

    Local $vecScores, $iArrScoresSize
    Local $bScoresIsArray = VarGetType($scores) == "Array"

    If $bScoresIsArray Then
        $vecScores = _VectorOfFloatCreate()

        $iArrScoresSize = UBound($scores)
        For $i = 0 To $iArrScoresSize - 1
            _VectorOfFloatPush($vecScores, $scores[$i])
        Next
    Else
        $vecScores = $scores
    EndIf

    Local $vecClassIds, $iArrClassIdsSize
    Local $bClassIdsIsArray = VarGetType($classIds) == "Array"

    If $bClassIdsIsArray Then
        $vecClassIds = _VectorOfIntCreate()

        $iArrClassIdsSize = UBound($classIds)
        For $i = 0 To $iArrClassIdsSize - 1
            _VectorOfIntPush($vecClassIds, $classIds[$i])
        Next
    Else
        $vecClassIds = $classIds
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorDetect", "struct*", $dpm, "ptr", $image, "ptr", $rects, "ptr", $vecScores, "ptr", $vecClassIds), "cveDPMDetectorDetect", @error)

    If $bClassIdsIsArray Then
        _VectorOfIntRelease($vecClassIds)
    EndIf

    If $bScoresIsArray Then
        _VectorOfFloatRelease($vecScores)
    EndIf
EndFunc   ;==>_cveDPMDetectorDetect

Func _cveDPMDetectorGetClassCount(ByRef $dpm)
    ; CVAPI(size_t) cveDPMDetectorGetClassCount(DPMDetector* dpm);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveDPMDetectorGetClassCount", "struct*", $dpm), "cveDPMDetectorGetClassCount", @error)
EndFunc   ;==>_cveDPMDetectorGetClassCount

Func _cveDPMDetectorGetClassNames(ByRef $dpm, ByRef $names)
    ; CVAPI(void) cveDPMDetectorGetClassNames(DPMDetector* dpm, std::vector<cv::String>* names);

    Local $vecNames, $iArrNamesSize
    Local $bNamesIsArray = VarGetType($names) == "Array"

    If $bNamesIsArray Then
        $vecNames = _VectorOfCvStringCreate()

        $iArrNamesSize = UBound($names)
        For $i = 0 To $iArrNamesSize - 1
            _VectorOfCvStringPush($vecNames, $names[$i])
        Next
    Else
        $vecNames = $names
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorGetClassNames", "struct*", $dpm, "ptr", $vecNames), "cveDPMDetectorGetClassNames", @error)

    If $bNamesIsArray Then
        _VectorOfCvStringRelease($vecNames)
    EndIf
EndFunc   ;==>_cveDPMDetectorGetClassNames

Func _cveDPMDetectorIsEmpty(ByRef $dpm)
    ; CVAPI(bool) cveDPMDetectorIsEmpty(DPMDetector* dpm);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDPMDetectorIsEmpty", "struct*", $dpm), "cveDPMDetectorIsEmpty", @error)
EndFunc   ;==>_cveDPMDetectorIsEmpty

Func _cveDPMDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveDPMDetectorRelease(cv::Ptr<cv::dpm::DPMDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorRelease", "ptr*", $sharedPtr), "cveDPMDetectorRelease", @error)
EndFunc   ;==>_cveDPMDetectorRelease