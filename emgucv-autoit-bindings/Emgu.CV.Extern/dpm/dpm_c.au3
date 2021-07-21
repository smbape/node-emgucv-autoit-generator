#include-once
#include "..\..\CVEUtils.au3"

Func _cveDPMDetectorCreate($filenames, $classNames, $sharedPtr)
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

    Local $bFilenamesDllType
    If VarGetType($filenames) == "DLLStruct" Then
        $bFilenamesDllType = "struct*"
    Else
        $bFilenamesDllType = "ptr"
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

    Local $bClassNamesDllType
    If VarGetType($classNames) == "DLLStruct" Then
        $bClassNamesDllType = "struct*"
    Else
        $bClassNamesDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDPMDetectorCreate", $bFilenamesDllType, $vecFilenames, $bClassNamesDllType, $vecClassNames, $bSharedPtrDllType, $sharedPtr), "cveDPMDetectorCreate", @error)

    If $bClassNamesIsArray Then
        _VectorOfCvStringRelease($vecClassNames)
    EndIf

    If $bFilenamesIsArray Then
        _VectorOfCvStringRelease($vecFilenames)
    EndIf

    Return $retval
EndFunc   ;==>_cveDPMDetectorCreate

Func _cveDPMDetectorDetect($dpm, $image, $rects, $scores, $classIds)
    ; CVAPI(void) cveDPMDetectorDetect(DPMDetector* dpm, cv::Mat* image, std::vector<CvRect>* rects, std::vector<float>* scores, std::vector<int>* classIds);

    Local $bDpmDllType
    If VarGetType($dpm) == "DLLStruct" Then
        $bDpmDllType = "struct*"
    Else
        $bDpmDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bRectsDllType
    If VarGetType($rects) == "DLLStruct" Then
        $bRectsDllType = "struct*"
    Else
        $bRectsDllType = "ptr"
    EndIf

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

    Local $bScoresDllType
    If VarGetType($scores) == "DLLStruct" Then
        $bScoresDllType = "struct*"
    Else
        $bScoresDllType = "ptr"
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

    Local $bClassIdsDllType
    If VarGetType($classIds) == "DLLStruct" Then
        $bClassIdsDllType = "struct*"
    Else
        $bClassIdsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorDetect", $bDpmDllType, $dpm, $bImageDllType, $image, $bRectsDllType, $rects, $bScoresDllType, $vecScores, $bClassIdsDllType, $vecClassIds), "cveDPMDetectorDetect", @error)

    If $bClassIdsIsArray Then
        _VectorOfIntRelease($vecClassIds)
    EndIf

    If $bScoresIsArray Then
        _VectorOfFloatRelease($vecScores)
    EndIf
EndFunc   ;==>_cveDPMDetectorDetect

Func _cveDPMDetectorGetClassCount($dpm)
    ; CVAPI(size_t) cveDPMDetectorGetClassCount(DPMDetector* dpm);

    Local $bDpmDllType
    If VarGetType($dpm) == "DLLStruct" Then
        $bDpmDllType = "struct*"
    Else
        $bDpmDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveDPMDetectorGetClassCount", $bDpmDllType, $dpm), "cveDPMDetectorGetClassCount", @error)
EndFunc   ;==>_cveDPMDetectorGetClassCount

Func _cveDPMDetectorGetClassNames($dpm, $names)
    ; CVAPI(void) cveDPMDetectorGetClassNames(DPMDetector* dpm, std::vector<cv::String>* names);

    Local $bDpmDllType
    If VarGetType($dpm) == "DLLStruct" Then
        $bDpmDllType = "struct*"
    Else
        $bDpmDllType = "ptr"
    EndIf

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

    Local $bNamesDllType
    If VarGetType($names) == "DLLStruct" Then
        $bNamesDllType = "struct*"
    Else
        $bNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorGetClassNames", $bDpmDllType, $dpm, $bNamesDllType, $vecNames), "cveDPMDetectorGetClassNames", @error)

    If $bNamesIsArray Then
        _VectorOfCvStringRelease($vecNames)
    EndIf
EndFunc   ;==>_cveDPMDetectorGetClassNames

Func _cveDPMDetectorIsEmpty($dpm)
    ; CVAPI(bool) cveDPMDetectorIsEmpty(DPMDetector* dpm);

    Local $bDpmDllType
    If VarGetType($dpm) == "DLLStruct" Then
        $bDpmDllType = "struct*"
    Else
        $bDpmDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDPMDetectorIsEmpty", $bDpmDllType, $dpm), "cveDPMDetectorIsEmpty", @error)
EndFunc   ;==>_cveDPMDetectorIsEmpty

Func _cveDPMDetectorRelease($sharedPtr)
    ; CVAPI(void) cveDPMDetectorRelease(cv::Ptr<cv::dpm::DPMDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveDPMDetectorRelease", @error)
EndFunc   ;==>_cveDPMDetectorRelease