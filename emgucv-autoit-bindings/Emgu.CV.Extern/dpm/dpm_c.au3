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

    Local $sFilenamesDllType
    If IsDllStruct($filenames) Then
        $sFilenamesDllType = "struct*"
    Else
        $sFilenamesDllType = "ptr"
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

    Local $sClassNamesDllType
    If IsDllStruct($classNames) Then
        $sClassNamesDllType = "struct*"
    Else
        $sClassNamesDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDPMDetectorCreate", $sFilenamesDllType, $vecFilenames, $sClassNamesDllType, $vecClassNames, $sSharedPtrDllType, $sharedPtr), "cveDPMDetectorCreate", @error)

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

    Local $sDpmDllType
    If IsDllStruct($dpm) Then
        $sDpmDllType = "struct*"
    Else
        $sDpmDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sRectsDllType
    If IsDllStruct($rects) Then
        $sRectsDllType = "struct*"
    Else
        $sRectsDllType = "ptr"
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

    Local $sScoresDllType
    If IsDllStruct($scores) Then
        $sScoresDllType = "struct*"
    Else
        $sScoresDllType = "ptr"
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

    Local $sClassIdsDllType
    If IsDllStruct($classIds) Then
        $sClassIdsDllType = "struct*"
    Else
        $sClassIdsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorDetect", $sDpmDllType, $dpm, $sImageDllType, $image, $sRectsDllType, $rects, $sScoresDllType, $vecScores, $sClassIdsDllType, $vecClassIds), "cveDPMDetectorDetect", @error)

    If $bClassIdsIsArray Then
        _VectorOfIntRelease($vecClassIds)
    EndIf

    If $bScoresIsArray Then
        _VectorOfFloatRelease($vecScores)
    EndIf
EndFunc   ;==>_cveDPMDetectorDetect

Func _cveDPMDetectorGetClassCount($dpm)
    ; CVAPI(size_t) cveDPMDetectorGetClassCount(DPMDetector* dpm);

    Local $sDpmDllType
    If IsDllStruct($dpm) Then
        $sDpmDllType = "struct*"
    Else
        $sDpmDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveDPMDetectorGetClassCount", $sDpmDllType, $dpm), "cveDPMDetectorGetClassCount", @error)
EndFunc   ;==>_cveDPMDetectorGetClassCount

Func _cveDPMDetectorGetClassNames($dpm, $names)
    ; CVAPI(void) cveDPMDetectorGetClassNames(DPMDetector* dpm, std::vector<cv::String>* names);

    Local $sDpmDllType
    If IsDllStruct($dpm) Then
        $sDpmDllType = "struct*"
    Else
        $sDpmDllType = "ptr"
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

    Local $sNamesDllType
    If IsDllStruct($names) Then
        $sNamesDllType = "struct*"
    Else
        $sNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorGetClassNames", $sDpmDllType, $dpm, $sNamesDllType, $vecNames), "cveDPMDetectorGetClassNames", @error)

    If $bNamesIsArray Then
        _VectorOfCvStringRelease($vecNames)
    EndIf
EndFunc   ;==>_cveDPMDetectorGetClassNames

Func _cveDPMDetectorIsEmpty($dpm)
    ; CVAPI(bool) cveDPMDetectorIsEmpty(DPMDetector* dpm);

    Local $sDpmDllType
    If IsDllStruct($dpm) Then
        $sDpmDllType = "struct*"
    Else
        $sDpmDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDPMDetectorIsEmpty", $sDpmDllType, $dpm), "cveDPMDetectorIsEmpty", @error)
EndFunc   ;==>_cveDPMDetectorIsEmpty

Func _cveDPMDetectorRelease($sharedPtr)
    ; CVAPI(void) cveDPMDetectorRelease(cv::Ptr<cv::dpm::DPMDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDPMDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveDPMDetectorRelease", @error)
EndFunc   ;==>_cveDPMDetectorRelease