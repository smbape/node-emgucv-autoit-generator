#include-once
#include "..\..\CVEUtils.au3"

Func _cveWBDetectorCreate($sharedPtr)
    ; CVAPI(cv::xobjdetect::WBDetector*) cveWBDetectorCreate(cv::Ptr<cv::xobjdetect::WBDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWBDetectorCreate", $sSharedPtrDllType, $sharedPtr), "cveWBDetectorCreate", @error)
EndFunc   ;==>_cveWBDetectorCreate

Func _cveWBDetectorRead($detector, $node)
    ; CVAPI(void) cveWBDetectorRead(cv::xobjdetect::WBDetector* detector, cv::FileNode* node);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorRead", $sDetectorDllType, $detector, $sNodeDllType, $node), "cveWBDetectorRead", @error)
EndFunc   ;==>_cveWBDetectorRead

Func _cveWBDetectorWrite($detector, $fs)
    ; CVAPI(void) cveWBDetectorWrite(cv::xobjdetect::WBDetector* detector, cv::FileStorage* fs);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sFsDllType
    If IsDllStruct($fs) Then
        $sFsDllType = "struct*"
    Else
        $sFsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorWrite", $sDetectorDllType, $detector, $sFsDllType, $fs), "cveWBDetectorWrite", @error)
EndFunc   ;==>_cveWBDetectorWrite

Func _cveWBDetectorTrain($detector, $posSamples, $negImgs)
    ; CVAPI(void) cveWBDetectorTrain(cv::xobjdetect::WBDetector* detector, cv::String* posSamples, cv::String* negImgs);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $bPosSamplesIsString = VarGetType($posSamples) == "String"
    If $bPosSamplesIsString Then
        $posSamples = _cveStringCreateFromStr($posSamples)
    EndIf

    Local $sPosSamplesDllType
    If IsDllStruct($posSamples) Then
        $sPosSamplesDllType = "struct*"
    Else
        $sPosSamplesDllType = "ptr"
    EndIf

    Local $bNegImgsIsString = VarGetType($negImgs) == "String"
    If $bNegImgsIsString Then
        $negImgs = _cveStringCreateFromStr($negImgs)
    EndIf

    Local $sNegImgsDllType
    If IsDllStruct($negImgs) Then
        $sNegImgsDllType = "struct*"
    Else
        $sNegImgsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorTrain", $sDetectorDllType, $detector, $sPosSamplesDllType, $posSamples, $sNegImgsDllType, $negImgs), "cveWBDetectorTrain", @error)

    If $bNegImgsIsString Then
        _cveStringRelease($negImgs)
    EndIf

    If $bPosSamplesIsString Then
        _cveStringRelease($posSamples)
    EndIf
EndFunc   ;==>_cveWBDetectorTrain

Func _cveWBDetectorDetect($detector, $img, $bboxes, $confidences)
    ; CVAPI(void) cveWBDetectorDetect(cv::xobjdetect::WBDetector* detector, cv::Mat* img, std::vector<cv::Rect>* bboxes, std::vector<double>* confidences);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecBboxes, $iArrBboxesSize
    Local $bBboxesIsArray = VarGetType($bboxes) == "Array"

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    Local $sBboxesDllType
    If IsDllStruct($bboxes) Then
        $sBboxesDllType = "struct*"
    Else
        $sBboxesDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = VarGetType($confidences) == "Array"

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfDoubleCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfDoublePush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $sConfidencesDllType
    If IsDllStruct($confidences) Then
        $sConfidencesDllType = "struct*"
    Else
        $sConfidencesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorDetect", $sDetectorDllType, $detector, $sImgDllType, $img, $sBboxesDllType, $vecBboxes, $sConfidencesDllType, $vecConfidences), "cveWBDetectorDetect", @error)

    If $bConfidencesIsArray Then
        _VectorOfDoubleRelease($vecConfidences)
    EndIf

    If $bBboxesIsArray Then
        _VectorOfRectRelease($vecBboxes)
    EndIf
EndFunc   ;==>_cveWBDetectorDetect

Func _cveWBDetectorRelease($detector, $sharedPtr)
    ; CVAPI(void) cveWBDetectorRelease(cv::xobjdetect::WBDetector** detector, cv::Ptr<cv::xobjdetect::WBDetector>** sharedPtr);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorRelease", $sDetectorDllType, $detector, $sSharedPtrDllType, $sharedPtr), "cveWBDetectorRelease", @error)
EndFunc   ;==>_cveWBDetectorRelease