#include-once
#include "..\..\CVEUtils.au3"

Func _cveWBDetectorCreate($sharedPtr)
    ; CVAPI(cv::xobjdetect::WBDetector*) cveWBDetectorCreate(cv::Ptr<cv::xobjdetect::WBDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWBDetectorCreate", $bSharedPtrDllType, $sharedPtr), "cveWBDetectorCreate", @error)
EndFunc   ;==>_cveWBDetectorCreate

Func _cveWBDetectorRead($detector, $node)
    ; CVAPI(void) cveWBDetectorRead(cv::xobjdetect::WBDetector* detector, cv::FileNode* node);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorRead", "ptr", $detector, "ptr", $node), "cveWBDetectorRead", @error)
EndFunc   ;==>_cveWBDetectorRead

Func _cveWBDetectorWrite($detector, $fs)
    ; CVAPI(void) cveWBDetectorWrite(cv::xobjdetect::WBDetector* detector, cv::FileStorage* fs);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorWrite", "ptr", $detector, "ptr", $fs), "cveWBDetectorWrite", @error)
EndFunc   ;==>_cveWBDetectorWrite

Func _cveWBDetectorTrain($detector, $posSamples, $negImgs)
    ; CVAPI(void) cveWBDetectorTrain(cv::xobjdetect::WBDetector* detector, cv::String* posSamples, cv::String* negImgs);

    Local $bPosSamplesIsString = VarGetType($posSamples) == "String"
    If $bPosSamplesIsString Then
        $posSamples = _cveStringCreateFromStr($posSamples)
    EndIf

    Local $bNegImgsIsString = VarGetType($negImgs) == "String"
    If $bNegImgsIsString Then
        $negImgs = _cveStringCreateFromStr($negImgs)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorTrain", "ptr", $detector, "ptr", $posSamples, "ptr", $negImgs), "cveWBDetectorTrain", @error)

    If $bNegImgsIsString Then
        _cveStringRelease($negImgs)
    EndIf

    If $bPosSamplesIsString Then
        _cveStringRelease($posSamples)
    EndIf
EndFunc   ;==>_cveWBDetectorTrain

Func _cveWBDetectorDetect($detector, $img, $bboxes, $confidences)
    ; CVAPI(void) cveWBDetectorDetect(cv::xobjdetect::WBDetector* detector, cv::Mat* img, std::vector<cv::Rect>* bboxes, std::vector<double>* confidences);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorDetect", "ptr", $detector, "ptr", $img, "ptr", $vecBboxes, "ptr", $vecConfidences), "cveWBDetectorDetect", @error)

    If $bConfidencesIsArray Then
        _VectorOfDoubleRelease($vecConfidences)
    EndIf

    If $bBboxesIsArray Then
        _VectorOfRectRelease($vecBboxes)
    EndIf
EndFunc   ;==>_cveWBDetectorDetect

Func _cveWBDetectorRelease($detector, $sharedPtr)
    ; CVAPI(void) cveWBDetectorRelease(cv::xobjdetect::WBDetector** detector, cv::Ptr<cv::xobjdetect::WBDetector>** sharedPtr);

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWBDetectorRelease", $bDetectorDllType, $detector, $bSharedPtrDllType, $sharedPtr), "cveWBDetectorRelease", @error)
EndFunc   ;==>_cveWBDetectorRelease