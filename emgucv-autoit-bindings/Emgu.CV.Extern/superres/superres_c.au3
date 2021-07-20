#include-once
#include "..\..\CVEUtils.au3"

Func _cveSuperresCreateFrameSourceVideo($fileName, $useGpu, $sharedPtr)
    ; CVAPI(cv::superres::FrameSource*) cveSuperresCreateFrameSourceVideo(cv::String* fileName, bool useGpu, cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperresCreateFrameSourceVideo", "ptr", $fileName, "boolean", $useGpu, $bSharedPtrDllType, $sharedPtr), "cveSuperresCreateFrameSourceVideo", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveSuperresCreateFrameSourceVideo

Func _cveSuperresCreateFrameSourceCamera($deviceId, $sharedPtr)
    ; CVAPI(cv::superres::FrameSource*) cveSuperresCreateFrameSourceCamera(int deviceId, cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperresCreateFrameSourceCamera", "int", $deviceId, $bSharedPtrDllType, $sharedPtr), "cveSuperresCreateFrameSourceCamera", @error)
EndFunc   ;==>_cveSuperresCreateFrameSourceCamera

Func _cveSuperresFrameSourceNextFrame($frameSource, $frame)
    ; CVAPI(void) cveSuperresFrameSourceNextFrame(cv::superres::FrameSource* frameSource, cv::_OutputArray* frame);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperresFrameSourceNextFrame", "ptr", $frameSource, "ptr", $frame), "cveSuperresFrameSourceNextFrame", @error)
EndFunc   ;==>_cveSuperresFrameSourceNextFrame

Func _cveSuperresFrameSourceNextFrameMat($frameSource, $matFrame)
    ; cveSuperresFrameSourceNextFrame using cv::Mat instead of _*Array

    Local $oArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $oArrFrame = _cveOutputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $oArrFrame = _cveOutputArrayFromMat($matFrame)
    EndIf

    _cveSuperresFrameSourceNextFrame($frameSource, $oArrFrame)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveOutputArrayRelease($oArrFrame)
EndFunc   ;==>_cveSuperresFrameSourceNextFrameMat

Func _cveSuperresFrameSourceRelease($sharedPtr)
    ; CVAPI(void) cveSuperresFrameSourceRelease(cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperresFrameSourceRelease", $bSharedPtrDllType, $sharedPtr), "cveSuperresFrameSourceRelease", @error)
EndFunc   ;==>_cveSuperresFrameSourceRelease

Func _cveSuperResolutionCreate($type, $frameSource, $frameSourceOut, $sharedPtr)
    ; CVAPI(cv::superres::SuperResolution*) cveSuperResolutionCreate(int type, cv::superres::FrameSource* frameSource, cv::superres::FrameSource** frameSourceOut, cv::Ptr<cv::superres::SuperResolution>** sharedPtr);

    Local $bFrameSourceOutDllType
    If VarGetType($frameSourceOut) == "DLLStruct" Then
        $bFrameSourceOutDllType = "struct*"
    Else
        $bFrameSourceOutDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperResolutionCreate", "int", $type, "ptr", $frameSource, $bFrameSourceOutDllType, $frameSourceOut, $bSharedPtrDllType, $sharedPtr), "cveSuperResolutionCreate", @error)
EndFunc   ;==>_cveSuperResolutionCreate

Func _cveSuperResolutionRelease($sharedPtr)
    ; CVAPI(void) cveSuperResolutionRelease(cv::Ptr<cv::superres::SuperResolution>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperResolutionRelease", $bSharedPtrDllType, $sharedPtr), "cveSuperResolutionRelease", @error)
EndFunc   ;==>_cveSuperResolutionRelease