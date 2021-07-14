#include-once
#include "..\..\CVEUtils.au3"

Func _cveSuperresCreateFrameSourceVideo($fileName, $useGpu, ByRef $sharedPtr)
    ; CVAPI(cv::superres::FrameSource*) cveSuperresCreateFrameSourceVideo(cv::String* fileName, bool useGpu, cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperresCreateFrameSourceVideo", "ptr", $fileName, "boolean", $useGpu, "ptr*", $sharedPtr), "cveSuperresCreateFrameSourceVideo", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveSuperresCreateFrameSourceVideo

Func _cveSuperresCreateFrameSourceCamera($deviceId, ByRef $sharedPtr)
    ; CVAPI(cv::superres::FrameSource*) cveSuperresCreateFrameSourceCamera(int deviceId, cv::Ptr<cv::superres::FrameSource>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperresCreateFrameSourceCamera", "int", $deviceId, "ptr*", $sharedPtr), "cveSuperresCreateFrameSourceCamera", @error)
EndFunc   ;==>_cveSuperresCreateFrameSourceCamera

Func _cveSuperresFrameSourceNextFrame(ByRef $frameSource, ByRef $frame)
    ; CVAPI(void) cveSuperresFrameSourceNextFrame(cv::superres::FrameSource* frameSource, cv::_OutputArray* frame);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperresFrameSourceNextFrame", "ptr", $frameSource, "ptr", $frame), "cveSuperresFrameSourceNextFrame", @error)
EndFunc   ;==>_cveSuperresFrameSourceNextFrame

Func _cveSuperresFrameSourceNextFrameMat(ByRef $frameSource, ByRef $matFrame)
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

Func _cveSuperresFrameSourceRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveSuperresFrameSourceRelease(cv::Ptr<cv::superres::FrameSource>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperresFrameSourceRelease", "ptr*", $sharedPtr), "cveSuperresFrameSourceRelease", @error)
EndFunc   ;==>_cveSuperresFrameSourceRelease

Func _cveSuperResolutionCreate($type, ByRef $frameSource, ByRef $frameSourceOut, ByRef $sharedPtr)
    ; CVAPI(cv::superres::SuperResolution*) cveSuperResolutionCreate(int type, cv::superres::FrameSource* frameSource, cv::superres::FrameSource** frameSourceOut, cv::Ptr<cv::superres::SuperResolution>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperResolutionCreate", "int", $type, "ptr", $frameSource, "ptr*", $frameSourceOut, "ptr*", $sharedPtr), "cveSuperResolutionCreate", @error)
EndFunc   ;==>_cveSuperResolutionCreate

Func _cveSuperResolutionRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveSuperResolutionRelease(cv::Ptr<cv::superres::SuperResolution>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperResolutionRelease", "ptr*", $sharedPtr), "cveSuperResolutionRelease", @error)
EndFunc   ;==>_cveSuperResolutionRelease