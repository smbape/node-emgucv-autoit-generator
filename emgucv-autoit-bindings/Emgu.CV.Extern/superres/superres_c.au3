#include-once
#include "..\..\CVEUtils.au3"

Func _cveSuperresCreateFrameSourceVideo($fileName, $useGpu, $sharedPtr)
    ; CVAPI(cv::superres::FrameSource*) cveSuperresCreateFrameSourceVideo(cv::String* fileName, bool useGpu, cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $bFileNameIsString = IsString($fileName)
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperresCreateFrameSourceVideo", $sFileNameDllType, $fileName, "boolean", $useGpu, $sSharedPtrDllType, $sharedPtr), "cveSuperresCreateFrameSourceVideo", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveSuperresCreateFrameSourceVideo

Func _cveSuperresCreateFrameSourceCamera($deviceId, $sharedPtr)
    ; CVAPI(cv::superres::FrameSource*) cveSuperresCreateFrameSourceCamera(int deviceId, cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperresCreateFrameSourceCamera", "int", $deviceId, $sSharedPtrDllType, $sharedPtr), "cveSuperresCreateFrameSourceCamera", @error)
EndFunc   ;==>_cveSuperresCreateFrameSourceCamera

Func _cveSuperresFrameSourceNextFrame($frameSource, $frame)
    ; CVAPI(void) cveSuperresFrameSourceNextFrame(cv::superres::FrameSource* frameSource, cv::_OutputArray* frame);

    Local $sFrameSourceDllType
    If IsDllStruct($frameSource) Then
        $sFrameSourceDllType = "struct*"
    Else
        $sFrameSourceDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperresFrameSourceNextFrame", $sFrameSourceDllType, $frameSource, $sFrameDllType, $frame), "cveSuperresFrameSourceNextFrame", @error)
EndFunc   ;==>_cveSuperresFrameSourceNextFrame

Func _cveSuperresFrameSourceNextFrameTyped($frameSource, $typeOfFrame, $frame)

    Local $oArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $oArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $oArrFrame = Call("_cveOutputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $oArrFrame = Call("_cveOutputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveSuperresFrameSourceNextFrame($frameSource, $oArrFrame)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveOutputArrayRelease($oArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperresFrameSourceNextFrameTyped

Func _cveSuperresFrameSourceNextFrameMat($frameSource, $frame)
    ; cveSuperresFrameSourceNextFrame using cv::Mat instead of _*Array
    _cveSuperresFrameSourceNextFrameTyped($frameSource, "Mat", $frame)
EndFunc   ;==>_cveSuperresFrameSourceNextFrameMat

Func _cveSuperresFrameSourceRelease($sharedPtr)
    ; CVAPI(void) cveSuperresFrameSourceRelease(cv::Ptr<cv::superres::FrameSource>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperresFrameSourceRelease", $sSharedPtrDllType, $sharedPtr), "cveSuperresFrameSourceRelease", @error)
EndFunc   ;==>_cveSuperresFrameSourceRelease

Func _cveSuperResolutionCreate($type, $frameSource, $frameSourceOut, $sharedPtr)
    ; CVAPI(cv::superres::SuperResolution*) cveSuperResolutionCreate(int type, cv::superres::FrameSource* frameSource, cv::superres::FrameSource** frameSourceOut, cv::Ptr<cv::superres::SuperResolution>** sharedPtr);

    Local $sFrameSourceDllType
    If IsDllStruct($frameSource) Then
        $sFrameSourceDllType = "struct*"
    Else
        $sFrameSourceDllType = "ptr"
    EndIf

    Local $sFrameSourceOutDllType
    If IsDllStruct($frameSourceOut) Then
        $sFrameSourceOutDllType = "struct*"
    ElseIf $frameSourceOut == Null Then
        $sFrameSourceOutDllType = "ptr"
    Else
        $sFrameSourceOutDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperResolutionCreate", "int", $type, $sFrameSourceDllType, $frameSource, $sFrameSourceOutDllType, $frameSourceOut, $sSharedPtrDllType, $sharedPtr), "cveSuperResolutionCreate", @error)
EndFunc   ;==>_cveSuperResolutionCreate

Func _cveSuperResolutionRelease($sharedPtr)
    ; CVAPI(void) cveSuperResolutionRelease(cv::Ptr<cv::superres::SuperResolution>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperResolutionRelease", $sSharedPtrDllType, $sharedPtr), "cveSuperResolutionRelease", @error)
EndFunc   ;==>_cveSuperResolutionRelease