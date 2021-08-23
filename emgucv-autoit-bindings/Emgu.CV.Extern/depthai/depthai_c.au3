#include-once
#include "..\..\CVEUtils.au3"

Func _depthaiDeviceCreate($usb_device, $usb2_mode)
    ; CVAPI(Device*) depthaiDeviceCreate(cv::String* usb_device, bool usb2_mode);

    Local $bUsb_deviceIsString = VarGetType($usb_device) == "String"
    If $bUsb_deviceIsString Then
        $usb_device = _cveStringCreateFromStr($usb_device)
    EndIf

    Local $sUsb_deviceDllType
    If IsDllStruct($usb_device) Then
        $sUsb_deviceDllType = "struct*"
    Else
        $sUsb_deviceDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiDeviceCreate", $sUsb_deviceDllType, $usb_device, "boolean", $usb2_mode), "depthaiDeviceCreate", @error)

    If $bUsb_deviceIsString Then
        _cveStringRelease($usb_device)
    EndIf

    Return $retval
EndFunc   ;==>_depthaiDeviceCreate

Func _depthaiDeviceRelease($usb_device)
    ; CVAPI(void) depthaiDeviceRelease(Device** usb_device);

    Local $sUsb_deviceDllType
    If IsDllStruct($usb_device) Then
        $sUsb_deviceDllType = "struct*"
    ElseIf $usb_device == Null Then
        $sUsb_deviceDllType = "ptr"
    Else
        $sUsb_deviceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiDeviceRelease", $sUsb_deviceDllType, $usb_device), "depthaiDeviceRelease", @error)
EndFunc   ;==>_depthaiDeviceRelease

Func _depthaiDeviceGetAvailableStreams($usb_device, $availableStreams)
    ; CVAPI(void) depthaiDeviceGetAvailableStreams(Device* usb_device, std::vector<cv::String>* availableStreams);

    Local $sUsb_deviceDllType
    If IsDllStruct($usb_device) Then
        $sUsb_deviceDllType = "struct*"
    Else
        $sUsb_deviceDllType = "ptr"
    EndIf

    Local $vecAvailableStreams, $iArrAvailableStreamsSize
    Local $bAvailableStreamsIsArray = VarGetType($availableStreams) == "Array"

    If $bAvailableStreamsIsArray Then
        $vecAvailableStreams = _VectorOfCvStringCreate()

        $iArrAvailableStreamsSize = UBound($availableStreams)
        For $i = 0 To $iArrAvailableStreamsSize - 1
            _VectorOfCvStringPush($vecAvailableStreams, $availableStreams[$i])
        Next
    Else
        $vecAvailableStreams = $availableStreams
    EndIf

    Local $sAvailableStreamsDllType
    If IsDllStruct($availableStreams) Then
        $sAvailableStreamsDllType = "struct*"
    Else
        $sAvailableStreamsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiDeviceGetAvailableStreams", $sUsb_deviceDllType, $usb_device, $sAvailableStreamsDllType, $vecAvailableStreams), "depthaiDeviceGetAvailableStreams", @error)

    If $bAvailableStreamsIsArray Then
        _VectorOfCvStringRelease($vecAvailableStreams)
    EndIf
EndFunc   ;==>_depthaiDeviceGetAvailableStreams

Func _depthaiDeviceCreatePipeline($usb_device, $config_json_str, $hostedPipelinePtr)
    ; CVAPI(CNNHostPipeline*) depthaiDeviceCreatePipeline(Device* usb_device, cv::String* config_json_str, std::shared_ptr<CNNHostPipeline>** hostedPipelinePtr);

    Local $sUsb_deviceDllType
    If IsDllStruct($usb_device) Then
        $sUsb_deviceDllType = "struct*"
    Else
        $sUsb_deviceDllType = "ptr"
    EndIf

    Local $bConfig_json_strIsString = VarGetType($config_json_str) == "String"
    If $bConfig_json_strIsString Then
        $config_json_str = _cveStringCreateFromStr($config_json_str)
    EndIf

    Local $sConfig_json_strDllType
    If IsDllStruct($config_json_str) Then
        $sConfig_json_strDllType = "struct*"
    Else
        $sConfig_json_strDllType = "ptr"
    EndIf

    Local $sHostedPipelinePtrDllType
    If IsDllStruct($hostedPipelinePtr) Then
        $sHostedPipelinePtrDllType = "struct*"
    ElseIf $hostedPipelinePtr == Null Then
        $sHostedPipelinePtrDllType = "ptr"
    Else
        $sHostedPipelinePtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiDeviceCreatePipeline", $sUsb_deviceDllType, $usb_device, $sConfig_json_strDllType, $config_json_str, $sHostedPipelinePtrDllType, $hostedPipelinePtr), "depthaiDeviceCreatePipeline", @error)

    If $bConfig_json_strIsString Then
        _cveStringRelease($config_json_str)
    EndIf

    Return $retval
EndFunc   ;==>_depthaiDeviceCreatePipeline

Func _depthaiCNNHostPipelineRelease($hostedPipelinePtr)
    ; CVAPI(void) depthaiCNNHostPipelineRelease(std::shared_ptr<CNNHostPipeline>** hostedPipelinePtr);

    Local $sHostedPipelinePtrDllType
    If IsDllStruct($hostedPipelinePtr) Then
        $sHostedPipelinePtrDllType = "struct*"
    ElseIf $hostedPipelinePtr == Null Then
        $sHostedPipelinePtrDllType = "ptr"
    Else
        $sHostedPipelinePtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiCNNHostPipelineRelease", $sHostedPipelinePtrDllType, $hostedPipelinePtr), "depthaiCNNHostPipelineRelease", @error)
EndFunc   ;==>_depthaiCNNHostPipelineRelease

Func _depthaiCNNHostPipelineGetAvailableNNetAndDataPackets($cnnHostPipeline, $blocking)
    ; CVAPI(NNetAndDataPackets*) depthaiCNNHostPipelineGetAvailableNNetAndDataPackets(CNNHostPipeline* cnnHostPipeline, bool blocking);

    Local $sCnnHostPipelineDllType
    If IsDllStruct($cnnHostPipeline) Then
        $sCnnHostPipelineDllType = "struct*"
    Else
        $sCnnHostPipelineDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiCNNHostPipelineGetAvailableNNetAndDataPackets", $sCnnHostPipelineDllType, $cnnHostPipeline, "boolean", $blocking), "depthaiCNNHostPipelineGetAvailableNNetAndDataPackets", @error)
EndFunc   ;==>_depthaiCNNHostPipelineGetAvailableNNetAndDataPackets

Func _depthaiNNetAndDataPacketsGetNNetCount($nnetAndDataPackets)
    ; CVAPI(int) depthaiNNetAndDataPacketsGetNNetCount(NNetAndDataPackets* nnetAndDataPackets);

    Local $sNnetAndDataPacketsDllType
    If IsDllStruct($nnetAndDataPackets) Then
        $sNnetAndDataPacketsDllType = "struct*"
    Else
        $sNnetAndDataPacketsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetAndDataPacketsGetNNetCount", $sNnetAndDataPacketsDllType, $nnetAndDataPackets), "depthaiNNetAndDataPacketsGetNNetCount", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetNNetCount

Func _depthaiNNetAndDataPacketsGetNNetArr($nnetAndDataPackets, $packetArr)
    ; CVAPI(void) depthaiNNetAndDataPacketsGetNNetArr(NNetAndDataPackets* nnetAndDataPackets, NNetPacket** packetArr);

    Local $sNnetAndDataPacketsDllType
    If IsDllStruct($nnetAndDataPackets) Then
        $sNnetAndDataPacketsDllType = "struct*"
    Else
        $sNnetAndDataPacketsDllType = "ptr"
    EndIf

    Local $sPacketArrDllType
    If IsDllStruct($packetArr) Then
        $sPacketArrDllType = "struct*"
    ElseIf $packetArr == Null Then
        $sPacketArrDllType = "ptr"
    Else
        $sPacketArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsGetNNetArr", $sNnetAndDataPacketsDllType, $nnetAndDataPackets, $sPacketArrDllType, $packetArr), "depthaiNNetAndDataPacketsGetNNetArr", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetNNetArr

Func _depthaiNNetAndDataPacketsGetHostDataPacketCount($nnetAndDataPackets)
    ; CVAPI(int) depthaiNNetAndDataPacketsGetHostDataPacketCount(NNetAndDataPackets* nnetAndDataPackets);

    Local $sNnetAndDataPacketsDllType
    If IsDllStruct($nnetAndDataPackets) Then
        $sNnetAndDataPacketsDllType = "struct*"
    Else
        $sNnetAndDataPacketsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetAndDataPacketsGetHostDataPacketCount", $sNnetAndDataPacketsDllType, $nnetAndDataPackets), "depthaiNNetAndDataPacketsGetHostDataPacketCount", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetHostDataPacketCount

Func _depthaiNNetAndDataPacketsGetHostDataPacketArr($nnetAndDataPackets, $packetArr)
    ; CVAPI(void) depthaiNNetAndDataPacketsGetHostDataPacketArr(NNetAndDataPackets* nnetAndDataPackets, HostDataPacket** packetArr);

    Local $sNnetAndDataPacketsDllType
    If IsDllStruct($nnetAndDataPackets) Then
        $sNnetAndDataPacketsDllType = "struct*"
    Else
        $sNnetAndDataPacketsDllType = "ptr"
    EndIf

    Local $sPacketArrDllType
    If IsDllStruct($packetArr) Then
        $sPacketArrDllType = "struct*"
    ElseIf $packetArr == Null Then
        $sPacketArrDllType = "ptr"
    Else
        $sPacketArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsGetHostDataPacketArr", $sNnetAndDataPacketsDllType, $nnetAndDataPackets, $sPacketArrDllType, $packetArr), "depthaiNNetAndDataPacketsGetHostDataPacketArr", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetHostDataPacketArr

Func _depthaiNNetAndDataPacketsRelease($nnetAndDataPackets)
    ; CVAPI(void) depthaiNNetAndDataPacketsRelease(NNetAndDataPackets** nnetAndDataPackets);

    Local $sNnetAndDataPacketsDllType
    If IsDllStruct($nnetAndDataPackets) Then
        $sNnetAndDataPacketsDllType = "struct*"
    ElseIf $nnetAndDataPackets == Null Then
        $sNnetAndDataPacketsDllType = "ptr"
    Else
        $sNnetAndDataPacketsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsRelease", $sNnetAndDataPacketsDllType, $nnetAndDataPackets), "depthaiNNetAndDataPacketsRelease", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsRelease

Func _depthaiHostDataPacketGetDimensions($packet, $dimensions)
    ; CVAPI(void) depthaiHostDataPacketGetDimensions(HostDataPacket* packet, std::vector<int>* dimensions);

    Local $sPacketDllType
    If IsDllStruct($packet) Then
        $sPacketDllType = "struct*"
    Else
        $sPacketDllType = "ptr"
    EndIf

    Local $vecDimensions, $iArrDimensionsSize
    Local $bDimensionsIsArray = VarGetType($dimensions) == "Array"

    If $bDimensionsIsArray Then
        $vecDimensions = _VectorOfIntCreate()

        $iArrDimensionsSize = UBound($dimensions)
        For $i = 0 To $iArrDimensionsSize - 1
            _VectorOfIntPush($vecDimensions, $dimensions[$i])
        Next
    Else
        $vecDimensions = $dimensions
    EndIf

    Local $sDimensionsDllType
    If IsDllStruct($dimensions) Then
        $sDimensionsDllType = "struct*"
    Else
        $sDimensionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiHostDataPacketGetDimensions", $sPacketDllType, $packet, $sDimensionsDllType, $vecDimensions), "depthaiHostDataPacketGetDimensions", @error)

    If $bDimensionsIsArray Then
        _VectorOfIntRelease($vecDimensions)
    EndIf
EndFunc   ;==>_depthaiHostDataPacketGetDimensions

Func _depthaiHostDataPacketGetMetadata($packet, $metadata)
    ; CVAPI(bool) depthaiHostDataPacketGetMetadata(HostDataPacket* packet, FrameMetadata* metadata);

    Local $sPacketDllType
    If IsDllStruct($packet) Then
        $sPacketDllType = "struct*"
    Else
        $sPacketDllType = "ptr"
    EndIf

    Local $sMetadataDllType
    If IsDllStruct($metadata) Then
        $sMetadataDllType = "struct*"
    Else
        $sMetadataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "depthaiHostDataPacketGetMetadata", $sPacketDllType, $packet, $sMetadataDllType, $metadata), "depthaiHostDataPacketGetMetadata", @error)
EndFunc   ;==>_depthaiHostDataPacketGetMetadata

Func _depthaiNNetPacketGetDetectedObjectsCount($packet)
    ; CVAPI(int) depthaiNNetPacketGetDetectedObjectsCount(NNetPacket* packet);

    Local $sPacketDllType
    If IsDllStruct($packet) Then
        $sPacketDllType = "struct*"
    Else
        $sPacketDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetPacketGetDetectedObjectsCount", $sPacketDllType, $packet), "depthaiNNetPacketGetDetectedObjectsCount", @error)
EndFunc   ;==>_depthaiNNetPacketGetDetectedObjectsCount

Func _depthaiNNetPacketGetDetectedObjects($packet, $detections)
    ; CVAPI(void) depthaiNNetPacketGetDetectedObjects(NNetPacket* packet, dai::Detection* detections);

    Local $sPacketDllType
    If IsDllStruct($packet) Then
        $sPacketDllType = "struct*"
    Else
        $sPacketDllType = "ptr"
    EndIf

    Local $sDetectionsDllType
    If IsDllStruct($detections) Then
        $sDetectionsDllType = "struct*"
    Else
        $sDetectionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetPacketGetDetectedObjects", $sPacketDllType, $packet, $sDetectionsDllType, $detections), "depthaiNNetPacketGetDetectedObjects", @error)
EndFunc   ;==>_depthaiNNetPacketGetDetectedObjects

Func _depthaiNNetPacketGetMetadata($packet, $metadata)
    ; CVAPI(bool) depthaiNNetPacketGetMetadata(NNetPacket* packet, FrameMetadata* metadata);

    Local $sPacketDllType
    If IsDllStruct($packet) Then
        $sPacketDllType = "struct*"
    Else
        $sPacketDllType = "ptr"
    EndIf

    Local $sMetadataDllType
    If IsDllStruct($metadata) Then
        $sMetadataDllType = "struct*"
    Else
        $sMetadataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "depthaiNNetPacketGetMetadata", $sPacketDllType, $packet, $sMetadataDllType, $metadata), "depthaiNNetPacketGetMetadata", @error)
EndFunc   ;==>_depthaiNNetPacketGetMetadata

Func _depthaiFrameMetadataCreate()
    ; CVAPI(FrameMetadata*) depthaiFrameMetadataCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiFrameMetadataCreate"), "depthaiFrameMetadataCreate", @error)
EndFunc   ;==>_depthaiFrameMetadataCreate

Func _depthaiFrameMetadataRelease($metadata)
    ; CVAPI(void) depthaiFrameMetadataRelease(FrameMetadata** metadata);

    Local $sMetadataDllType
    If IsDllStruct($metadata) Then
        $sMetadataDllType = "struct*"
    ElseIf $metadata == Null Then
        $sMetadataDllType = "ptr"
    Else
        $sMetadataDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiFrameMetadataRelease", $sMetadataDllType, $metadata), "depthaiFrameMetadataRelease", @error)
EndFunc   ;==>_depthaiFrameMetadataRelease