#include-once
#include "..\..\CVEUtils.au3"

Func _depthaiDeviceCreate($usb_device, $usb2_mode)
    ; CVAPI(Device*) depthaiDeviceCreate(cv::String* usb_device, bool usb2_mode);

    Local $bUsb_deviceIsString = VarGetType($usb_device) == "String"
    If $bUsb_deviceIsString Then
        $usb_device = _cveStringCreateFromStr($usb_device)
    EndIf

    Local $bUsb_deviceDllType
    If VarGetType($usb_device) == "DLLStruct" Then
        $bUsb_deviceDllType = "struct*"
    Else
        $bUsb_deviceDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiDeviceCreate", $bUsb_deviceDllType, $usb_device, "boolean", $usb2_mode), "depthaiDeviceCreate", @error)

    If $bUsb_deviceIsString Then
        _cveStringRelease($usb_device)
    EndIf

    Return $retval
EndFunc   ;==>_depthaiDeviceCreate

Func _depthaiDeviceRelease($usb_device)
    ; CVAPI(void) depthaiDeviceRelease(Device** usb_device);

    Local $bUsb_deviceDllType
    If VarGetType($usb_device) == "DLLStruct" Then
        $bUsb_deviceDllType = "struct*"
    Else
        $bUsb_deviceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiDeviceRelease", $bUsb_deviceDllType, $usb_device), "depthaiDeviceRelease", @error)
EndFunc   ;==>_depthaiDeviceRelease

Func _depthaiDeviceGetAvailableStreams($usb_device, $availableStreams)
    ; CVAPI(void) depthaiDeviceGetAvailableStreams(Device* usb_device, std::vector< cv::String >* availableStreams);

    Local $bUsb_deviceDllType
    If VarGetType($usb_device) == "DLLStruct" Then
        $bUsb_deviceDllType = "struct*"
    Else
        $bUsb_deviceDllType = "ptr"
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

    Local $bAvailableStreamsDllType
    If VarGetType($availableStreams) == "DLLStruct" Then
        $bAvailableStreamsDllType = "struct*"
    Else
        $bAvailableStreamsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiDeviceGetAvailableStreams", $bUsb_deviceDllType, $usb_device, $bAvailableStreamsDllType, $vecAvailableStreams), "depthaiDeviceGetAvailableStreams", @error)

    If $bAvailableStreamsIsArray Then
        _VectorOfCvStringRelease($vecAvailableStreams)
    EndIf
EndFunc   ;==>_depthaiDeviceGetAvailableStreams

Func _depthaiDeviceCreatePipeline($usb_device, $config_json_str, $hostedPipelinePtr)
    ; CVAPI(CNNHostPipeline*) depthaiDeviceCreatePipeline(Device* usb_device, cv::String* config_json_str, std::shared_ptr<CNNHostPipeline>** hostedPipelinePtr);

    Local $bUsb_deviceDllType
    If VarGetType($usb_device) == "DLLStruct" Then
        $bUsb_deviceDllType = "struct*"
    Else
        $bUsb_deviceDllType = "ptr"
    EndIf

    Local $bConfig_json_strIsString = VarGetType($config_json_str) == "String"
    If $bConfig_json_strIsString Then
        $config_json_str = _cveStringCreateFromStr($config_json_str)
    EndIf

    Local $bConfig_json_strDllType
    If VarGetType($config_json_str) == "DLLStruct" Then
        $bConfig_json_strDllType = "struct*"
    Else
        $bConfig_json_strDllType = "ptr"
    EndIf

    Local $bHostedPipelinePtrDllType
    If VarGetType($hostedPipelinePtr) == "DLLStruct" Then
        $bHostedPipelinePtrDllType = "struct*"
    Else
        $bHostedPipelinePtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiDeviceCreatePipeline", $bUsb_deviceDllType, $usb_device, $bConfig_json_strDllType, $config_json_str, $bHostedPipelinePtrDllType, $hostedPipelinePtr), "depthaiDeviceCreatePipeline", @error)

    If $bConfig_json_strIsString Then
        _cveStringRelease($config_json_str)
    EndIf

    Return $retval
EndFunc   ;==>_depthaiDeviceCreatePipeline

Func _depthaiCNNHostPipelineRelease($hostedPipelinePtr)
    ; CVAPI(void) depthaiCNNHostPipelineRelease(std::shared_ptr<CNNHostPipeline>** hostedPipelinePtr);

    Local $bHostedPipelinePtrDllType
    If VarGetType($hostedPipelinePtr) == "DLLStruct" Then
        $bHostedPipelinePtrDllType = "struct*"
    Else
        $bHostedPipelinePtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiCNNHostPipelineRelease", $bHostedPipelinePtrDllType, $hostedPipelinePtr), "depthaiCNNHostPipelineRelease", @error)
EndFunc   ;==>_depthaiCNNHostPipelineRelease

Func _depthaiCNNHostPipelineGetAvailableNNetAndDataPackets($cnnHostPipeline, $blocking)
    ; CVAPI(NNetAndDataPackets*) depthaiCNNHostPipelineGetAvailableNNetAndDataPackets(CNNHostPipeline* cnnHostPipeline, bool blocking);

    Local $bCnnHostPipelineDllType
    If VarGetType($cnnHostPipeline) == "DLLStruct" Then
        $bCnnHostPipelineDllType = "struct*"
    Else
        $bCnnHostPipelineDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiCNNHostPipelineGetAvailableNNetAndDataPackets", $bCnnHostPipelineDllType, $cnnHostPipeline, "boolean", $blocking), "depthaiCNNHostPipelineGetAvailableNNetAndDataPackets", @error)
EndFunc   ;==>_depthaiCNNHostPipelineGetAvailableNNetAndDataPackets

Func _depthaiNNetAndDataPacketsGetNNetCount($nnetAndDataPackets)
    ; CVAPI(int) depthaiNNetAndDataPacketsGetNNetCount(NNetAndDataPackets* nnetAndDataPackets);

    Local $bNnetAndDataPacketsDllType
    If VarGetType($nnetAndDataPackets) == "DLLStruct" Then
        $bNnetAndDataPacketsDllType = "struct*"
    Else
        $bNnetAndDataPacketsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetAndDataPacketsGetNNetCount", $bNnetAndDataPacketsDllType, $nnetAndDataPackets), "depthaiNNetAndDataPacketsGetNNetCount", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetNNetCount

Func _depthaiNNetAndDataPacketsGetNNetArr($nnetAndDataPackets, $packetArr)
    ; CVAPI(void) depthaiNNetAndDataPacketsGetNNetArr(NNetAndDataPackets* nnetAndDataPackets, NNetPacket** packetArr);

    Local $bNnetAndDataPacketsDllType
    If VarGetType($nnetAndDataPackets) == "DLLStruct" Then
        $bNnetAndDataPacketsDllType = "struct*"
    Else
        $bNnetAndDataPacketsDllType = "ptr"
    EndIf

    Local $bPacketArrDllType
    If VarGetType($packetArr) == "DLLStruct" Then
        $bPacketArrDllType = "struct*"
    Else
        $bPacketArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsGetNNetArr", $bNnetAndDataPacketsDllType, $nnetAndDataPackets, $bPacketArrDllType, $packetArr), "depthaiNNetAndDataPacketsGetNNetArr", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetNNetArr

Func _depthaiNNetAndDataPacketsGetHostDataPacketCount($nnetAndDataPackets)
    ; CVAPI(int) depthaiNNetAndDataPacketsGetHostDataPacketCount(NNetAndDataPackets* nnetAndDataPackets);

    Local $bNnetAndDataPacketsDllType
    If VarGetType($nnetAndDataPackets) == "DLLStruct" Then
        $bNnetAndDataPacketsDllType = "struct*"
    Else
        $bNnetAndDataPacketsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetAndDataPacketsGetHostDataPacketCount", $bNnetAndDataPacketsDllType, $nnetAndDataPackets), "depthaiNNetAndDataPacketsGetHostDataPacketCount", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetHostDataPacketCount

Func _depthaiNNetAndDataPacketsGetHostDataPacketArr($nnetAndDataPackets, $packetArr)
    ; CVAPI(void) depthaiNNetAndDataPacketsGetHostDataPacketArr(NNetAndDataPackets* nnetAndDataPackets, HostDataPacket** packetArr);

    Local $bNnetAndDataPacketsDllType
    If VarGetType($nnetAndDataPackets) == "DLLStruct" Then
        $bNnetAndDataPacketsDllType = "struct*"
    Else
        $bNnetAndDataPacketsDllType = "ptr"
    EndIf

    Local $bPacketArrDllType
    If VarGetType($packetArr) == "DLLStruct" Then
        $bPacketArrDllType = "struct*"
    Else
        $bPacketArrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsGetHostDataPacketArr", $bNnetAndDataPacketsDllType, $nnetAndDataPackets, $bPacketArrDllType, $packetArr), "depthaiNNetAndDataPacketsGetHostDataPacketArr", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetHostDataPacketArr

Func _depthaiNNetAndDataPacketsRelease($nnetAndDataPackets)
    ; CVAPI(void) depthaiNNetAndDataPacketsRelease(NNetAndDataPackets** nnetAndDataPackets);

    Local $bNnetAndDataPacketsDllType
    If VarGetType($nnetAndDataPackets) == "DLLStruct" Then
        $bNnetAndDataPacketsDllType = "struct*"
    Else
        $bNnetAndDataPacketsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsRelease", $bNnetAndDataPacketsDllType, $nnetAndDataPackets), "depthaiNNetAndDataPacketsRelease", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsRelease

Func _depthaiHostDataPacketGetDimensions($packet, $dimensions)
    ; CVAPI(void) depthaiHostDataPacketGetDimensions(HostDataPacket* packet, std::vector< int >* dimensions);

    Local $bPacketDllType
    If VarGetType($packet) == "DLLStruct" Then
        $bPacketDllType = "struct*"
    Else
        $bPacketDllType = "ptr"
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

    Local $bDimensionsDllType
    If VarGetType($dimensions) == "DLLStruct" Then
        $bDimensionsDllType = "struct*"
    Else
        $bDimensionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiHostDataPacketGetDimensions", $bPacketDllType, $packet, $bDimensionsDllType, $vecDimensions), "depthaiHostDataPacketGetDimensions", @error)

    If $bDimensionsIsArray Then
        _VectorOfIntRelease($vecDimensions)
    EndIf
EndFunc   ;==>_depthaiHostDataPacketGetDimensions

Func _depthaiHostDataPacketGetMetadata($packet, $metadata)
    ; CVAPI(bool) depthaiHostDataPacketGetMetadata(HostDataPacket* packet, FrameMetadata* metadata);

    Local $bPacketDllType
    If VarGetType($packet) == "DLLStruct" Then
        $bPacketDllType = "struct*"
    Else
        $bPacketDllType = "ptr"
    EndIf

    Local $bMetadataDllType
    If VarGetType($metadata) == "DLLStruct" Then
        $bMetadataDllType = "struct*"
    Else
        $bMetadataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "depthaiHostDataPacketGetMetadata", $bPacketDllType, $packet, $bMetadataDllType, $metadata), "depthaiHostDataPacketGetMetadata", @error)
EndFunc   ;==>_depthaiHostDataPacketGetMetadata

Func _depthaiNNetPacketGetDetectedObjectsCount($packet)
    ; CVAPI(int) depthaiNNetPacketGetDetectedObjectsCount(NNetPacket* packet);

    Local $bPacketDllType
    If VarGetType($packet) == "DLLStruct" Then
        $bPacketDllType = "struct*"
    Else
        $bPacketDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetPacketGetDetectedObjectsCount", $bPacketDllType, $packet), "depthaiNNetPacketGetDetectedObjectsCount", @error)
EndFunc   ;==>_depthaiNNetPacketGetDetectedObjectsCount

Func _depthaiNNetPacketGetDetectedObjects($packet, $detections)
    ; CVAPI(void) depthaiNNetPacketGetDetectedObjects(NNetPacket* packet, dai::Detection* detections);

    Local $bPacketDllType
    If VarGetType($packet) == "DLLStruct" Then
        $bPacketDllType = "struct*"
    Else
        $bPacketDllType = "ptr"
    EndIf

    Local $bDetectionsDllType
    If VarGetType($detections) == "DLLStruct" Then
        $bDetectionsDllType = "struct*"
    Else
        $bDetectionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetPacketGetDetectedObjects", $bPacketDllType, $packet, $bDetectionsDllType, $detections), "depthaiNNetPacketGetDetectedObjects", @error)
EndFunc   ;==>_depthaiNNetPacketGetDetectedObjects

Func _depthaiNNetPacketGetMetadata($packet, $metadata)
    ; CVAPI(bool) depthaiNNetPacketGetMetadata(NNetPacket* packet, FrameMetadata* metadata);

    Local $bPacketDllType
    If VarGetType($packet) == "DLLStruct" Then
        $bPacketDllType = "struct*"
    Else
        $bPacketDllType = "ptr"
    EndIf

    Local $bMetadataDllType
    If VarGetType($metadata) == "DLLStruct" Then
        $bMetadataDllType = "struct*"
    Else
        $bMetadataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "depthaiNNetPacketGetMetadata", $bPacketDllType, $packet, $bMetadataDllType, $metadata), "depthaiNNetPacketGetMetadata", @error)
EndFunc   ;==>_depthaiNNetPacketGetMetadata

Func _depthaiFrameMetadataCreate()
    ; CVAPI(FrameMetadata*) depthaiFrameMetadataCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiFrameMetadataCreate"), "depthaiFrameMetadataCreate", @error)
EndFunc   ;==>_depthaiFrameMetadataCreate

Func _depthaiFrameMetadataRelease($metadata)
    ; CVAPI(void) depthaiFrameMetadataRelease(FrameMetadata** metadata);

    Local $bMetadataDllType
    If VarGetType($metadata) == "DLLStruct" Then
        $bMetadataDllType = "struct*"
    Else
        $bMetadataDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiFrameMetadataRelease", $bMetadataDllType, $metadata), "depthaiFrameMetadataRelease", @error)
EndFunc   ;==>_depthaiFrameMetadataRelease