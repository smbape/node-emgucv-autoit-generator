#include-once
#include <..\..\CVEUtils.au3>

Func _depthaiDeviceCreate($usb_device, $usb2_mode)
    ; CVAPI(Device*) depthaiDeviceCreate(cv::String* usb_device, bool usb2_mode);

    Local $bUsb_deviceIsString = VarGetType($usb_device) == "String"
    If $bUsb_deviceIsString Then
        $usb_device = _cveStringCreateFromStr($usb_device)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiDeviceCreate", "ptr", $usb_device, "boolean", $usb2_mode), "depthaiDeviceCreate", @error)

    If $bUsb_deviceIsString Then
        _cveStringRelease($usb_device)
    EndIf

    Return $retval
EndFunc   ;==>_depthaiDeviceCreate

Func _depthaiDeviceRelease(ByRef $usb_device)
    ; CVAPI(void) depthaiDeviceRelease(Device** usb_device);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiDeviceRelease", "ptr*", $usb_device), "depthaiDeviceRelease", @error)
EndFunc   ;==>_depthaiDeviceRelease

Func _depthaiDeviceGetAvailableStreams(ByRef $usb_device, ByRef $availableStreams)
    ; CVAPI(void) depthaiDeviceGetAvailableStreams(Device* usb_device, std::vector< cv::String >* availableStreams);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiDeviceGetAvailableStreams", "struct*", $usb_device, "ptr", $vecAvailableStreams), "depthaiDeviceGetAvailableStreams", @error)

    If $bAvailableStreamsIsArray Then
        _VectorOfCvStringRelease($vecAvailableStreams)
    EndIf
EndFunc   ;==>_depthaiDeviceGetAvailableStreams

Func _depthaiDeviceCreatePipeline(ByRef $usb_device, $config_json_str, ByRef $hostedPipelinePtr)
    ; CVAPI(CNNHostPipeline*) depthaiDeviceCreatePipeline(Device* usb_device, cv::String* config_json_str, std::shared_ptr<CNNHostPipeline>** hostedPipelinePtr);

    Local $bConfig_json_strIsString = VarGetType($config_json_str) == "String"
    If $bConfig_json_strIsString Then
        $config_json_str = _cveStringCreateFromStr($config_json_str)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiDeviceCreatePipeline", "struct*", $usb_device, "ptr", $config_json_str, "ptr*", $hostedPipelinePtr), "depthaiDeviceCreatePipeline", @error)

    If $bConfig_json_strIsString Then
        _cveStringRelease($config_json_str)
    EndIf

    Return $retval
EndFunc   ;==>_depthaiDeviceCreatePipeline

Func _depthaiCNNHostPipelineRelease(ByRef $hostedPipelinePtr)
    ; CVAPI(void) depthaiCNNHostPipelineRelease(std::shared_ptr<CNNHostPipeline>** hostedPipelinePtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiCNNHostPipelineRelease", "ptr*", $hostedPipelinePtr), "depthaiCNNHostPipelineRelease", @error)
EndFunc   ;==>_depthaiCNNHostPipelineRelease

Func _depthaiCNNHostPipelineGetAvailableNNetAndDataPackets(ByRef $cnnHostPipeline, $blocking)
    ; CVAPI(NNetAndDataPackets*) depthaiCNNHostPipelineGetAvailableNNetAndDataPackets(CNNHostPipeline* cnnHostPipeline, bool blocking);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiCNNHostPipelineGetAvailableNNetAndDataPackets", "struct*", $cnnHostPipeline, "boolean", $blocking), "depthaiCNNHostPipelineGetAvailableNNetAndDataPackets", @error)
EndFunc   ;==>_depthaiCNNHostPipelineGetAvailableNNetAndDataPackets

Func _depthaiNNetAndDataPacketsGetNNetCount(ByRef $nnetAndDataPackets)
    ; CVAPI(int) depthaiNNetAndDataPacketsGetNNetCount(NNetAndDataPackets* nnetAndDataPackets);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetAndDataPacketsGetNNetCount", "struct*", $nnetAndDataPackets), "depthaiNNetAndDataPacketsGetNNetCount", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetNNetCount

Func _depthaiNNetAndDataPacketsGetNNetArr(ByRef $nnetAndDataPackets, ByRef $packetArr)
    ; CVAPI(void) depthaiNNetAndDataPacketsGetNNetArr(NNetAndDataPackets* nnetAndDataPackets, NNetPacket** packetArr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsGetNNetArr", "struct*", $nnetAndDataPackets, "ptr*", $packetArr), "depthaiNNetAndDataPacketsGetNNetArr", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetNNetArr

Func _depthaiNNetAndDataPacketsGetHostDataPacketCount(ByRef $nnetAndDataPackets)
    ; CVAPI(int) depthaiNNetAndDataPacketsGetHostDataPacketCount(NNetAndDataPackets* nnetAndDataPackets);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetAndDataPacketsGetHostDataPacketCount", "struct*", $nnetAndDataPackets), "depthaiNNetAndDataPacketsGetHostDataPacketCount", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetHostDataPacketCount

Func _depthaiNNetAndDataPacketsGetHostDataPacketArr(ByRef $nnetAndDataPackets, ByRef $packetArr)
    ; CVAPI(void) depthaiNNetAndDataPacketsGetHostDataPacketArr(NNetAndDataPackets* nnetAndDataPackets, HostDataPacket** packetArr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsGetHostDataPacketArr", "struct*", $nnetAndDataPackets, "ptr*", $packetArr), "depthaiNNetAndDataPacketsGetHostDataPacketArr", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsGetHostDataPacketArr

Func _depthaiNNetAndDataPacketsRelease(ByRef $nnetAndDataPackets)
    ; CVAPI(void) depthaiNNetAndDataPacketsRelease(NNetAndDataPackets** nnetAndDataPackets);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetAndDataPacketsRelease", "ptr*", $nnetAndDataPackets), "depthaiNNetAndDataPacketsRelease", @error)
EndFunc   ;==>_depthaiNNetAndDataPacketsRelease

Func _depthaiHostDataPacketGetDimensions(ByRef $packet, ByRef $dimensions)
    ; CVAPI(void) depthaiHostDataPacketGetDimensions(HostDataPacket* packet, std::vector< int >* dimensions);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiHostDataPacketGetDimensions", "struct*", $packet, "ptr", $vecDimensions), "depthaiHostDataPacketGetDimensions", @error)

    If $bDimensionsIsArray Then
        _VectorOfIntRelease($vecDimensions)
    EndIf
EndFunc   ;==>_depthaiHostDataPacketGetDimensions

Func _depthaiHostDataPacketGetMetadata(ByRef $packet, ByRef $metadata)
    ; CVAPI(bool) depthaiHostDataPacketGetMetadata(HostDataPacket* packet, FrameMetadata* metadata);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "depthaiHostDataPacketGetMetadata", "struct*", $packet, "struct*", $metadata), "depthaiHostDataPacketGetMetadata", @error)
EndFunc   ;==>_depthaiHostDataPacketGetMetadata

Func _depthaiNNetPacketGetDetectedObjectsCount(ByRef $packet)
    ; CVAPI(int) depthaiNNetPacketGetDetectedObjectsCount(NNetPacket* packet);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "depthaiNNetPacketGetDetectedObjectsCount", "struct*", $packet), "depthaiNNetPacketGetDetectedObjectsCount", @error)
EndFunc   ;==>_depthaiNNetPacketGetDetectedObjectsCount

Func _depthaiNNetPacketGetDetectedObjects(ByRef $packet, ByRef $detections)
    ; CVAPI(void) depthaiNNetPacketGetDetectedObjects(NNetPacket* packet, dai::Detection* detections);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiNNetPacketGetDetectedObjects", "struct*", $packet, "ptr", $detections), "depthaiNNetPacketGetDetectedObjects", @error)
EndFunc   ;==>_depthaiNNetPacketGetDetectedObjects

Func _depthaiNNetPacketGetMetadata(ByRef $packet, ByRef $metadata)
    ; CVAPI(bool) depthaiNNetPacketGetMetadata(NNetPacket* packet, FrameMetadata* metadata);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "depthaiNNetPacketGetMetadata", "struct*", $packet, "struct*", $metadata), "depthaiNNetPacketGetMetadata", @error)
EndFunc   ;==>_depthaiNNetPacketGetMetadata

Func _depthaiFrameMetadataCreate()
    ; CVAPI(FrameMetadata*) depthaiFrameMetadataCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "depthaiFrameMetadataCreate"), "depthaiFrameMetadataCreate", @error)
EndFunc   ;==>_depthaiFrameMetadataCreate

Func _depthaiFrameMetadataRelease(ByRef $metadata)
    ; CVAPI(void) depthaiFrameMetadataRelease(FrameMetadata** metadata);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "depthaiFrameMetadataRelease", "ptr*", $metadata), "depthaiFrameMetadataRelease", @error)
EndFunc   ;==>_depthaiFrameMetadataRelease