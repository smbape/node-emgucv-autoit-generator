#include-once
#include "..\..\CVEUtils.au3"

Func _cveWeChatQRCodeCreate($detectorPrototxtPath, $detectorCaffeModelPath, $superResolutionPrototxtPath, $superResolutionCaffeModelPath)
    ; CVAPI(cv::wechat_qrcode::WeChatQRCode*) cveWeChatQRCodeCreate(cv::String* detectorPrototxtPath, cv::String* detectorCaffeModelPath, cv::String* superResolutionPrototxtPath, cv::String* superResolutionCaffeModelPath);

    Local $bDetectorPrototxtPathIsString = VarGetType($detectorPrototxtPath) == "String"
    If $bDetectorPrototxtPathIsString Then
        $detectorPrototxtPath = _cveStringCreateFromStr($detectorPrototxtPath)
    EndIf

    Local $sDetectorPrototxtPathDllType
    If IsDllStruct($detectorPrototxtPath) Then
        $sDetectorPrototxtPathDllType = "struct*"
    Else
        $sDetectorPrototxtPathDllType = "ptr"
    EndIf

    Local $bDetectorCaffeModelPathIsString = VarGetType($detectorCaffeModelPath) == "String"
    If $bDetectorCaffeModelPathIsString Then
        $detectorCaffeModelPath = _cveStringCreateFromStr($detectorCaffeModelPath)
    EndIf

    Local $sDetectorCaffeModelPathDllType
    If IsDllStruct($detectorCaffeModelPath) Then
        $sDetectorCaffeModelPathDllType = "struct*"
    Else
        $sDetectorCaffeModelPathDllType = "ptr"
    EndIf

    Local $bSuperResolutionPrototxtPathIsString = VarGetType($superResolutionPrototxtPath) == "String"
    If $bSuperResolutionPrototxtPathIsString Then
        $superResolutionPrototxtPath = _cveStringCreateFromStr($superResolutionPrototxtPath)
    EndIf

    Local $sSuperResolutionPrototxtPathDllType
    If IsDllStruct($superResolutionPrototxtPath) Then
        $sSuperResolutionPrototxtPathDllType = "struct*"
    Else
        $sSuperResolutionPrototxtPathDllType = "ptr"
    EndIf

    Local $bSuperResolutionCaffeModelPathIsString = VarGetType($superResolutionCaffeModelPath) == "String"
    If $bSuperResolutionCaffeModelPathIsString Then
        $superResolutionCaffeModelPath = _cveStringCreateFromStr($superResolutionCaffeModelPath)
    EndIf

    Local $sSuperResolutionCaffeModelPathDllType
    If IsDllStruct($superResolutionCaffeModelPath) Then
        $sSuperResolutionCaffeModelPathDllType = "struct*"
    Else
        $sSuperResolutionCaffeModelPathDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWeChatQRCodeCreate", $sDetectorPrototxtPathDllType, $detectorPrototxtPath, $sDetectorCaffeModelPathDllType, $detectorCaffeModelPath, $sSuperResolutionPrototxtPathDllType, $superResolutionPrototxtPath, $sSuperResolutionCaffeModelPathDllType, $superResolutionCaffeModelPath), "cveWeChatQRCodeCreate", @error)

    If $bSuperResolutionCaffeModelPathIsString Then
        _cveStringRelease($superResolutionCaffeModelPath)
    EndIf

    If $bSuperResolutionPrototxtPathIsString Then
        _cveStringRelease($superResolutionPrototxtPath)
    EndIf

    If $bDetectorCaffeModelPathIsString Then
        _cveStringRelease($detectorCaffeModelPath)
    EndIf

    If $bDetectorPrototxtPathIsString Then
        _cveStringRelease($detectorPrototxtPath)
    EndIf

    Return $retval
EndFunc   ;==>_cveWeChatQRCodeCreate

Func _cveWeChatQRCodeRelease($detector)
    ; CVAPI(void) cveWeChatQRCodeRelease(cv::wechat_qrcode::WeChatQRCode** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeChatQRCodeRelease", $sDetectorDllType, $detector), "cveWeChatQRCodeRelease", @error)
EndFunc   ;==>_cveWeChatQRCodeRelease

Func _cveWeChatQRCodeDetectAndDecode($detector, $img, $points, $results)
    ; CVAPI(void) cveWeChatQRCodeDetectAndDecode(cv::wechat_qrcode::WeChatQRCode* detector, cv::_InputArray* img, cv::_OutputArray* points, std::vector<std::string>* results);

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

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sResultsDllType
    If IsDllStruct($results) Then
        $sResultsDllType = "struct*"
    Else
        $sResultsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeChatQRCodeDetectAndDecode", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points, $sResultsDllType, $results), "cveWeChatQRCodeDetectAndDecode", @error)
EndFunc   ;==>_cveWeChatQRCodeDetectAndDecode

Func _cveWeChatQRCodeDetectAndDecodeMat($detector, $matImg, $matPoints, $results)
    ; cveWeChatQRCodeDetectAndDecode using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $oArrPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $oArrPoints = _cveOutputArrayFromMat($matPoints)
    EndIf

    _cveWeChatQRCodeDetectAndDecode($detector, $iArrImg, $oArrPoints, $results)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveOutputArrayRelease($oArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveWeChatQRCodeDetectAndDecodeMat