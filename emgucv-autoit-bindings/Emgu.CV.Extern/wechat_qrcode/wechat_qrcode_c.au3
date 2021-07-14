#include-once
#include "..\..\CVEUtils.au3"

Func _cveWeChatQRCodeCreate($detectorPrototxtPath, $detectorCaffeModelPath, $superResolutionPrototxtPath, $superResolutionCaffeModelPath)
    ; CVAPI(cv::wechat_qrcode::WeChatQRCode*) cveWeChatQRCodeCreate(cv::String* detectorPrototxtPath, cv::String* detectorCaffeModelPath, cv::String* superResolutionPrototxtPath, cv::String* superResolutionCaffeModelPath);

    Local $bDetectorPrototxtPathIsString = VarGetType($detectorPrototxtPath) == "String"
    If $bDetectorPrototxtPathIsString Then
        $detectorPrototxtPath = _cveStringCreateFromStr($detectorPrototxtPath)
    EndIf

    Local $bDetectorCaffeModelPathIsString = VarGetType($detectorCaffeModelPath) == "String"
    If $bDetectorCaffeModelPathIsString Then
        $detectorCaffeModelPath = _cveStringCreateFromStr($detectorCaffeModelPath)
    EndIf

    Local $bSuperResolutionPrototxtPathIsString = VarGetType($superResolutionPrototxtPath) == "String"
    If $bSuperResolutionPrototxtPathIsString Then
        $superResolutionPrototxtPath = _cveStringCreateFromStr($superResolutionPrototxtPath)
    EndIf

    Local $bSuperResolutionCaffeModelPathIsString = VarGetType($superResolutionCaffeModelPath) == "String"
    If $bSuperResolutionCaffeModelPathIsString Then
        $superResolutionCaffeModelPath = _cveStringCreateFromStr($superResolutionCaffeModelPath)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWeChatQRCodeCreate", "ptr", $detectorPrototxtPath, "ptr", $detectorCaffeModelPath, "ptr", $superResolutionPrototxtPath, "ptr", $superResolutionCaffeModelPath), "cveWeChatQRCodeCreate", @error)

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

Func _cveWeChatQRCodeRelease(ByRef $detector)
    ; CVAPI(void) cveWeChatQRCodeRelease(cv::wechat_qrcode::WeChatQRCode** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeChatQRCodeRelease", "ptr*", $detector), "cveWeChatQRCodeRelease", @error)
EndFunc   ;==>_cveWeChatQRCodeRelease

Func _cveWeChatQRCodeDetectAndDecode(ByRef $detector, ByRef $img, ByRef $points, ByRef $results)
    ; CVAPI(void) cveWeChatQRCodeDetectAndDecode(cv::wechat_qrcode::WeChatQRCode* detector, cv::_InputArray* img, cv::_OutputArray* points, std::vector<std::string>* results);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeChatQRCodeDetectAndDecode", "ptr", $detector, "ptr", $img, "ptr", $points, "ptr", $results), "cveWeChatQRCodeDetectAndDecode", @error)
EndFunc   ;==>_cveWeChatQRCodeDetectAndDecode

Func _cveWeChatQRCodeDetectAndDecodeMat(ByRef $detector, ByRef $matImg, ByRef $matPoints, ByRef $results)
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