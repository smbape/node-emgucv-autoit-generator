#include-once
#include "..\..\CVEUtils.au3"

Func _cveWeChatQRCodeCreate($detectorPrototxtPath, $detectorCaffeModelPath, $superResolutionPrototxtPath, $superResolutionCaffeModelPath)
    ; CVAPI(cv::wechat_qrcode::WeChatQRCode*) cveWeChatQRCodeCreate(cv::String* detectorPrototxtPath, cv::String* detectorCaffeModelPath, cv::String* superResolutionPrototxtPath, cv::String* superResolutionCaffeModelPath);

    Local $bDetectorPrototxtPathIsString = VarGetType($detectorPrototxtPath) == "String"
    If $bDetectorPrototxtPathIsString Then
        $detectorPrototxtPath = _cveStringCreateFromStr($detectorPrototxtPath)
    EndIf

    Local $bDetectorPrototxtPathDllType
    If VarGetType($detectorPrototxtPath) == "DLLStruct" Then
        $bDetectorPrototxtPathDllType = "struct*"
    Else
        $bDetectorPrototxtPathDllType = "ptr"
    EndIf

    Local $bDetectorCaffeModelPathIsString = VarGetType($detectorCaffeModelPath) == "String"
    If $bDetectorCaffeModelPathIsString Then
        $detectorCaffeModelPath = _cveStringCreateFromStr($detectorCaffeModelPath)
    EndIf

    Local $bDetectorCaffeModelPathDllType
    If VarGetType($detectorCaffeModelPath) == "DLLStruct" Then
        $bDetectorCaffeModelPathDllType = "struct*"
    Else
        $bDetectorCaffeModelPathDllType = "ptr"
    EndIf

    Local $bSuperResolutionPrototxtPathIsString = VarGetType($superResolutionPrototxtPath) == "String"
    If $bSuperResolutionPrototxtPathIsString Then
        $superResolutionPrototxtPath = _cveStringCreateFromStr($superResolutionPrototxtPath)
    EndIf

    Local $bSuperResolutionPrototxtPathDllType
    If VarGetType($superResolutionPrototxtPath) == "DLLStruct" Then
        $bSuperResolutionPrototxtPathDllType = "struct*"
    Else
        $bSuperResolutionPrototxtPathDllType = "ptr"
    EndIf

    Local $bSuperResolutionCaffeModelPathIsString = VarGetType($superResolutionCaffeModelPath) == "String"
    If $bSuperResolutionCaffeModelPathIsString Then
        $superResolutionCaffeModelPath = _cveStringCreateFromStr($superResolutionCaffeModelPath)
    EndIf

    Local $bSuperResolutionCaffeModelPathDllType
    If VarGetType($superResolutionCaffeModelPath) == "DLLStruct" Then
        $bSuperResolutionCaffeModelPathDllType = "struct*"
    Else
        $bSuperResolutionCaffeModelPathDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWeChatQRCodeCreate", $bDetectorPrototxtPathDllType, $detectorPrototxtPath, $bDetectorCaffeModelPathDllType, $detectorCaffeModelPath, $bSuperResolutionPrototxtPathDllType, $superResolutionPrototxtPath, $bSuperResolutionCaffeModelPathDllType, $superResolutionCaffeModelPath), "cveWeChatQRCodeCreate", @error)

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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeChatQRCodeRelease", $bDetectorDllType, $detector), "cveWeChatQRCodeRelease", @error)
EndFunc   ;==>_cveWeChatQRCodeRelease

Func _cveWeChatQRCodeDetectAndDecode($detector, $img, $points, $results)
    ; CVAPI(void) cveWeChatQRCodeDetectAndDecode(cv::wechat_qrcode::WeChatQRCode* detector, cv::_InputArray* img, cv::_OutputArray* points, std::vector<std::string>* results);

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bResultsDllType
    If VarGetType($results) == "DLLStruct" Then
        $bResultsDllType = "struct*"
    Else
        $bResultsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeChatQRCodeDetectAndDecode", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points, $bResultsDllType, $results), "cveWeChatQRCodeDetectAndDecode", @error)
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