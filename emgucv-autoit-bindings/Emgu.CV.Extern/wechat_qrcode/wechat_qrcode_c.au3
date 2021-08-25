#include-once
#include "..\..\CVEUtils.au3"

Func _cveWeChatQRCodeCreate($detectorPrototxtPath, $detectorCaffeModelPath, $superResolutionPrototxtPath, $superResolutionCaffeModelPath)
    ; CVAPI(cv::wechat_qrcode::WeChatQRCode*) cveWeChatQRCodeCreate(cv::String* detectorPrototxtPath, cv::String* detectorCaffeModelPath, cv::String* superResolutionPrototxtPath, cv::String* superResolutionCaffeModelPath);

    Local $bDetectorPrototxtPathIsString = IsString($detectorPrototxtPath)
    If $bDetectorPrototxtPathIsString Then
        $detectorPrototxtPath = _cveStringCreateFromStr($detectorPrototxtPath)
    EndIf

    Local $sDetectorPrototxtPathDllType
    If IsDllStruct($detectorPrototxtPath) Then
        $sDetectorPrototxtPathDllType = "struct*"
    Else
        $sDetectorPrototxtPathDllType = "ptr"
    EndIf

    Local $bDetectorCaffeModelPathIsString = IsString($detectorCaffeModelPath)
    If $bDetectorCaffeModelPathIsString Then
        $detectorCaffeModelPath = _cveStringCreateFromStr($detectorCaffeModelPath)
    EndIf

    Local $sDetectorCaffeModelPathDllType
    If IsDllStruct($detectorCaffeModelPath) Then
        $sDetectorCaffeModelPathDllType = "struct*"
    Else
        $sDetectorCaffeModelPathDllType = "ptr"
    EndIf

    Local $bSuperResolutionPrototxtPathIsString = IsString($superResolutionPrototxtPath)
    If $bSuperResolutionPrototxtPathIsString Then
        $superResolutionPrototxtPath = _cveStringCreateFromStr($superResolutionPrototxtPath)
    EndIf

    Local $sSuperResolutionPrototxtPathDllType
    If IsDllStruct($superResolutionPrototxtPath) Then
        $sSuperResolutionPrototxtPathDllType = "struct*"
    Else
        $sSuperResolutionPrototxtPathDllType = "ptr"
    EndIf

    Local $bSuperResolutionCaffeModelPathIsString = IsString($superResolutionCaffeModelPath)
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

Func _cveWeChatQRCodeDetectAndDecodeTyped($detector, $typeOfImg, $img, $typeOfPoints, $points, $results)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $oArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $oArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $oArrPoints = Call("_cveOutputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $oArrPoints = Call("_cveOutputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveWeChatQRCodeDetectAndDecode($detector, $iArrImg, $oArrPoints, $results)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveOutputArrayRelease($oArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveWeChatQRCodeDetectAndDecodeTyped

Func _cveWeChatQRCodeDetectAndDecodeMat($detector, $img, $points, $results)
    ; cveWeChatQRCodeDetectAndDecode using cv::Mat instead of _*Array
    _cveWeChatQRCodeDetectAndDecodeTyped($detector, "Mat", $img, "Mat", $points, $results)
EndFunc   ;==>_cveWeChatQRCodeDetectAndDecodeMat