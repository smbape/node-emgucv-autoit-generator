#include-once
#include "..\..\CVEUtils.au3"

Func _cveBarcodeDetectorCreate($prototxtPath, $modelPath)
    ; CVAPI(cv::barcode::BarcodeDetector*) cveBarcodeDetectorCreate(cv::String* prototxtPath, cv::String* modelPath);

    Local $bPrototxtPathIsString = IsString($prototxtPath)
    If $bPrototxtPathIsString Then
        $prototxtPath = _cveStringCreateFromStr($prototxtPath)
    EndIf

    Local $sPrototxtPathDllType
    If IsDllStruct($prototxtPath) Then
        $sPrototxtPathDllType = "struct*"
    Else
        $sPrototxtPathDllType = "ptr"
    EndIf

    Local $bModelPathIsString = IsString($modelPath)
    If $bModelPathIsString Then
        $modelPath = _cveStringCreateFromStr($modelPath)
    EndIf

    Local $sModelPathDllType
    If IsDllStruct($modelPath) Then
        $sModelPathDllType = "struct*"
    Else
        $sModelPathDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBarcodeDetectorCreate", $sPrototxtPathDllType, $prototxtPath, $sModelPathDllType, $modelPath), "cveBarcodeDetectorCreate", @error)

    If $bModelPathIsString Then
        _cveStringRelease($modelPath)
    EndIf

    If $bPrototxtPathIsString Then
        _cveStringRelease($prototxtPath)
    EndIf

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorCreate

Func _cveBarcodeDetectorRelease($detector)
    ; CVAPI(void) cveBarcodeDetectorRelease(cv::barcode::BarcodeDetector** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBarcodeDetectorRelease", $sDetectorDllType, $detector), "cveBarcodeDetectorRelease", @error)
EndFunc   ;==>_cveBarcodeDetectorRelease

Func _cveBarcodeDetectorDetect($detector, $img, $points)
    ; CVAPI(bool) cveBarcodeDetectorDetect(cv::barcode::BarcodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBarcodeDetectorDetect", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points), "cveBarcodeDetectorDetect", @error)
EndFunc   ;==>_cveBarcodeDetectorDetect

Func _cveBarcodeDetectorDetectTyped($detector, $typeOfImg, $img, $typeOfPoints, $points)

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

    Local $retval = _cveBarcodeDetectorDetect($detector, $iArrImg, $oArrPoints)

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

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectTyped

Func _cveBarcodeDetectorDetectMat($detector, $img, $points)
    ; cveBarcodeDetectorDetect using cv::Mat instead of _*Array
    Local $retval = _cveBarcodeDetectorDetectTyped($detector, "Mat", $img, "Mat", $points)

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectMat

Func _cveBarcodeDetectorDecode($detector, $img, $points, $decoded_info, $decoded_type)
    ; CVAPI(bool) cveBarcodeDetectorDecode(cv::barcode::BarcodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, std::vector<cv::String>* decoded_info, std::vector<int>* decoded_type);

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

    Local $vecDecoded_info, $iArrDecoded_infoSize
    Local $bDecoded_infoIsArray = IsArray($decoded_info)

    If $bDecoded_infoIsArray Then
        $vecDecoded_info = _VectorOfCvStringCreate()

        $iArrDecoded_infoSize = UBound($decoded_info)
        For $i = 0 To $iArrDecoded_infoSize - 1
            _VectorOfCvStringPush($vecDecoded_info, $decoded_info[$i])
        Next
    Else
        $vecDecoded_info = $decoded_info
    EndIf

    Local $sDecoded_infoDllType
    If IsDllStruct($decoded_info) Then
        $sDecoded_infoDllType = "struct*"
    Else
        $sDecoded_infoDllType = "ptr"
    EndIf

    Local $vecDecoded_type, $iArrDecoded_typeSize
    Local $bDecoded_typeIsArray = IsArray($decoded_type)

    If $bDecoded_typeIsArray Then
        $vecDecoded_type = _VectorOfIntCreate()

        $iArrDecoded_typeSize = UBound($decoded_type)
        For $i = 0 To $iArrDecoded_typeSize - 1
            _VectorOfIntPush($vecDecoded_type, $decoded_type[$i])
        Next
    Else
        $vecDecoded_type = $decoded_type
    EndIf

    Local $sDecoded_typeDllType
    If IsDllStruct($decoded_type) Then
        $sDecoded_typeDllType = "struct*"
    Else
        $sDecoded_typeDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBarcodeDetectorDecode", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points, $sDecoded_infoDllType, $vecDecoded_info, $sDecoded_typeDllType, $vecDecoded_type), "cveBarcodeDetectorDecode", @error)

    If $bDecoded_typeIsArray Then
        _VectorOfIntRelease($vecDecoded_type)
    EndIf

    If $bDecoded_infoIsArray Then
        _VectorOfCvStringRelease($vecDecoded_info)
    EndIf

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDecode

Func _cveBarcodeDetectorDecodeTyped($detector, $typeOfImg, $img, $typeOfPoints, $points, $decoded_info, $decoded_type)

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

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    Local $retval = _cveBarcodeDetectorDecode($detector, $iArrImg, $iArrPoints, $decoded_info, $decoded_type)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
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

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDecodeTyped

Func _cveBarcodeDetectorDecodeMat($detector, $img, $points, $decoded_info, $decoded_type)
    ; cveBarcodeDetectorDecode using cv::Mat instead of _*Array
    Local $retval = _cveBarcodeDetectorDecodeTyped($detector, "Mat", $img, "Mat", $points, $decoded_info, $decoded_type)

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDecodeMat

Func _cveBarcodeDetectorDetectAndDecode($detector, $img, $decoded_info, $decoded_type, $points)
    ; CVAPI(bool) cveBarcodeDetectorDetectAndDecode(cv::barcode::BarcodeDetector* detector, cv::_InputArray* img, std::vector<cv::String>* decoded_info, std::vector<int>* decoded_type, cv::_OutputArray* points);

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

    Local $vecDecoded_info, $iArrDecoded_infoSize
    Local $bDecoded_infoIsArray = IsArray($decoded_info)

    If $bDecoded_infoIsArray Then
        $vecDecoded_info = _VectorOfCvStringCreate()

        $iArrDecoded_infoSize = UBound($decoded_info)
        For $i = 0 To $iArrDecoded_infoSize - 1
            _VectorOfCvStringPush($vecDecoded_info, $decoded_info[$i])
        Next
    Else
        $vecDecoded_info = $decoded_info
    EndIf

    Local $sDecoded_infoDllType
    If IsDllStruct($decoded_info) Then
        $sDecoded_infoDllType = "struct*"
    Else
        $sDecoded_infoDllType = "ptr"
    EndIf

    Local $vecDecoded_type, $iArrDecoded_typeSize
    Local $bDecoded_typeIsArray = IsArray($decoded_type)

    If $bDecoded_typeIsArray Then
        $vecDecoded_type = _VectorOfIntCreate()

        $iArrDecoded_typeSize = UBound($decoded_type)
        For $i = 0 To $iArrDecoded_typeSize - 1
            _VectorOfIntPush($vecDecoded_type, $decoded_type[$i])
        Next
    Else
        $vecDecoded_type = $decoded_type
    EndIf

    Local $sDecoded_typeDllType
    If IsDllStruct($decoded_type) Then
        $sDecoded_typeDllType = "struct*"
    Else
        $sDecoded_typeDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBarcodeDetectorDetectAndDecode", $sDetectorDllType, $detector, $sImgDllType, $img, $sDecoded_infoDllType, $vecDecoded_info, $sDecoded_typeDllType, $vecDecoded_type, $sPointsDllType, $points), "cveBarcodeDetectorDetectAndDecode", @error)

    If $bDecoded_typeIsArray Then
        _VectorOfIntRelease($vecDecoded_type)
    EndIf

    If $bDecoded_infoIsArray Then
        _VectorOfCvStringRelease($vecDecoded_info)
    EndIf

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectAndDecode

Func _cveBarcodeDetectorDetectAndDecodeTyped($detector, $typeOfImg, $img, $decoded_info, $decoded_type, $typeOfPoints, $points)

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

    Local $retval = _cveBarcodeDetectorDetectAndDecode($detector, $iArrImg, $decoded_info, $decoded_type, $oArrPoints)

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

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectAndDecodeTyped

Func _cveBarcodeDetectorDetectAndDecodeMat($detector, $img, $decoded_info, $decoded_type, $points)
    ; cveBarcodeDetectorDetectAndDecode using cv::Mat instead of _*Array
    Local $retval = _cveBarcodeDetectorDetectAndDecodeTyped($detector, "Mat", $img, $decoded_info, $decoded_type, "Mat", $points)

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectAndDecodeMat