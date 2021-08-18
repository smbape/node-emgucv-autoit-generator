#include-once
#include "..\..\CVEUtils.au3"

Func _cveBarcodeDetectorCreate($prototxtPath, $modelPath)
    ; CVAPI(cv::barcode::BarcodeDetector*) cveBarcodeDetectorCreate(cv::String* prototxtPath, cv::String* modelPath);

    Local $bPrototxtPathIsString = VarGetType($prototxtPath) == "String"
    If $bPrototxtPathIsString Then
        $prototxtPath = _cveStringCreateFromStr($prototxtPath)
    EndIf

    Local $bPrototxtPathDllType
    If VarGetType($prototxtPath) == "DLLStruct" Then
        $bPrototxtPathDllType = "struct*"
    Else
        $bPrototxtPathDllType = "ptr"
    EndIf

    Local $bModelPathIsString = VarGetType($modelPath) == "String"
    If $bModelPathIsString Then
        $modelPath = _cveStringCreateFromStr($modelPath)
    EndIf

    Local $bModelPathDllType
    If VarGetType($modelPath) == "DLLStruct" Then
        $bModelPathDllType = "struct*"
    Else
        $bModelPathDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBarcodeDetectorCreate", $bPrototxtPathDllType, $prototxtPath, $bModelPathDllType, $modelPath), "cveBarcodeDetectorCreate", @error)

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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBarcodeDetectorRelease", $bDetectorDllType, $detector), "cveBarcodeDetectorRelease", @error)
EndFunc   ;==>_cveBarcodeDetectorRelease

Func _cveBarcodeDetectorDetect($detector, $img, $points)
    ; CVAPI(bool) cveBarcodeDetectorDetect(cv::barcode::BarcodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBarcodeDetectorDetect", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points), "cveBarcodeDetectorDetect", @error)
EndFunc   ;==>_cveBarcodeDetectorDetect

Func _cveBarcodeDetectorDetectMat($detector, $matImg, $matPoints)
    ; cveBarcodeDetectorDetect using cv::Mat instead of _*Array

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

    Local $retval = _cveBarcodeDetectorDetect($detector, $iArrImg, $oArrPoints)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveOutputArrayRelease($oArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectMat

Func _cveBarcodeDetectorDecode($detector, $img, $points, $decoded_info, $decoded_type)
    ; CVAPI(bool) cveBarcodeDetectorDecode(cv::barcode::BarcodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, std::vector<cv::String>* decoded_info, std::vector<int>* decoded_type);

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

    Local $vecDecoded_info, $iArrDecoded_infoSize
    Local $bDecoded_infoIsArray = VarGetType($decoded_info) == "Array"

    If $bDecoded_infoIsArray Then
        $vecDecoded_info = _VectorOfCvStringCreate()

        $iArrDecoded_infoSize = UBound($decoded_info)
        For $i = 0 To $iArrDecoded_infoSize - 1
            _VectorOfCvStringPush($vecDecoded_info, $decoded_info[$i])
        Next
    Else
        $vecDecoded_info = $decoded_info
    EndIf

    Local $bDecoded_infoDllType
    If VarGetType($decoded_info) == "DLLStruct" Then
        $bDecoded_infoDllType = "struct*"
    Else
        $bDecoded_infoDllType = "ptr"
    EndIf

    Local $vecDecoded_type, $iArrDecoded_typeSize
    Local $bDecoded_typeIsArray = VarGetType($decoded_type) == "Array"

    If $bDecoded_typeIsArray Then
        $vecDecoded_type = _VectorOfIntCreate()

        $iArrDecoded_typeSize = UBound($decoded_type)
        For $i = 0 To $iArrDecoded_typeSize - 1
            _VectorOfIntPush($vecDecoded_type, $decoded_type[$i])
        Next
    Else
        $vecDecoded_type = $decoded_type
    EndIf

    Local $bDecoded_typeDllType
    If VarGetType($decoded_type) == "DLLStruct" Then
        $bDecoded_typeDllType = "struct*"
    Else
        $bDecoded_typeDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBarcodeDetectorDecode", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points, $bDecoded_infoDllType, $vecDecoded_info, $bDecoded_typeDllType, $vecDecoded_type), "cveBarcodeDetectorDecode", @error)

    If $bDecoded_typeIsArray Then
        _VectorOfIntRelease($vecDecoded_type)
    EndIf

    If $bDecoded_infoIsArray Then
        _VectorOfCvStringRelease($vecDecoded_info)
    EndIf

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDecode

Func _cveBarcodeDetectorDecodeMat($detector, $matImg, $matPoints, $decoded_info, $decoded_type)
    ; cveBarcodeDetectorDecode using cv::Mat instead of _*Array

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

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $retval = _cveBarcodeDetectorDecode($detector, $iArrImg, $iArrPoints, $decoded_info, $decoded_type)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDecodeMat

Func _cveBarcodeDetectorDetectAndDecode($detector, $img, $decoded_info, $decoded_type, $points)
    ; CVAPI(bool) cveBarcodeDetectorDetectAndDecode(cv::barcode::BarcodeDetector* detector, cv::_InputArray* img, std::vector<cv::String>* decoded_info, std::vector<int>* decoded_type, cv::_OutputArray* points);

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

    Local $vecDecoded_info, $iArrDecoded_infoSize
    Local $bDecoded_infoIsArray = VarGetType($decoded_info) == "Array"

    If $bDecoded_infoIsArray Then
        $vecDecoded_info = _VectorOfCvStringCreate()

        $iArrDecoded_infoSize = UBound($decoded_info)
        For $i = 0 To $iArrDecoded_infoSize - 1
            _VectorOfCvStringPush($vecDecoded_info, $decoded_info[$i])
        Next
    Else
        $vecDecoded_info = $decoded_info
    EndIf

    Local $bDecoded_infoDllType
    If VarGetType($decoded_info) == "DLLStruct" Then
        $bDecoded_infoDllType = "struct*"
    Else
        $bDecoded_infoDllType = "ptr"
    EndIf

    Local $vecDecoded_type, $iArrDecoded_typeSize
    Local $bDecoded_typeIsArray = VarGetType($decoded_type) == "Array"

    If $bDecoded_typeIsArray Then
        $vecDecoded_type = _VectorOfIntCreate()

        $iArrDecoded_typeSize = UBound($decoded_type)
        For $i = 0 To $iArrDecoded_typeSize - 1
            _VectorOfIntPush($vecDecoded_type, $decoded_type[$i])
        Next
    Else
        $vecDecoded_type = $decoded_type
    EndIf

    Local $bDecoded_typeDllType
    If VarGetType($decoded_type) == "DLLStruct" Then
        $bDecoded_typeDllType = "struct*"
    Else
        $bDecoded_typeDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBarcodeDetectorDetectAndDecode", $bDetectorDllType, $detector, $bImgDllType, $img, $bDecoded_infoDllType, $vecDecoded_info, $bDecoded_typeDllType, $vecDecoded_type, $bPointsDllType, $points), "cveBarcodeDetectorDetectAndDecode", @error)

    If $bDecoded_typeIsArray Then
        _VectorOfIntRelease($vecDecoded_type)
    EndIf

    If $bDecoded_infoIsArray Then
        _VectorOfCvStringRelease($vecDecoded_info)
    EndIf

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectAndDecode

Func _cveBarcodeDetectorDetectAndDecodeMat($detector, $matImg, $decoded_info, $decoded_type, $matPoints)
    ; cveBarcodeDetectorDetectAndDecode using cv::Mat instead of _*Array

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

    Local $retval = _cveBarcodeDetectorDetectAndDecode($detector, $iArrImg, $decoded_info, $decoded_type, $oArrPoints)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveOutputArrayRelease($oArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveBarcodeDetectorDetectAndDecodeMat