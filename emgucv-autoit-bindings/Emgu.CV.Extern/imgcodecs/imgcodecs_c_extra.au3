#include-once
#include "..\..\CVEUtils.au3"

Func _cveHaveImageReader($filename)
    ; CVAPI(bool) cveHaveImageReader(cv::String* filename);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHaveImageReader", "ptr", $filename), "cveHaveImageReader", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveHaveImageReader

Func _cveHaveImageWriter($filename)
    ; CVAPI(bool) cveHaveImageWriter(cv::String* filename);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHaveImageWriter", "ptr", $filename), "cveHaveImageWriter", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveHaveImageWriter

Func _cveImwrite($filename, $img, $params = _VectorOfIntCreate())
    ; CVAPI(bool) cveImwrite(cv::String* filename, cv::_InputArray* img, std::vector<int>* params);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $vecParams, $iArrParamsSize
    Local $bParamsIsArray = VarGetType($params) == "Array"

    If $bParamsIsArray Then
        $vecParams = _VectorOfIntCreate()

        $iArrParamsSize = UBound($params)
        For $i = 0 To $iArrParamsSize - 1
            _VectorOfIntPush($vecParams, $params[$i])
        Next
    Else
        $vecParams = $params
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImwrite", "ptr", $filename, "ptr", $img, "ptr", $vecParams), "cveImwrite", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveImwrite

Func _cveImwriteMat($filename, $matImg, $params = _VectorOfIntCreate())
    ; cveImwrite using cv::Mat instead of _*Array

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

    Local $retval = _cveImwrite($filename, $iArrImg, $params)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveImwriteMat

Func _cveImwritemulti($filename, $img, $params)
    ; CVAPI(bool) cveImwritemulti(cv::String* filename, cv::_InputArray* img, std::vector<int>* params);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $vecParams, $iArrParamsSize
    Local $bParamsIsArray = VarGetType($params) == "Array"

    If $bParamsIsArray Then
        $vecParams = _VectorOfIntCreate()

        $iArrParamsSize = UBound($params)
        For $i = 0 To $iArrParamsSize - 1
            _VectorOfIntPush($vecParams, $params[$i])
        Next
    Else
        $vecParams = $params
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImwritemulti", "ptr", $filename, "ptr", $img, "ptr", $vecParams), "cveImwritemulti", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveImwritemulti

Func _cveImwritemultiMat($filename, $matImg, $params)
    ; cveImwritemulti using cv::Mat instead of _*Array

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

    Local $retval = _cveImwritemulti($filename, $iArrImg, $params)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveImwritemultiMat

Func _cveImread($fileName, $flags = $CV_IMREAD_COLOR, $result = Null)
    ; CVAPI(void) cveImread(cv::String* fileName, int flags, cv::Mat* result = Null);

    If $result == Null Then
        $result = _cveMatCreate()
    EndIf

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImread", "ptr", $fileName, "int", $flags, "ptr", $result), "cveImread", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $result
EndFunc   ;==>_cveImread

Func _cveImreadmulti($filename, $mats, $flags = $CV_IMREAD_ANYCOLOR)
    ; CVAPI(bool) cveImreadmulti(const cv::String* filename, std::vector<cv::Mat>* mats, int flags);

    Local $vecMats, $iArrMatsSize
    Local $bMatsIsArray = VarGetType($mats) == "Array"

    If $bMatsIsArray Then
        $vecMats = _VectorOfMatCreate()

        $iArrMatsSize = UBound($mats)
        For $i = 0 To $iArrMatsSize - 1
            _VectorOfMatPush($vecMats, $mats[$i])
        Next
    Else
        $vecMats = $mats
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImreadmulti", "ptr", $filename, "ptr", $vecMats, "int", $flags), "cveImreadmulti", @error)

    If $bMatsIsArray Then
        _VectorOfMatRelease($vecMats)
    EndIf

    Return $retval
EndFunc   ;==>_cveImreadmulti

Func _cveImdecode($buf, $flags, $dst)
    ; CVAPI(void) cveImdecode(cv::_InputArray* buf, int flags, cv::Mat* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImdecode", "ptr", $buf, "int", $flags, "ptr", $dst), "cveImdecode", @error)
EndFunc   ;==>_cveImdecode

Func _cveImdecodeMat($matBuf, $flags, $dst)
    ; cveImdecode using cv::Mat instead of _*Array

    Local $iArrBuf, $vectorOfMatBuf, $iArrBufSize
    Local $bBufIsArray = VarGetType($matBuf) == "Array"

    If $bBufIsArray Then
        $vectorOfMatBuf = _VectorOfMatCreate()

        $iArrBufSize = UBound($matBuf)
        For $i = 0 To $iArrBufSize - 1
            _VectorOfMatPush($vectorOfMatBuf, $matBuf[$i])
        Next

        $iArrBuf = _cveInputArrayFromVectorOfMat($vectorOfMatBuf)
    Else
        $iArrBuf = _cveInputArrayFromMat($matBuf)
    EndIf

    _cveImdecode($iArrBuf, $flags, $dst)

    If $bBufIsArray Then
        _VectorOfMatRelease($vectorOfMatBuf)
    EndIf

    _cveInputArrayRelease($iArrBuf)
EndFunc   ;==>_cveImdecodeMat

Func _cveImencode($ext, $img, $buf, $params = _VectorOfIntCreate())
    ; CVAPI(bool) cveImencode(cv::String* ext, cv::_InputArray* img, std::vector< unsigned char >* buf, std::vector< int >* params);

    Local $bExtIsString = VarGetType($ext) == "String"
    If $bExtIsString Then
        $ext = _cveStringCreateFromStr($ext)
    EndIf

    Local $vecBuf, $iArrBufSize
    Local $bBufIsArray = VarGetType($buf) == "Array"

    If $bBufIsArray Then
        $vecBuf = _VectorOfByteCreate()

        $iArrBufSize = UBound($buf)
        For $i = 0 To $iArrBufSize - 1
            _VectorOfBytePush($vecBuf, $buf[$i])
        Next
    Else
        $vecBuf = $buf
    EndIf

    Local $vecParams, $iArrParamsSize
    Local $bParamsIsArray = VarGetType($params) == "Array"

    If $bParamsIsArray Then
        $vecParams = _VectorOfIntCreate()

        $iArrParamsSize = UBound($params)
        For $i = 0 To $iArrParamsSize - 1
            _VectorOfIntPush($vecParams, $params[$i])
        Next
    Else
        $vecParams = $params
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImencode", "ptr", $ext, "ptr", $img, "ptr", $vecBuf, "ptr", $vecParams), "cveImencode", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bBufIsArray Then
        _VectorOfByteRelease($vecBuf)
    EndIf

    If $bExtIsString Then
        _cveStringRelease($ext)
    EndIf

    Return $retval
EndFunc   ;==>_cveImencode

Func _cveImencodeMat($ext, $matImg, $buf, $params = _VectorOfIntCreate())
    ; cveImencode using cv::Mat instead of _*Array

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

    Local $retval = _cveImencode($ext, $iArrImg, $buf, $params)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveImencodeMat