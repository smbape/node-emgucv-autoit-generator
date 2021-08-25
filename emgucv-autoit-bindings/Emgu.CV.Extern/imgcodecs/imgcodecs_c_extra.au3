#include-once
#include "..\..\CVEUtils.au3"

Func _cveHaveImageReader($filename)
    ; CVAPI(bool) cveHaveImageReader(cv::String* filename);

    Local $bFilenameIsString = IsString($filename)
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHaveImageReader", $sFilenameDllType, $filename), "cveHaveImageReader", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveHaveImageReader

Func _cveHaveImageWriter($filename)
    ; CVAPI(bool) cveHaveImageWriter(cv::String* filename);

    Local $bFilenameIsString = IsString($filename)
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHaveImageWriter", $sFilenameDllType, $filename), "cveHaveImageWriter", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveHaveImageWriter

Func _cveImwrite($filename, $img, $params = _VectorOfIntCreate())
    ; CVAPI(bool) cveImwrite(cv::String* filename, cv::_InputArray* img, std::vector<int>* params);

    Local $bFilenameIsString = IsString($filename)
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecParams, $iArrParamsSize
    Local $bParamsIsArray = IsArray($params)

    If $bParamsIsArray Then
        $vecParams = _VectorOfIntCreate()

        $iArrParamsSize = UBound($params)
        For $i = 0 To $iArrParamsSize - 1
            _VectorOfIntPush($vecParams, $params[$i])
        Next
    Else
        $vecParams = $params
    EndIf

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    Else
        $sParamsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImwrite", $sFilenameDllType, $filename, $sImgDllType, $img, $sParamsDllType, $vecParams), "cveImwrite", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveImwrite

Func _cveImwriteTyped($filename, $typeOfImg, $img, $params = _VectorOfIntCreate())

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

    Local $retval = _cveImwrite($filename, $iArrImg, $params)

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
EndFunc   ;==>_cveImwriteTyped

Func _cveImwriteMat($filename, $img, $params = _VectorOfIntCreate())
    ; cveImwrite using cv::Mat instead of _*Array
    Local $retval = _cveImwriteTyped($filename, "Mat", $img, $params)

    Return $retval
EndFunc   ;==>_cveImwriteMat

Func _cveImwritemulti($filename, $img, $params)
    ; CVAPI(bool) cveImwritemulti(cv::String* filename, cv::_InputArray* img, std::vector<int>* params);

    Local $bFilenameIsString = IsString($filename)
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecParams, $iArrParamsSize
    Local $bParamsIsArray = IsArray($params)

    If $bParamsIsArray Then
        $vecParams = _VectorOfIntCreate()

        $iArrParamsSize = UBound($params)
        For $i = 0 To $iArrParamsSize - 1
            _VectorOfIntPush($vecParams, $params[$i])
        Next
    Else
        $vecParams = $params
    EndIf

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    Else
        $sParamsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImwritemulti", $sFilenameDllType, $filename, $sImgDllType, $img, $sParamsDllType, $vecParams), "cveImwritemulti", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveImwritemulti

Func _cveImwritemultiTyped($filename, $typeOfImg, $img, $params)

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

    Local $retval = _cveImwritemulti($filename, $iArrImg, $params)

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
EndFunc   ;==>_cveImwritemultiTyped

Func _cveImwritemultiMat($filename, $img, $params)
    ; cveImwritemulti using cv::Mat instead of _*Array
    Local $retval = _cveImwritemultiTyped($filename, "Mat", $img, $params)

    Return $retval
EndFunc   ;==>_cveImwritemultiMat

Func _cveImread($fileName, $flags = $CV_IMREAD_COLOR, $result = Null)
    ; CVAPI(void) cveImread(cv::String* fileName, int flags, cv::Mat* result = Null);

    If $result == Null Then
        $result = _cveMatCreate()
    EndIf

    Local $bFileNameIsString = IsString($fileName)
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImread", $sFileNameDllType, $fileName, "int", $flags, $sResultDllType, $result), "cveImread", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $result
EndFunc   ;==>_cveImread

Func _cveImreadmulti($filename, $mats, $flags = $CV_IMREAD_ANYCOLOR)
    ; CVAPI(bool) cveImreadmulti(const cv::String* filename, std::vector<cv::Mat>* mats, int flags);

    Local $bFilenameIsString = IsString($filename)
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    Local $vecMats, $iArrMatsSize
    Local $bMatsIsArray = IsArray($mats)

    If $bMatsIsArray Then
        $vecMats = _VectorOfMatCreate()

        $iArrMatsSize = UBound($mats)
        For $i = 0 To $iArrMatsSize - 1
            _VectorOfMatPush($vecMats, $mats[$i])
        Next
    Else
        $vecMats = $mats
    EndIf

    Local $sMatsDllType
    If IsDllStruct($mats) Then
        $sMatsDllType = "struct*"
    Else
        $sMatsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImreadmulti", $sFilenameDllType, $filename, $sMatsDllType, $vecMats, "int", $flags), "cveImreadmulti", @error)

    If $bMatsIsArray Then
        _VectorOfMatRelease($vecMats)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveImreadmulti

Func _cveImdecode($buf, $flags, $dst)
    ; CVAPI(void) cveImdecode(cv::_InputArray* buf, int flags, cv::Mat* dst);

    Local $sBufDllType
    If IsDllStruct($buf) Then
        $sBufDllType = "struct*"
    Else
        $sBufDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImdecode", $sBufDllType, $buf, "int", $flags, $sDstDllType, $dst), "cveImdecode", @error)
EndFunc   ;==>_cveImdecode

Func _cveImdecodeTyped($typeOfBuf, $buf, $flags, $dst)

    Local $iArrBuf, $vectorBuf, $iArrBufSize
    Local $bBufIsArray = IsArray($buf)
    Local $bBufCreate = IsDllStruct($buf) And $typeOfBuf == "Scalar"

    If $typeOfBuf == Default Then
        $iArrBuf = $buf
    ElseIf $bBufIsArray Then
        $vectorBuf = Call("_VectorOf" & $typeOfBuf & "Create")

        $iArrBufSize = UBound($buf)
        For $i = 0 To $iArrBufSize - 1
            Call("_VectorOf" & $typeOfBuf & "Push", $vectorBuf, $buf[$i])
        Next

        $iArrBuf = Call("_cveInputArrayFromVectorOf" & $typeOfBuf, $vectorBuf)
    Else
        If $bBufCreate Then
            $buf = Call("_cve" & $typeOfBuf & "Create", $buf)
        EndIf
        $iArrBuf = Call("_cveInputArrayFrom" & $typeOfBuf, $buf)
    EndIf

    _cveImdecode($iArrBuf, $flags, $dst)

    If $bBufIsArray Then
        Call("_VectorOf" & $typeOfBuf & "Release", $vectorBuf)
    EndIf

    If $typeOfBuf <> Default Then
        _cveInputArrayRelease($iArrBuf)
        If $bBufCreate Then
            Call("_cve" & $typeOfBuf & "Release", $buf)
        EndIf
    EndIf
EndFunc   ;==>_cveImdecodeTyped

Func _cveImdecodeMat($buf, $flags, $dst)
    ; cveImdecode using cv::Mat instead of _*Array
    _cveImdecodeTyped("Mat", $buf, $flags, $dst)
EndFunc   ;==>_cveImdecodeMat

Func _cveImencode($ext, $img, $buf, $params = _VectorOfIntCreate())
    ; CVAPI(bool) cveImencode(cv::String* ext, cv::_InputArray* img, std::vector<unsigned char>* buf, std::vector<int>* params);

    Local $bExtIsString = IsString($ext)
    If $bExtIsString Then
        $ext = _cveStringCreateFromStr($ext)
    EndIf

    Local $sExtDllType
    If IsDllStruct($ext) Then
        $sExtDllType = "struct*"
    Else
        $sExtDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecBuf, $iArrBufSize
    Local $bBufIsArray = IsArray($buf)

    If $bBufIsArray Then
        $vecBuf = _VectorOfByteCreate()

        $iArrBufSize = UBound($buf)
        For $i = 0 To $iArrBufSize - 1
            _VectorOfBytePush($vecBuf, $buf[$i])
        Next
    Else
        $vecBuf = $buf
    EndIf

    Local $sBufDllType
    If IsDllStruct($buf) Then
        $sBufDllType = "struct*"
    Else
        $sBufDllType = "ptr"
    EndIf

    Local $vecParams, $iArrParamsSize
    Local $bParamsIsArray = IsArray($params)

    If $bParamsIsArray Then
        $vecParams = _VectorOfIntCreate()

        $iArrParamsSize = UBound($params)
        For $i = 0 To $iArrParamsSize - 1
            _VectorOfIntPush($vecParams, $params[$i])
        Next
    Else
        $vecParams = $params
    EndIf

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    Else
        $sParamsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveImencode", $sExtDllType, $ext, $sImgDllType, $img, $sBufDllType, $vecBuf, $sParamsDllType, $vecParams), "cveImencode", @error)

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

Func _cveImencodeTyped($ext, $typeOfImg, $img, $buf, $params = _VectorOfIntCreate())

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

    Local $retval = _cveImencode($ext, $iArrImg, $buf, $params)

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
EndFunc   ;==>_cveImencodeTyped

Func _cveImencodeMat($ext, $img, $buf, $params = _VectorOfIntCreate())
    ; cveImencode using cv::Mat instead of _*Array
    Local $retval = _cveImencodeTyped($ext, "Mat", $img, $buf, $params)

    Return $retval
EndFunc   ;==>_cveImencodeMat