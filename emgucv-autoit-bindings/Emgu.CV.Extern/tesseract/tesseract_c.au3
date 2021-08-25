#include-once
#include "..\..\CVEUtils.au3"

Func _TesseractGetVersion()
    ; CVAPI(const char*) TesseractGetVersion();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "TesseractGetVersion"), "TesseractGetVersion", @error)
EndFunc   ;==>_TesseractGetVersion

Func _TessBaseAPICreate()
    ; CVAPI(EmguTesseract*) TessBaseAPICreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "TessBaseAPICreate"), "TessBaseAPICreate", @error)
EndFunc   ;==>_TessBaseAPICreate

Func _TessBaseAPIInit($ocr, $dataPath, $language, $mode)
    ; CVAPI(int) TessBaseAPIInit(EmguTesseract* ocr, cv::String* dataPath, cv::String* language, int mode);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $bDataPathIsString = IsString($dataPath)
    If $bDataPathIsString Then
        $dataPath = _cveStringCreateFromStr($dataPath)
    EndIf

    Local $sDataPathDllType
    If IsDllStruct($dataPath) Then
        $sDataPathDllType = "struct*"
    Else
        $sDataPathDllType = "ptr"
    EndIf

    Local $bLanguageIsString = IsString($language)
    If $bLanguageIsString Then
        $language = _cveStringCreateFromStr($language)
    EndIf

    Local $sLanguageDllType
    If IsDllStruct($language) Then
        $sLanguageDllType = "struct*"
    Else
        $sLanguageDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIInit", $sOcrDllType, $ocr, $sDataPathDllType, $dataPath, $sLanguageDllType, $language, "int", $mode), "TessBaseAPIInit", @error)

    If $bLanguageIsString Then
        _cveStringRelease($language)
    EndIf

    If $bDataPathIsString Then
        _cveStringRelease($dataPath)
    EndIf

    Return $retval
EndFunc   ;==>_TessBaseAPIInit

Func _TessBaseAPIRelease($ocr)
    ; CVAPI(void) TessBaseAPIRelease(EmguTesseract** ocr);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    ElseIf $ocr == Null Then
        $sOcrDllType = "ptr"
    Else
        $sOcrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIRelease", $sOcrDllType, $ocr), "TessBaseAPIRelease", @error)
EndFunc   ;==>_TessBaseAPIRelease

Func _TessBaseAPIRecognize($ocr)
    ; CVAPI(int) TessBaseAPIRecognize(EmguTesseract* ocr);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIRecognize", $sOcrDllType, $ocr), "TessBaseAPIRecognize", @error)
EndFunc   ;==>_TessBaseAPIRecognize

Func _TessBaseAPISetImage($ocr, $mat)
    ; CVAPI(void) TessBaseAPISetImage(EmguTesseract* ocr, cv::_InputArray* mat);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPISetImage", $sOcrDllType, $ocr, $sMatDllType, $mat), "TessBaseAPISetImage", @error)
EndFunc   ;==>_TessBaseAPISetImage

Func _TessBaseAPISetImageTyped($ocr, $typeOfMat, $mat)

    Local $iArrMat, $vectorMat, $iArrMatSize
    Local $bMatIsArray = IsArray($mat)
    Local $bMatCreate = IsDllStruct($mat) And $typeOfMat == "Scalar"

    If $typeOfMat == Default Then
        $iArrMat = $mat
    ElseIf $bMatIsArray Then
        $vectorMat = Call("_VectorOf" & $typeOfMat & "Create")

        $iArrMatSize = UBound($mat)
        For $i = 0 To $iArrMatSize - 1
            Call("_VectorOf" & $typeOfMat & "Push", $vectorMat, $mat[$i])
        Next

        $iArrMat = Call("_cveInputArrayFromVectorOf" & $typeOfMat, $vectorMat)
    Else
        If $bMatCreate Then
            $mat = Call("_cve" & $typeOfMat & "Create", $mat)
        EndIf
        $iArrMat = Call("_cveInputArrayFrom" & $typeOfMat, $mat)
    EndIf

    _TessBaseAPISetImage($ocr, $iArrMat)

    If $bMatIsArray Then
        Call("_VectorOf" & $typeOfMat & "Release", $vectorMat)
    EndIf

    If $typeOfMat <> Default Then
        _cveInputArrayRelease($iArrMat)
        If $bMatCreate Then
            Call("_cve" & $typeOfMat & "Release", $mat)
        EndIf
    EndIf
EndFunc   ;==>_TessBaseAPISetImageTyped

Func _TessBaseAPISetImageMat($ocr, $mat)
    ; TessBaseAPISetImage using cv::Mat instead of _*Array
    _TessBaseAPISetImageTyped($ocr, "Mat", $mat)
EndFunc   ;==>_TessBaseAPISetImageMat

Func _TessBaseAPISetImagePix($ocr, $pix)
    ; CVAPI(void) TessBaseAPISetImagePix(EmguTesseract* ocr, Pix* pix);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $sPixDllType
    If IsDllStruct($pix) Then
        $sPixDllType = "struct*"
    Else
        $sPixDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPISetImagePix", $sOcrDllType, $ocr, $sPixDllType, $pix), "TessBaseAPISetImagePix", @error)
EndFunc   ;==>_TessBaseAPISetImagePix

Func _TessBaseAPIGetUTF8Text($ocr, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetUTF8Text(EmguTesseract* ocr, std::vector<unsigned char>* vectorOfByte);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = IsArray($vectorOfByte)

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    Local $sVectorOfByteDllType
    If IsDllStruct($vectorOfByte) Then
        $sVectorOfByteDllType = "struct*"
    Else
        $sVectorOfByteDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetUTF8Text", $sOcrDllType, $ocr, $sVectorOfByteDllType, $vecVectorOfByte), "TessBaseAPIGetUTF8Text", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetUTF8Text

Func _TessBaseAPIGetHOCRText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetHOCRText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = IsArray($vectorOfByte)

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    Local $sVectorOfByteDllType
    If IsDllStruct($vectorOfByte) Then
        $sVectorOfByteDllType = "struct*"
    Else
        $sVectorOfByteDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetHOCRText", $sOcrDllType, $ocr, "int", $pageNumber, $sVectorOfByteDllType, $vecVectorOfByte), "TessBaseAPIGetHOCRText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetHOCRText

Func _TessBaseAPIGetTSVText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetTSVText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = IsArray($vectorOfByte)

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    Local $sVectorOfByteDllType
    If IsDllStruct($vectorOfByte) Then
        $sVectorOfByteDllType = "struct*"
    Else
        $sVectorOfByteDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetTSVText", $sOcrDllType, $ocr, "int", $pageNumber, $sVectorOfByteDllType, $vecVectorOfByte), "TessBaseAPIGetTSVText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetTSVText

Func _TessBaseAPIGetBoxText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetBoxText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = IsArray($vectorOfByte)

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    Local $sVectorOfByteDllType
    If IsDllStruct($vectorOfByte) Then
        $sVectorOfByteDllType = "struct*"
    Else
        $sVectorOfByteDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetBoxText", $sOcrDllType, $ocr, "int", $pageNumber, $sVectorOfByteDllType, $vecVectorOfByte), "TessBaseAPIGetBoxText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetBoxText

Func _TessBaseAPIGetUNLVText($ocr, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetUNLVText(EmguTesseract* ocr, std::vector<unsigned char>* vectorOfByte);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = IsArray($vectorOfByte)

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    Local $sVectorOfByteDllType
    If IsDllStruct($vectorOfByte) Then
        $sVectorOfByteDllType = "struct*"
    Else
        $sVectorOfByteDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetUNLVText", $sOcrDllType, $ocr, $sVectorOfByteDllType, $vecVectorOfByte), "TessBaseAPIGetUNLVText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetUNLVText

Func _TessBaseAPIGetOsdText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetOsdText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = IsArray($vectorOfByte)

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    Local $sVectorOfByteDllType
    If IsDllStruct($vectorOfByte) Then
        $sVectorOfByteDllType = "struct*"
    Else
        $sVectorOfByteDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetOsdText", $sOcrDllType, $ocr, "int", $pageNumber, $sVectorOfByteDllType, $vecVectorOfByte), "TessBaseAPIGetOsdText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetOsdText

Func _TessBaseAPIExtractResult($ocr, $charSeq, $resultSeq)
    ; CVAPI(void) TessBaseAPIExtractResult(EmguTesseract* ocr, std::vector<unsigned char>* charSeq, std::vector<TesseractResult>* resultSeq);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $vecCharSeq, $iArrCharSeqSize
    Local $bCharSeqIsArray = IsArray($charSeq)

    If $bCharSeqIsArray Then
        $vecCharSeq = _VectorOfByteCreate()

        $iArrCharSeqSize = UBound($charSeq)
        For $i = 0 To $iArrCharSeqSize - 1
            _VectorOfBytePush($vecCharSeq, $charSeq[$i])
        Next
    Else
        $vecCharSeq = $charSeq
    EndIf

    Local $sCharSeqDllType
    If IsDllStruct($charSeq) Then
        $sCharSeqDllType = "struct*"
    Else
        $sCharSeqDllType = "ptr"
    EndIf

    Local $vecResultSeq, $iArrResultSeqSize
    Local $bResultSeqIsArray = IsArray($resultSeq)

    If $bResultSeqIsArray Then
        $vecResultSeq = _VectorOfTesseractResultCreate()

        $iArrResultSeqSize = UBound($resultSeq)
        For $i = 0 To $iArrResultSeqSize - 1
            _VectorOfTesseractResultPush($vecResultSeq, $resultSeq[$i])
        Next
    Else
        $vecResultSeq = $resultSeq
    EndIf

    Local $sResultSeqDllType
    If IsDllStruct($resultSeq) Then
        $sResultSeqDllType = "struct*"
    Else
        $sResultSeqDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIExtractResult", $sOcrDllType, $ocr, $sCharSeqDllType, $vecCharSeq, $sResultSeqDllType, $vecResultSeq), "TessBaseAPIExtractResult", @error)

    If $bResultSeqIsArray Then
        _VectorOfTesseractResultRelease($vecResultSeq)
    EndIf

    If $bCharSeqIsArray Then
        _VectorOfByteRelease($vecCharSeq)
    EndIf
EndFunc   ;==>_TessBaseAPIExtractResult

Func _TessBaseAPIProcessPage($ocr, $pix, $pageIndex, $filename, $retryConfig, $timeoutMillisec, $renderer)
    ; CVAPI(bool) TessBaseAPIProcessPage(EmguTesseract* ocr, Pix* pix, int pageIndex, cv::String* filename, cv::String* retryConfig, int timeoutMillisec, tesseract::TessResultRenderer* renderer);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $sPixDllType
    If IsDllStruct($pix) Then
        $sPixDllType = "struct*"
    Else
        $sPixDllType = "ptr"
    EndIf

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

    Local $bRetryConfigIsString = IsString($retryConfig)
    If $bRetryConfigIsString Then
        $retryConfig = _cveStringCreateFromStr($retryConfig)
    EndIf

    Local $sRetryConfigDllType
    If IsDllStruct($retryConfig) Then
        $sRetryConfigDllType = "struct*"
    Else
        $sRetryConfigDllType = "ptr"
    EndIf

    Local $sRendererDllType
    If IsDllStruct($renderer) Then
        $sRendererDllType = "struct*"
    Else
        $sRendererDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "TessBaseAPIProcessPage", $sOcrDllType, $ocr, $sPixDllType, $pix, "int", $pageIndex, $sFilenameDllType, $filename, $sRetryConfigDllType, $retryConfig, "int", $timeoutMillisec, $sRendererDllType, $renderer), "TessBaseAPIProcessPage", @error)

    If $bRetryConfigIsString Then
        _cveStringRelease($retryConfig)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_TessBaseAPIProcessPage

Func _TessBaseAPISetVariable($ocr, $varName, $value)
    ; CVAPI(bool) TessBaseAPISetVariable(EmguTesseract* ocr, const char* varName, const char* value);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $sVarNameDllType
    If IsDllStruct($varName) Then
        $sVarNameDllType = "struct*"
    ElseIf IsPtr($varName) Then
        $sVarNameDllType = "ptr"
    Else
        $sVarNameDllType = "str"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    ElseIf IsPtr($value) Then
        $sValueDllType = "ptr"
    Else
        $sValueDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "TessBaseAPISetVariable", $sOcrDllType, $ocr, $sVarNameDllType, $varName, $sValueDllType, $value), "TessBaseAPISetVariable", @error)
EndFunc   ;==>_TessBaseAPISetVariable

Func _TessBaseAPISetPageSegMode($ocr, $mode)
    ; CVAPI(void) TessBaseAPISetPageSegMode(EmguTesseract* ocr, tesseract::PageSegMode mode);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPISetPageSegMode", $sOcrDllType, $ocr, "int", $mode), "TessBaseAPISetPageSegMode", @error)
EndFunc   ;==>_TessBaseAPISetPageSegMode

Func _TessBaseAPIGetPageSegMode($ocr)
    ; CVAPI(tesseract::PageSegMode) TessBaseAPIGetPageSegMode(EmguTesseract* ocr);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIGetPageSegMode", $sOcrDllType, $ocr), "TessBaseAPIGetPageSegMode", @error)
EndFunc   ;==>_TessBaseAPIGetPageSegMode

Func _TessBaseAPIGetOpenCLDevice($ocr, $device)
    ; CVAPI(int) TessBaseAPIGetOpenCLDevice(EmguTesseract* ocr, void** device);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    ElseIf $device == Null Then
        $sDeviceDllType = "ptr"
    Else
        $sDeviceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIGetOpenCLDevice", $sOcrDllType, $ocr, $sDeviceDllType, $device), "TessBaseAPIGetOpenCLDevice", @error)
EndFunc   ;==>_TessBaseAPIGetOpenCLDevice

Func _TessBaseAPIAnalyseLayout($ocr, $mergeSimilarWords)
    ; CVAPI(tesseract::PageIterator*) TessBaseAPIAnalyseLayout(EmguTesseract* ocr, bool mergeSimilarWords);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "TessBaseAPIAnalyseLayout", $sOcrDllType, $ocr, "boolean", $mergeSimilarWords), "TessBaseAPIAnalyseLayout", @error)
EndFunc   ;==>_TessBaseAPIAnalyseLayout

Func _TessPageIteratorGetOrientation($iterator, $orientation, $writingDirection, $order, $deskewAngle)
    ; CVAPI(void) TessPageIteratorGetOrientation(tesseract::PageIterator* iterator, tesseract::Orientation* orientation, tesseract::WritingDirection* writingDirection, tesseract::TextlineOrder* order, float* deskewAngle);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf

    Local $sOrientationDllType
    If IsDllStruct($orientation) Then
        $sOrientationDllType = "struct*"
    Else
        $sOrientationDllType = "ptr"
    EndIf

    Local $sWritingDirectionDllType
    If IsDllStruct($writingDirection) Then
        $sWritingDirectionDllType = "struct*"
    Else
        $sWritingDirectionDllType = "ptr"
    EndIf

    Local $sOrderDllType
    If IsDllStruct($order) Then
        $sOrderDllType = "struct*"
    Else
        $sOrderDllType = "ptr"
    EndIf

    Local $sDeskewAngleDllType
    If IsDllStruct($deskewAngle) Then
        $sDeskewAngleDllType = "struct*"
    Else
        $sDeskewAngleDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessPageIteratorGetOrientation", $sIteratorDllType, $iterator, $sOrientationDllType, $orientation, $sWritingDirectionDllType, $writingDirection, $sOrderDllType, $order, $sDeskewAngleDllType, $deskewAngle), "TessPageIteratorGetOrientation", @error)
EndFunc   ;==>_TessPageIteratorGetOrientation

Func _TessPageIteratorRelease($iterator)
    ; CVAPI(void) TessPageIteratorRelease(tesseract::PageIterator** iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    ElseIf $iterator == Null Then
        $sIteratorDllType = "ptr"
    Else
        $sIteratorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessPageIteratorRelease", $sIteratorDllType, $iterator), "TessPageIteratorRelease", @error)
EndFunc   ;==>_TessPageIteratorRelease

Func _TessPageIteratorGetBaseLine($iterator, $level, $x1, $y1, $x2, $y2)
    ; CVAPI(bool) TessPageIteratorGetBaseLine(tesseract::PageIterator* iterator, tesseract::PageIteratorLevel level, int* x1, int* y1, int* x2, int* y2);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf

    Local $sX1DllType
    If IsDllStruct($x1) Then
        $sX1DllType = "struct*"
    Else
        $sX1DllType = "int*"
    EndIf

    Local $sY1DllType
    If IsDllStruct($y1) Then
        $sY1DllType = "struct*"
    Else
        $sY1DllType = "int*"
    EndIf

    Local $sX2DllType
    If IsDllStruct($x2) Then
        $sX2DllType = "struct*"
    Else
        $sX2DllType = "int*"
    EndIf

    Local $sY2DllType
    If IsDllStruct($y2) Then
        $sY2DllType = "struct*"
    Else
        $sY2DllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "TessPageIteratorGetBaseLine", $sIteratorDllType, $iterator, "int", $level, $sX1DllType, $x1, $sY1DllType, $y1, $sX2DllType, $x2, $sY2DllType, $y2), "TessPageIteratorGetBaseLine", @error)
EndFunc   ;==>_TessPageIteratorGetBaseLine

Func _TessBaseAPIIsValidWord($ocr, $word)
    ; CVAPI(int) TessBaseAPIIsValidWord(EmguTesseract* ocr, char* word);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf

    Local $sWordDllType
    If IsDllStruct($word) Then
        $sWordDllType = "struct*"
    Else
        $sWordDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIIsValidWord", $sOcrDllType, $ocr, $sWordDllType, $word), "TessBaseAPIIsValidWord", @error)
EndFunc   ;==>_TessBaseAPIIsValidWord

Func _TessBaseAPIGetOem($ocr)
    ; CVAPI(int) TessBaseAPIGetOem(EmguTesseract* ocr);

    Local $sOcrDllType
    If IsDllStruct($ocr) Then
        $sOcrDllType = "struct*"
    Else
        $sOcrDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIGetOem", $sOcrDllType, $ocr), "TessBaseAPIGetOem", @error)
EndFunc   ;==>_TessBaseAPIGetOem

Func _TessPDFRendererCreate($outputbase, $datadir, $textonly, $resultRenderer)
    ; CVAPI(tesseract::TessPDFRenderer*) TessPDFRendererCreate(cv::String* outputbase, cv::String* datadir, bool textonly, tesseract::TessResultRenderer** resultRenderer);

    Local $bOutputbaseIsString = IsString($outputbase)
    If $bOutputbaseIsString Then
        $outputbase = _cveStringCreateFromStr($outputbase)
    EndIf

    Local $sOutputbaseDllType
    If IsDllStruct($outputbase) Then
        $sOutputbaseDllType = "struct*"
    Else
        $sOutputbaseDllType = "ptr"
    EndIf

    Local $bDatadirIsString = IsString($datadir)
    If $bDatadirIsString Then
        $datadir = _cveStringCreateFromStr($datadir)
    EndIf

    Local $sDatadirDllType
    If IsDllStruct($datadir) Then
        $sDatadirDllType = "struct*"
    Else
        $sDatadirDllType = "ptr"
    EndIf

    Local $sResultRendererDllType
    If IsDllStruct($resultRenderer) Then
        $sResultRendererDllType = "struct*"
    ElseIf $resultRenderer == Null Then
        $sResultRendererDllType = "ptr"
    Else
        $sResultRendererDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "TessPDFRendererCreate", $sOutputbaseDllType, $outputbase, $sDatadirDllType, $datadir, "boolean", $textonly, $sResultRendererDllType, $resultRenderer), "TessPDFRendererCreate", @error)

    If $bDatadirIsString Then
        _cveStringRelease($datadir)
    EndIf

    If $bOutputbaseIsString Then
        _cveStringRelease($outputbase)
    EndIf

    Return $retval
EndFunc   ;==>_TessPDFRendererCreate

Func _TessPDFRendererRelease($renderer)
    ; CVAPI(void) TessPDFRendererRelease(tesseract::TessPDFRenderer** renderer);

    Local $sRendererDllType
    If IsDllStruct($renderer) Then
        $sRendererDllType = "struct*"
    ElseIf $renderer == Null Then
        $sRendererDllType = "ptr"
    Else
        $sRendererDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessPDFRendererRelease", $sRendererDllType, $renderer), "TessPDFRendererRelease", @error)
EndFunc   ;==>_TessPDFRendererRelease

Func _leptCreatePixFromMat($m)
    ; CVAPI(Pix*) leptCreatePixFromMat(cv::Mat* m);

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "leptCreatePixFromMat", $sMDllType, $m), "leptCreatePixFromMat", @error)
EndFunc   ;==>_leptCreatePixFromMat

Func _leptPixDestroy($pix)
    ; CVAPI(void) leptPixDestroy(Pix** pix);

    Local $sPixDllType
    If IsDllStruct($pix) Then
        $sPixDllType = "struct*"
    ElseIf $pix == Null Then
        $sPixDllType = "ptr"
    Else
        $sPixDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "leptPixDestroy", $sPixDllType, $pix), "leptPixDestroy", @error)
EndFunc   ;==>_leptPixDestroy

Func _stdSetlocale($category, $locale)
    ; CVAPI(char*) stdSetlocale(int category, char* locale);

    Local $sLocaleDllType
    If IsDllStruct($locale) Then
        $sLocaleDllType = "struct*"
    Else
        $sLocaleDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "stdSetlocale", "int", $category, $sLocaleDllType, $locale), "stdSetlocale", @error)
EndFunc   ;==>_stdSetlocale