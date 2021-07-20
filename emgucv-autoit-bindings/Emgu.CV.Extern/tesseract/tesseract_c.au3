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

    Local $bDataPathIsString = VarGetType($dataPath) == "String"
    If $bDataPathIsString Then
        $dataPath = _cveStringCreateFromStr($dataPath)
    EndIf

    Local $bLanguageIsString = VarGetType($language) == "String"
    If $bLanguageIsString Then
        $language = _cveStringCreateFromStr($language)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIInit", "struct*", $ocr, "ptr", $dataPath, "ptr", $language, "int", $mode), "TessBaseAPIInit", @error)

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

    Local $bOcrDllType
    If VarGetType($ocr) == "DLLStruct" Then
        $bOcrDllType = "struct*"
    Else
        $bOcrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIRelease", $bOcrDllType, $ocr), "TessBaseAPIRelease", @error)
EndFunc   ;==>_TessBaseAPIRelease

Func _TessBaseAPIRecognize($ocr)
    ; CVAPI(int) TessBaseAPIRecognize(EmguTesseract* ocr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIRecognize", "struct*", $ocr), "TessBaseAPIRecognize", @error)
EndFunc   ;==>_TessBaseAPIRecognize

Func _TessBaseAPISetImage($ocr, $mat)
    ; CVAPI(void) TessBaseAPISetImage(EmguTesseract* ocr, cv::_InputArray* mat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPISetImage", "struct*", $ocr, "ptr", $mat), "TessBaseAPISetImage", @error)
EndFunc   ;==>_TessBaseAPISetImage

Func _TessBaseAPISetImageMat($ocr, $matMat)
    ; TessBaseAPISetImage using cv::Mat instead of _*Array

    Local $iArrMat, $vectorOfMatMat, $iArrMatSize
    Local $bMatIsArray = VarGetType($matMat) == "Array"

    If $bMatIsArray Then
        $vectorOfMatMat = _VectorOfMatCreate()

        $iArrMatSize = UBound($matMat)
        For $i = 0 To $iArrMatSize - 1
            _VectorOfMatPush($vectorOfMatMat, $matMat[$i])
        Next

        $iArrMat = _cveInputArrayFromVectorOfMat($vectorOfMatMat)
    Else
        $iArrMat = _cveInputArrayFromMat($matMat)
    EndIf

    _TessBaseAPISetImage($ocr, $iArrMat)

    If $bMatIsArray Then
        _VectorOfMatRelease($vectorOfMatMat)
    EndIf

    _cveInputArrayRelease($iArrMat)
EndFunc   ;==>_TessBaseAPISetImageMat

Func _TessBaseAPISetImagePix($ocr, $pix)
    ; CVAPI(void) TessBaseAPISetImagePix(EmguTesseract* ocr, Pix* pix);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPISetImagePix", "struct*", $ocr, "struct*", $pix), "TessBaseAPISetImagePix", @error)
EndFunc   ;==>_TessBaseAPISetImagePix

Func _TessBaseAPIGetUTF8Text($ocr, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetUTF8Text(EmguTesseract* ocr, std::vector<unsigned char>* vectorOfByte);

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = VarGetType($vectorOfByte) == "Array"

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetUTF8Text", "struct*", $ocr, "ptr", $vecVectorOfByte), "TessBaseAPIGetUTF8Text", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetUTF8Text

Func _TessBaseAPIGetHOCRText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetHOCRText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = VarGetType($vectorOfByte) == "Array"

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetHOCRText", "struct*", $ocr, "int", $pageNumber, "ptr", $vecVectorOfByte), "TessBaseAPIGetHOCRText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetHOCRText

Func _TessBaseAPIGetTSVText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetTSVText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = VarGetType($vectorOfByte) == "Array"

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetTSVText", "struct*", $ocr, "int", $pageNumber, "ptr", $vecVectorOfByte), "TessBaseAPIGetTSVText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetTSVText

Func _TessBaseAPIGetBoxText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetBoxText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = VarGetType($vectorOfByte) == "Array"

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetBoxText", "struct*", $ocr, "int", $pageNumber, "ptr", $vecVectorOfByte), "TessBaseAPIGetBoxText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetBoxText

Func _TessBaseAPIGetUNLVText($ocr, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetUNLVText(EmguTesseract* ocr, std::vector<unsigned char>* vectorOfByte);

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = VarGetType($vectorOfByte) == "Array"

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetUNLVText", "struct*", $ocr, "ptr", $vecVectorOfByte), "TessBaseAPIGetUNLVText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetUNLVText

Func _TessBaseAPIGetOsdText($ocr, $pageNumber, $vectorOfByte)
    ; CVAPI(void) TessBaseAPIGetOsdText(EmguTesseract* ocr, int pageNumber, std::vector<unsigned char>* vectorOfByte);

    Local $vecVectorOfByte, $iArrVectorOfByteSize
    Local $bVectorOfByteIsArray = VarGetType($vectorOfByte) == "Array"

    If $bVectorOfByteIsArray Then
        $vecVectorOfByte = _VectorOfByteCreate()

        $iArrVectorOfByteSize = UBound($vectorOfByte)
        For $i = 0 To $iArrVectorOfByteSize - 1
            _VectorOfBytePush($vecVectorOfByte, $vectorOfByte[$i])
        Next
    Else
        $vecVectorOfByte = $vectorOfByte
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIGetOsdText", "struct*", $ocr, "int", $pageNumber, "ptr", $vecVectorOfByte), "TessBaseAPIGetOsdText", @error)

    If $bVectorOfByteIsArray Then
        _VectorOfByteRelease($vecVectorOfByte)
    EndIf
EndFunc   ;==>_TessBaseAPIGetOsdText

Func _TessBaseAPIExtractResult($ocr, $charSeq, $resultSeq)
    ; CVAPI(void) TessBaseAPIExtractResult(EmguTesseract* ocr, std::vector<unsigned char>* charSeq, std::vector<TesseractResult>* resultSeq);

    Local $vecCharSeq, $iArrCharSeqSize
    Local $bCharSeqIsArray = VarGetType($charSeq) == "Array"

    If $bCharSeqIsArray Then
        $vecCharSeq = _VectorOfByteCreate()

        $iArrCharSeqSize = UBound($charSeq)
        For $i = 0 To $iArrCharSeqSize - 1
            _VectorOfBytePush($vecCharSeq, $charSeq[$i])
        Next
    Else
        $vecCharSeq = $charSeq
    EndIf

    Local $vecResultSeq, $iArrResultSeqSize
    Local $bResultSeqIsArray = VarGetType($resultSeq) == "Array"

    If $bResultSeqIsArray Then
        $vecResultSeq = _VectorOfTesseractResultCreate()

        $iArrResultSeqSize = UBound($resultSeq)
        For $i = 0 To $iArrResultSeqSize - 1
            _VectorOfTesseractResultPush($vecResultSeq, $resultSeq[$i])
        Next
    Else
        $vecResultSeq = $resultSeq
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPIExtractResult", "struct*", $ocr, "ptr", $vecCharSeq, "ptr", $vecResultSeq), "TessBaseAPIExtractResult", @error)

    If $bResultSeqIsArray Then
        _VectorOfTesseractResultRelease($vecResultSeq)
    EndIf

    If $bCharSeqIsArray Then
        _VectorOfByteRelease($vecCharSeq)
    EndIf
EndFunc   ;==>_TessBaseAPIExtractResult

Func _TessBaseAPIProcessPage($ocr, $pix, $pageIndex, $filename, $retryConfig, $timeoutMillisec, $renderer)
    ; CVAPI(bool) TessBaseAPIProcessPage(EmguTesseract* ocr, Pix* pix, int pageIndex, cv::String* filename, cv::String* retryConfig, int timeoutMillisec, tesseract::TessResultRenderer* renderer);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $bRetryConfigIsString = VarGetType($retryConfig) == "String"
    If $bRetryConfigIsString Then
        $retryConfig = _cveStringCreateFromStr($retryConfig)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "TessBaseAPIProcessPage", "struct*", $ocr, "struct*", $pix, "int", $pageIndex, "ptr", $filename, "ptr", $retryConfig, "int", $timeoutMillisec, "ptr", $renderer), "TessBaseAPIProcessPage", @error)

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "TessBaseAPISetVariable", "struct*", $ocr, "str", $varName, "str", $value), "TessBaseAPISetVariable", @error)
EndFunc   ;==>_TessBaseAPISetVariable

Func _TessBaseAPISetPageSegMode($ocr, $mode)
    ; CVAPI(void) TessBaseAPISetPageSegMode(EmguTesseract* ocr, tesseract::PageSegMode mode);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessBaseAPISetPageSegMode", "struct*", $ocr, "tesseract::PageSegMode", $mode), "TessBaseAPISetPageSegMode", @error)
EndFunc   ;==>_TessBaseAPISetPageSegMode

Func _TessBaseAPIGetPageSegMode($ocr)
    ; CVAPI(tesseract::PageSegMode) TessBaseAPIGetPageSegMode(EmguTesseract* ocr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "tesseract::PageSegMode:cdecl", "TessBaseAPIGetPageSegMode", "struct*", $ocr), "TessBaseAPIGetPageSegMode", @error)
EndFunc   ;==>_TessBaseAPIGetPageSegMode

Func _TessBaseAPIGetOpenCLDevice($ocr, $device)
    ; CVAPI(int) TessBaseAPIGetOpenCLDevice(EmguTesseract* ocr, void ** device);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIGetOpenCLDevice", "struct*", $ocr, $bDeviceDllType, $device), "TessBaseAPIGetOpenCLDevice", @error)
EndFunc   ;==>_TessBaseAPIGetOpenCLDevice

Func _TessBaseAPIAnalyseLayout($ocr, $mergeSimilarWords)
    ; CVAPI(tesseract::PageIterator*) TessBaseAPIAnalyseLayout(EmguTesseract* ocr, bool mergeSimilarWords);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "TessBaseAPIAnalyseLayout", "struct*", $ocr, "boolean", $mergeSimilarWords), "TessBaseAPIAnalyseLayout", @error)
EndFunc   ;==>_TessBaseAPIAnalyseLayout

Func _TessPageIteratorGetOrientation($iterator, $orientation, $writingDirection, $order, $deskewAngle)
    ; CVAPI(void) TessPageIteratorGetOrientation(tesseract::PageIterator* iterator, tesseract::Orientation* orientation, tesseract::WritingDirection* writingDirection, tesseract::TextlineOrder* order, float* deskewAngle);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessPageIteratorGetOrientation", "ptr", $iterator, "ptr", $orientation, "ptr", $writingDirection, "ptr", $order, "struct*", $deskewAngle), "TessPageIteratorGetOrientation", @error)
EndFunc   ;==>_TessPageIteratorGetOrientation

Func _TessPageIteratorRelease($iterator)
    ; CVAPI(void) TessPageIteratorRelease(tesseract::PageIterator** iterator);

    Local $bIteratorDllType
    If VarGetType($iterator) == "DLLStruct" Then
        $bIteratorDllType = "struct*"
    Else
        $bIteratorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessPageIteratorRelease", $bIteratorDllType, $iterator), "TessPageIteratorRelease", @error)
EndFunc   ;==>_TessPageIteratorRelease

Func _TessPageIteratorGetBaseLine($iterator, $level, $x1, $y1, $x2, $y2)
    ; CVAPI(bool) TessPageIteratorGetBaseLine(tesseract::PageIterator* iterator, tesseract::PageIteratorLevel level, int* x1, int* y1, int* x2, int* y2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "TessPageIteratorGetBaseLine", "ptr", $iterator, "tesseract::PageIteratorLevel", $level, "struct*", $x1, "struct*", $y1, "struct*", $x2, "struct*", $y2), "TessPageIteratorGetBaseLine", @error)
EndFunc   ;==>_TessPageIteratorGetBaseLine

Func _TessBaseAPIIsValidWord($ocr, $word)
    ; CVAPI(int) TessBaseAPIIsValidWord(EmguTesseract* ocr, char* word);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIIsValidWord", "struct*", $ocr, "struct*", $word), "TessBaseAPIIsValidWord", @error)
EndFunc   ;==>_TessBaseAPIIsValidWord

Func _TessBaseAPIGetOem($ocr)
    ; CVAPI(int) TessBaseAPIGetOem(EmguTesseract* ocr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "TessBaseAPIGetOem", "struct*", $ocr), "TessBaseAPIGetOem", @error)
EndFunc   ;==>_TessBaseAPIGetOem

Func _TessPDFRendererCreate($outputbase, $datadir, $textonly, $resultRenderer)
    ; CVAPI(tesseract::TessPDFRenderer*) TessPDFRendererCreate(cv::String* outputbase, cv::String* datadir, bool textonly, tesseract::TessResultRenderer** resultRenderer);

    Local $bOutputbaseIsString = VarGetType($outputbase) == "String"
    If $bOutputbaseIsString Then
        $outputbase = _cveStringCreateFromStr($outputbase)
    EndIf

    Local $bDatadirIsString = VarGetType($datadir) == "String"
    If $bDatadirIsString Then
        $datadir = _cveStringCreateFromStr($datadir)
    EndIf

    Local $bResultRendererDllType
    If VarGetType($resultRenderer) == "DLLStruct" Then
        $bResultRendererDllType = "struct*"
    Else
        $bResultRendererDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "TessPDFRendererCreate", "ptr", $outputbase, "ptr", $datadir, "boolean", $textonly, $bResultRendererDllType, $resultRenderer), "TessPDFRendererCreate", @error)

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

    Local $bRendererDllType
    If VarGetType($renderer) == "DLLStruct" Then
        $bRendererDllType = "struct*"
    Else
        $bRendererDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "TessPDFRendererRelease", $bRendererDllType, $renderer), "TessPDFRendererRelease", @error)
EndFunc   ;==>_TessPDFRendererRelease

Func _leptCreatePixFromMat($m)
    ; CVAPI(Pix*) leptCreatePixFromMat(cv::Mat* m);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "leptCreatePixFromMat", "ptr", $m), "leptCreatePixFromMat", @error)
EndFunc   ;==>_leptCreatePixFromMat

Func _leptPixDestroy($pix)
    ; CVAPI(void) leptPixDestroy(Pix** pix);

    Local $bPixDllType
    If VarGetType($pix) == "DLLStruct" Then
        $bPixDllType = "struct*"
    Else
        $bPixDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "leptPixDestroy", $bPixDllType, $pix), "leptPixDestroy", @error)
EndFunc   ;==>_leptPixDestroy

Func _stdSetlocale($category, $locale)
    ; CVAPI(char*) stdSetlocale(int category, char* locale);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "stdSetlocale", "int", $category, "struct*", $locale), "stdSetlocale", @error)
EndFunc   ;==>_stdSetlocale