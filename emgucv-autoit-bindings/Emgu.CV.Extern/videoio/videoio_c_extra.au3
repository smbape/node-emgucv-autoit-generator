#include-once
#include "..\..\CVEUtils.au3"

Func _OpenniGetColorPoints($capture, $points, $mask)
    ; CVAPI(void) OpenniGetColorPoints(CvCapture* capture, std::vector<ColorPoint>* points, IplImage* mask);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $vecPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($points) == "Array"

    If $bPointsIsArray Then
        $vecPoints = _VectorOfColorPointCreate()

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfColorPointPush($vecPoints, $points[$i])
        Next
    Else
        $vecPoints = $points
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "OpenniGetColorPoints", $bCaptureDllType, $capture, $bPointsDllType, $vecPoints, $bMaskDllType, $mask), "OpenniGetColorPoints", @error)

    If $bPointsIsArray Then
        _VectorOfColorPointRelease($vecPoints)
    EndIf
EndFunc   ;==>_OpenniGetColorPoints

Func _cveVideoCaptureCreateFromDevice($device, $apiPreference, $params)
    ; CVAPI(cv::VideoCapture*) cveVideoCaptureCreateFromDevice(int device, int apiPreference, std::vector< int >* params);

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

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoCaptureCreateFromDevice", "int", $device, "int", $apiPreference, $bParamsDllType, $vecParams), "cveVideoCaptureCreateFromDevice", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoCaptureCreateFromDevice

Func _cveVideoCaptureCreateFromFile($fileName, $apiPreference, $params)
    ; CVAPI(cv::VideoCapture*) cveVideoCaptureCreateFromFile(cv::String* fileName, int apiPreference, std::vector< int >* params);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $bFileNameDllType
    If VarGetType($fileName) == "DLLStruct" Then
        $bFileNameDllType = "struct*"
    Else
        $bFileNameDllType = "ptr"
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

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoCaptureCreateFromFile", $bFileNameDllType, $fileName, "int", $apiPreference, $bParamsDllType, $vecParams), "cveVideoCaptureCreateFromFile", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoCaptureCreateFromFile

Func _cveVideoCaptureRelease($capture)
    ; CVAPI(void) cveVideoCaptureRelease(cv::VideoCapture** capture);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureRelease", $bCaptureDllType, $capture), "cveVideoCaptureRelease", @error)
EndFunc   ;==>_cveVideoCaptureRelease

Func _cveVideoCaptureSet($capture, $propId, $value)
    ; CVAPI(bool) cveVideoCaptureSet(cv::VideoCapture* capture, int propId, double value);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureSet", $bCaptureDllType, $capture, "int", $propId, "double", $value), "cveVideoCaptureSet", @error)
EndFunc   ;==>_cveVideoCaptureSet

Func _cveVideoCaptureGet($capture, $propId)
    ; CVAPI(double) cveVideoCaptureGet(cv::VideoCapture* capture, int propId);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveVideoCaptureGet", $bCaptureDllType, $capture, "int", $propId), "cveVideoCaptureGet", @error)
EndFunc   ;==>_cveVideoCaptureGet

Func _cveVideoCaptureGrab($capture)
    ; CVAPI(bool) cveVideoCaptureGrab(cv::VideoCapture* capture);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureGrab", $bCaptureDllType, $capture), "cveVideoCaptureGrab", @error)
EndFunc   ;==>_cveVideoCaptureGrab

Func _cveVideoCaptureRetrieve($capture, $image, $flag)
    ; CVAPI(bool) cveVideoCaptureRetrieve(cv::VideoCapture* capture, cv::_OutputArray* image, int flag);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureRetrieve", $bCaptureDllType, $capture, $bImageDllType, $image, "int", $flag), "cveVideoCaptureRetrieve", @error)
EndFunc   ;==>_cveVideoCaptureRetrieve

Func _cveVideoCaptureRetrieveMat($capture, $matImage, $flag)
    ; cveVideoCaptureRetrieve using cv::Mat instead of _*Array

    Local $oArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $oArrImage = _cveOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $oArrImage = _cveOutputArrayFromMat($matImage)
    EndIf

    Local $retval = _cveVideoCaptureRetrieve($capture, $oArrImage, $flag)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveOutputArrayRelease($oArrImage)

    Return $retval
EndFunc   ;==>_cveVideoCaptureRetrieveMat

Func _cveVideoCaptureRead($capture, $image)
    ; CVAPI(bool) cveVideoCaptureRead(cv::VideoCapture* capture, cv::_OutputArray* image);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureRead", $bCaptureDllType, $capture, $bImageDllType, $image), "cveVideoCaptureRead", @error)
EndFunc   ;==>_cveVideoCaptureRead

Func _cveVideoCaptureReadMat($capture, $matImage)
    ; cveVideoCaptureRead using cv::Mat instead of _*Array

    Local $oArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $oArrImage = _cveOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $oArrImage = _cveOutputArrayFromMat($matImage)
    EndIf

    Local $retval = _cveVideoCaptureRead($capture, $oArrImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveOutputArrayRelease($oArrImage)

    Return $retval
EndFunc   ;==>_cveVideoCaptureReadMat

Func _cveVideoCaptureReadToMat($capture, $mat)
    ; CVAPI(void) cveVideoCaptureReadToMat(cv::VideoCapture* capture, cv::Mat* mat);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureReadToMat", $bCaptureDllType, $capture, $bMatDllType, $mat), "cveVideoCaptureReadToMat", @error)
EndFunc   ;==>_cveVideoCaptureReadToMat

Func _cveVideoCaptureReadToUMat($capture, $umat)
    ; CVAPI(void) cveVideoCaptureReadToUMat(cv::VideoCapture* capture, cv::UMat* umat);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $bUmatDllType
    If VarGetType($umat) == "DLLStruct" Then
        $bUmatDllType = "struct*"
    Else
        $bUmatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureReadToUMat", $bCaptureDllType, $capture, $bUmatDllType, $umat), "cveVideoCaptureReadToUMat", @error)
EndFunc   ;==>_cveVideoCaptureReadToUMat

Func _cveVideoCaptureGetBackendName($capture, $name)
    ; CVAPI(void) cveVideoCaptureGetBackendName(cv::VideoCapture* capture, cv::String* name);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $bNameDllType
    If VarGetType($name) == "DLLStruct" Then
        $bNameDllType = "struct*"
    Else
        $bNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureGetBackendName", $bCaptureDllType, $capture, $bNameDllType, $name), "cveVideoCaptureGetBackendName", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveVideoCaptureGetBackendName

Func _cveVideoCaptureWaitAny($streams, $readyIndex, $timeoutNs)
    ; CVAPI(bool) cveVideoCaptureWaitAny(std::vector<cv::VideoCapture>* streams, std::vector<int>* readyIndex, int timeoutNs);

    Local $vecStreams, $iArrStreamsSize
    Local $bStreamsIsArray = VarGetType($streams) == "Array"

    If $bStreamsIsArray Then
        $vecStreams = _VectorOfVideoCaptureCreate()

        $iArrStreamsSize = UBound($streams)
        For $i = 0 To $iArrStreamsSize - 1
            _VectorOfVideoCapturePush($vecStreams, $streams[$i])
        Next
    Else
        $vecStreams = $streams
    EndIf

    Local $bStreamsDllType
    If VarGetType($streams) == "DLLStruct" Then
        $bStreamsDllType = "struct*"
    Else
        $bStreamsDllType = "ptr"
    EndIf

    Local $vecReadyIndex, $iArrReadyIndexSize
    Local $bReadyIndexIsArray = VarGetType($readyIndex) == "Array"

    If $bReadyIndexIsArray Then
        $vecReadyIndex = _VectorOfIntCreate()

        $iArrReadyIndexSize = UBound($readyIndex)
        For $i = 0 To $iArrReadyIndexSize - 1
            _VectorOfIntPush($vecReadyIndex, $readyIndex[$i])
        Next
    Else
        $vecReadyIndex = $readyIndex
    EndIf

    Local $bReadyIndexDllType
    If VarGetType($readyIndex) == "DLLStruct" Then
        $bReadyIndexDllType = "struct*"
    Else
        $bReadyIndexDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureWaitAny", $bStreamsDllType, $vecStreams, $bReadyIndexDllType, $vecReadyIndex, "int", $timeoutNs), "cveVideoCaptureWaitAny", @error)

    If $bReadyIndexIsArray Then
        _VectorOfIntRelease($vecReadyIndex)
    EndIf

    If $bStreamsIsArray Then
        _VectorOfVideoCaptureRelease($vecStreams)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoCaptureWaitAny

Func _cveVideoWriterCreate($filename, $fourcc, $fps, $frameSize, $isColor)
    ; CVAPI(cv::VideoWriter*) cveVideoWriterCreate(cv::String* filename, int fourcc, double fps, CvSize* frameSize, bool isColor);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $bFilenameDllType
    If VarGetType($filename) == "DLLStruct" Then
        $bFilenameDllType = "struct*"
    Else
        $bFilenameDllType = "ptr"
    EndIf

    Local $bFrameSizeDllType
    If VarGetType($frameSize) == "DLLStruct" Then
        $bFrameSizeDllType = "struct*"
    Else
        $bFrameSizeDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoWriterCreate", $bFilenameDllType, $filename, "int", $fourcc, "double", $fps, $bFrameSizeDllType, $frameSize, "boolean", $isColor), "cveVideoWriterCreate", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoWriterCreate

Func _cveVideoWriterCreate2($filename, $apiPreference, $fourcc, $fps, $frameSize, $isColor)
    ; CVAPI(cv::VideoWriter*) cveVideoWriterCreate2(cv::String* filename, int apiPreference, int fourcc, double fps, CvSize* frameSize, bool isColor);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $bFilenameDllType
    If VarGetType($filename) == "DLLStruct" Then
        $bFilenameDllType = "struct*"
    Else
        $bFilenameDllType = "ptr"
    EndIf

    Local $bFrameSizeDllType
    If VarGetType($frameSize) == "DLLStruct" Then
        $bFrameSizeDllType = "struct*"
    Else
        $bFrameSizeDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoWriterCreate2", $bFilenameDllType, $filename, "int", $apiPreference, "int", $fourcc, "double", $fps, $bFrameSizeDllType, $frameSize, "boolean", $isColor), "cveVideoWriterCreate2", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoWriterCreate2

Func _cveVideoWriterCreate3($filename, $apiPreference, $fourcc, $fps, $frameSize, $params)
    ; CVAPI(cv::VideoWriter*) cveVideoWriterCreate3(cv::String* filename, int apiPreference, int fourcc, double fps, CvSize* frameSize, std::vector< int >* params);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $bFilenameDllType
    If VarGetType($filename) == "DLLStruct" Then
        $bFilenameDllType = "struct*"
    Else
        $bFilenameDllType = "ptr"
    EndIf

    Local $bFrameSizeDllType
    If VarGetType($frameSize) == "DLLStruct" Then
        $bFrameSizeDllType = "struct*"
    Else
        $bFrameSizeDllType = "ptr"
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

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoWriterCreate3", $bFilenameDllType, $filename, "int", $apiPreference, "int", $fourcc, "double", $fps, $bFrameSizeDllType, $frameSize, $bParamsDllType, $vecParams), "cveVideoWriterCreate3", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoWriterCreate3

Func _cveVideoWriterIsOpened($writer)
    ; CVAPI(bool) cveVideoWriterIsOpened(cv::VideoWriter* writer);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoWriterIsOpened", $bWriterDllType, $writer), "cveVideoWriterIsOpened", @error)
EndFunc   ;==>_cveVideoWriterIsOpened

Func _cveVideoWriterSet($writer, $propId, $value)
    ; CVAPI(bool) cveVideoWriterSet(cv::VideoWriter* writer, int propId, double value);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoWriterSet", $bWriterDllType, $writer, "int", $propId, "double", $value), "cveVideoWriterSet", @error)
EndFunc   ;==>_cveVideoWriterSet

Func _cveVideoWriterGet($writer, $propId)
    ; CVAPI(double) cveVideoWriterGet(cv::VideoWriter* writer, int propId);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveVideoWriterGet", $bWriterDllType, $writer, "int", $propId), "cveVideoWriterGet", @error)
EndFunc   ;==>_cveVideoWriterGet

Func _cveVideoWriterRelease($writer)
    ; CVAPI(void) cveVideoWriterRelease(cv::VideoWriter** writer);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoWriterRelease", $bWriterDllType, $writer), "cveVideoWriterRelease", @error)
EndFunc   ;==>_cveVideoWriterRelease

Func _cveVideoWriterWrite($writer, $image)
    ; CVAPI(void) cveVideoWriterWrite(cv::VideoWriter* writer, cv::_InputArray* image);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoWriterWrite", $bWriterDllType, $writer, $bImageDllType, $image), "cveVideoWriterWrite", @error)
EndFunc   ;==>_cveVideoWriterWrite

Func _cveVideoWriterWriteMat($writer, $matImage)
    ; cveVideoWriterWrite using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    _cveVideoWriterWrite($writer, $iArrImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveVideoWriterWriteMat

Func _cveVideoWriterFourcc($c1, $c2, $c3, $c4)
    ; CVAPI(int) cveVideoWriterFourcc(char c1, char c2, char c3, char c4);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveVideoWriterFourcc", "byte", $c1, "byte", $c2, "byte", $c3, "byte", $c4), "cveVideoWriterFourcc", @error)
EndFunc   ;==>_cveVideoWriterFourcc

Func _cveGetBackendName($api, $name)
    ; CVAPI(void) cveGetBackendName(int api, cv::String* name);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $bNameDllType
    If VarGetType($name) == "DLLStruct" Then
        $bNameDllType = "struct*"
    Else
        $bNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetBackendName", "int", $api, $bNameDllType, $name), "cveGetBackendName", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveGetBackendName

Func _cveGetBackends($backends)
    ; CVAPI(void) cveGetBackends(std::vector<int>* backends);

    Local $vecBackends, $iArrBackendsSize
    Local $bBackendsIsArray = VarGetType($backends) == "Array"

    If $bBackendsIsArray Then
        $vecBackends = _VectorOfIntCreate()

        $iArrBackendsSize = UBound($backends)
        For $i = 0 To $iArrBackendsSize - 1
            _VectorOfIntPush($vecBackends, $backends[$i])
        Next
    Else
        $vecBackends = $backends
    EndIf

    Local $bBackendsDllType
    If VarGetType($backends) == "DLLStruct" Then
        $bBackendsDllType = "struct*"
    Else
        $bBackendsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetBackends", $bBackendsDllType, $vecBackends), "cveGetBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetBackends

Func _cveGetCameraBackends($backends)
    ; CVAPI(void) cveGetCameraBackends(std::vector<int>* backends);

    Local $vecBackends, $iArrBackendsSize
    Local $bBackendsIsArray = VarGetType($backends) == "Array"

    If $bBackendsIsArray Then
        $vecBackends = _VectorOfIntCreate()

        $iArrBackendsSize = UBound($backends)
        For $i = 0 To $iArrBackendsSize - 1
            _VectorOfIntPush($vecBackends, $backends[$i])
        Next
    Else
        $vecBackends = $backends
    EndIf

    Local $bBackendsDllType
    If VarGetType($backends) == "DLLStruct" Then
        $bBackendsDllType = "struct*"
    Else
        $bBackendsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetCameraBackends", $bBackendsDllType, $vecBackends), "cveGetCameraBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetCameraBackends

Func _cveGetStreamBackends($backends)
    ; CVAPI(void) cveGetStreamBackends(std::vector<int>* backends);

    Local $vecBackends, $iArrBackendsSize
    Local $bBackendsIsArray = VarGetType($backends) == "Array"

    If $bBackendsIsArray Then
        $vecBackends = _VectorOfIntCreate()

        $iArrBackendsSize = UBound($backends)
        For $i = 0 To $iArrBackendsSize - 1
            _VectorOfIntPush($vecBackends, $backends[$i])
        Next
    Else
        $vecBackends = $backends
    EndIf

    Local $bBackendsDllType
    If VarGetType($backends) == "DLLStruct" Then
        $bBackendsDllType = "struct*"
    Else
        $bBackendsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetStreamBackends", $bBackendsDllType, $vecBackends), "cveGetStreamBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetStreamBackends

Func _cveGetWriterBackends($backends)
    ; CVAPI(void) cveGetWriterBackends(std::vector<int>* backends);

    Local $vecBackends, $iArrBackendsSize
    Local $bBackendsIsArray = VarGetType($backends) == "Array"

    If $bBackendsIsArray Then
        $vecBackends = _VectorOfIntCreate()

        $iArrBackendsSize = UBound($backends)
        For $i = 0 To $iArrBackendsSize - 1
            _VectorOfIntPush($vecBackends, $backends[$i])
        Next
    Else
        $vecBackends = $backends
    EndIf

    Local $bBackendsDllType
    If VarGetType($backends) == "DLLStruct" Then
        $bBackendsDllType = "struct*"
    Else
        $bBackendsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetWriterBackends", $bBackendsDllType, $vecBackends), "cveGetWriterBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetWriterBackends