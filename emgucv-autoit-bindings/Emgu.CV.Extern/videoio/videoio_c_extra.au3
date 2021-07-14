#include-once
#include "..\..\CVEUtils.au3"

Func _OpenniGetColorPoints(ByRef $capture, ByRef $points, ByRef $mask)
    ; CVAPI(void) OpenniGetColorPoints(CvCapture* capture, std::vector<ColorPoint>* points, IplImage* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "OpenniGetColorPoints", "struct*", $capture, "ptr", $vecPoints, "struct*", $mask), "OpenniGetColorPoints", @error)

    If $bPointsIsArray Then
        _VectorOfColorPointRelease($vecPoints)
    EndIf
EndFunc   ;==>_OpenniGetColorPoints

Func _cveVideoCaptureCreateFromDevice($device, $apiPreference, ByRef $params)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoCaptureCreateFromDevice", "int", $device, "int", $apiPreference, "ptr", $vecParams), "cveVideoCaptureCreateFromDevice", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoCaptureCreateFromDevice

Func _cveVideoCaptureCreateFromFile($fileName, $apiPreference, ByRef $params)
    ; CVAPI(cv::VideoCapture*) cveVideoCaptureCreateFromFile(cv::String* fileName, int apiPreference, std::vector< int >* params);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoCaptureCreateFromFile", "ptr", $fileName, "int", $apiPreference, "ptr", $vecParams), "cveVideoCaptureCreateFromFile", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoCaptureCreateFromFile

Func _cveVideoCaptureRelease(ByRef $capture)
    ; CVAPI(void) cveVideoCaptureRelease(cv::VideoCapture** capture);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureRelease", "ptr*", $capture), "cveVideoCaptureRelease", @error)
EndFunc   ;==>_cveVideoCaptureRelease

Func _cveVideoCaptureSet(ByRef $capture, $propId, $value)
    ; CVAPI(bool) cveVideoCaptureSet(cv::VideoCapture* capture, int propId, double value);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureSet", "ptr", $capture, "int", $propId, "double", $value), "cveVideoCaptureSet", @error)
EndFunc   ;==>_cveVideoCaptureSet

Func _cveVideoCaptureGet(ByRef $capture, $propId)
    ; CVAPI(double) cveVideoCaptureGet(cv::VideoCapture* capture, int propId);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveVideoCaptureGet", "ptr", $capture, "int", $propId), "cveVideoCaptureGet", @error)
EndFunc   ;==>_cveVideoCaptureGet

Func _cveVideoCaptureGrab(ByRef $capture)
    ; CVAPI(bool) cveVideoCaptureGrab(cv::VideoCapture* capture);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureGrab", "ptr", $capture), "cveVideoCaptureGrab", @error)
EndFunc   ;==>_cveVideoCaptureGrab

Func _cveVideoCaptureRetrieve(ByRef $capture, ByRef $image, $flag)
    ; CVAPI(bool) cveVideoCaptureRetrieve(cv::VideoCapture* capture, cv::_OutputArray* image, int flag);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureRetrieve", "ptr", $capture, "ptr", $image, "int", $flag), "cveVideoCaptureRetrieve", @error)
EndFunc   ;==>_cveVideoCaptureRetrieve

Func _cveVideoCaptureRetrieveMat(ByRef $capture, ByRef $matImage, $flag)
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

Func _cveVideoCaptureRead(ByRef $capture, ByRef $image)
    ; CVAPI(bool) cveVideoCaptureRead(cv::VideoCapture* capture, cv::_OutputArray* image);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureRead", "ptr", $capture, "ptr", $image), "cveVideoCaptureRead", @error)
EndFunc   ;==>_cveVideoCaptureRead

Func _cveVideoCaptureReadMat(ByRef $capture, ByRef $matImage)
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

Func _cveVideoCaptureReadToMat(ByRef $capture, ByRef $mat)
    ; CVAPI(void) cveVideoCaptureReadToMat(cv::VideoCapture* capture, cv::Mat* mat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureReadToMat", "ptr", $capture, "ptr", $mat), "cveVideoCaptureReadToMat", @error)
EndFunc   ;==>_cveVideoCaptureReadToMat

Func _cveVideoCaptureReadToUMat(ByRef $capture, ByRef $umat)
    ; CVAPI(void) cveVideoCaptureReadToUMat(cv::VideoCapture* capture, cv::UMat* umat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureReadToUMat", "ptr", $capture, "ptr", $umat), "cveVideoCaptureReadToUMat", @error)
EndFunc   ;==>_cveVideoCaptureReadToUMat

Func _cveVideoCaptureGetBackendName(ByRef $capture, $name)
    ; CVAPI(void) cveVideoCaptureGetBackendName(cv::VideoCapture* capture, cv::String* name);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureGetBackendName", "ptr", $capture, "ptr", $name), "cveVideoCaptureGetBackendName", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveVideoCaptureGetBackendName

Func _cveVideoCaptureWaitAny(ByRef $streams, ByRef $readyIndex, $timeoutNs)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureWaitAny", "ptr", $vecStreams, "ptr", $vecReadyIndex, "int", $timeoutNs), "cveVideoCaptureWaitAny", @error)

    If $bReadyIndexIsArray Then
        _VectorOfIntRelease($vecReadyIndex)
    EndIf

    If $bStreamsIsArray Then
        _VectorOfVideoCaptureRelease($vecStreams)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoCaptureWaitAny

Func _cveVideoWriterCreate($filename, $fourcc, $fps, ByRef $frameSize, $isColor)
    ; CVAPI(cv::VideoWriter*) cveVideoWriterCreate(cv::String* filename, int fourcc, double fps, CvSize* frameSize, bool isColor);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoWriterCreate", "ptr", $filename, "int", $fourcc, "double", $fps, "struct*", $frameSize, "boolean", $isColor), "cveVideoWriterCreate", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoWriterCreate

Func _cveVideoWriterCreate2($filename, $apiPreference, $fourcc, $fps, ByRef $frameSize, $isColor)
    ; CVAPI(cv::VideoWriter*) cveVideoWriterCreate2(cv::String* filename, int apiPreference, int fourcc, double fps, CvSize* frameSize, bool isColor);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoWriterCreate2", "ptr", $filename, "int", $apiPreference, "int", $fourcc, "double", $fps, "struct*", $frameSize, "boolean", $isColor), "cveVideoWriterCreate2", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoWriterCreate2

Func _cveVideoWriterCreate3($filename, $apiPreference, $fourcc, $fps, ByRef $frameSize, ByRef $params)
    ; CVAPI(cv::VideoWriter*) cveVideoWriterCreate3(cv::String* filename, int apiPreference, int fourcc, double fps, CvSize* frameSize, std::vector< int >* params);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideoWriterCreate3", "ptr", $filename, "int", $apiPreference, "int", $fourcc, "double", $fps, "struct*", $frameSize, "ptr", $vecParams), "cveVideoWriterCreate3", @error)

    If $bParamsIsArray Then
        _VectorOfIntRelease($vecParams)
    EndIf

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cveVideoWriterCreate3

Func _cveVideoWriterIsOpened(ByRef $writer)
    ; CVAPI(bool) cveVideoWriterIsOpened(cv::VideoWriter* writer);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoWriterIsOpened", "ptr", $writer), "cveVideoWriterIsOpened", @error)
EndFunc   ;==>_cveVideoWriterIsOpened

Func _cveVideoWriterSet(ByRef $writer, $propId, $value)
    ; CVAPI(bool) cveVideoWriterSet(cv::VideoWriter* writer, int propId, double value);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoWriterSet", "ptr", $writer, "int", $propId, "double", $value), "cveVideoWriterSet", @error)
EndFunc   ;==>_cveVideoWriterSet

Func _cveVideoWriterGet(ByRef $writer, $propId)
    ; CVAPI(double) cveVideoWriterGet(cv::VideoWriter* writer, int propId);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveVideoWriterGet", "ptr", $writer, "int", $propId), "cveVideoWriterGet", @error)
EndFunc   ;==>_cveVideoWriterGet

Func _cveVideoWriterRelease(ByRef $writer)
    ; CVAPI(void) cveVideoWriterRelease(cv::VideoWriter** writer);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoWriterRelease", "ptr*", $writer), "cveVideoWriterRelease", @error)
EndFunc   ;==>_cveVideoWriterRelease

Func _cveVideoWriterWrite(ByRef $writer, ByRef $image)
    ; CVAPI(void) cveVideoWriterWrite(cv::VideoWriter* writer, cv::Mat* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoWriterWrite", "ptr", $writer, "ptr", $image), "cveVideoWriterWrite", @error)
EndFunc   ;==>_cveVideoWriterWrite

Func _cveVideoWriterFourcc($c1, $c2, $c3, $c4)
    ; CVAPI(int) cveVideoWriterFourcc(char c1, char c2, char c3, char c4);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveVideoWriterFourcc", "char", $c1, "char", $c2, "char", $c3, "char", $c4), "cveVideoWriterFourcc", @error)
EndFunc   ;==>_cveVideoWriterFourcc

Func _cveGetBackendName($api, $name)
    ; CVAPI(void) cveGetBackendName(int api, cv::String* name);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetBackendName", "int", $api, "ptr", $name), "cveGetBackendName", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveGetBackendName

Func _cveGetBackends(ByRef $backends)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetBackends", "ptr", $vecBackends), "cveGetBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetBackends

Func _cveGetCameraBackends(ByRef $backends)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetCameraBackends", "ptr", $vecBackends), "cveGetCameraBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetCameraBackends

Func _cveGetStreamBackends(ByRef $backends)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetStreamBackends", "ptr", $vecBackends), "cveGetStreamBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetStreamBackends

Func _cveGetWriterBackends(ByRef $backends)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetWriterBackends", "ptr", $vecBackends), "cveGetWriterBackends", @error)

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveGetWriterBackends