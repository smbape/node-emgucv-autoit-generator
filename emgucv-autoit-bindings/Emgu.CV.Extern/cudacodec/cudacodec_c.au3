#include-once
#include "..\..\CVEUtils.au3"

Func _cudaVideoWriterCreate($fileName, $frameSize, $fps, $format, $sharedPtr)
    ; CVAPI(cv::cudacodec::VideoWriter*) cudaVideoWriterCreate(cv::String* fileName, CvSize* frameSize, double fps, cv::cudacodec::SurfaceFormat format, cv::Ptr<cv::cudacodec::VideoWriter>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf

    Local $sFrameSizeDllType
    If IsDllStruct($frameSize) Then
        $sFrameSizeDllType = "struct*"
    Else
        $sFrameSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaVideoWriterCreate", $sFileNameDllType, $fileName, $sFrameSizeDllType, $frameSize, "double", $fps, "int", $format, $sSharedPtrDllType, $sharedPtr), "cudaVideoWriterCreate", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cudaVideoWriterCreate

Func _cudaVideoWriterRelease($writer)
    ; CVAPI(void) cudaVideoWriterRelease(cv::Ptr<cv::cudacodec::VideoWriter>** writer);

    Local $sWriterDllType
    If IsDllStruct($writer) Then
        $sWriterDllType = "struct*"
    ElseIf $writer == Null Then
        $sWriterDllType = "ptr"
    Else
        $sWriterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoWriterRelease", $sWriterDllType, $writer), "cudaVideoWriterRelease", @error)
EndFunc   ;==>_cudaVideoWriterRelease

Func _cudaVideoWriterWrite($writer, $frame, $lastFrame)
    ; CVAPI(void) cudaVideoWriterWrite(cv::cudacodec::VideoWriter* writer, cv::_InputArray* frame, bool lastFrame);

    Local $sWriterDllType
    If IsDllStruct($writer) Then
        $sWriterDllType = "struct*"
    Else
        $sWriterDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoWriterWrite", $sWriterDllType, $writer, $sFrameDllType, $frame, "boolean", $lastFrame), "cudaVideoWriterWrite", @error)
EndFunc   ;==>_cudaVideoWriterWrite

Func _cudaVideoWriterWriteMat($writer, $matFrame, $lastFrame)
    ; cudaVideoWriterWrite using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cudaVideoWriterWrite($writer, $iArrFrame, $lastFrame)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cudaVideoWriterWriteMat

Func _cudaVideoReaderCreate($fileName, $sharedPtr)
    ; CVAPI(cv::cudacodec::VideoReader*) cudaVideoReaderCreate(cv::String* fileName, cv::Ptr<cv::cudacodec::VideoReader>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaVideoReaderCreate", $sFileNameDllType, $fileName, $sSharedPtrDllType, $sharedPtr), "cudaVideoReaderCreate", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cudaVideoReaderCreate

Func _cudaVideoReaderRelease($reader)
    ; CVAPI(void) cudaVideoReaderRelease(cv::Ptr<cv::cudacodec::VideoReader>** reader);

    Local $sReaderDllType
    If IsDllStruct($reader) Then
        $sReaderDllType = "struct*"
    ElseIf $reader == Null Then
        $sReaderDllType = "ptr"
    Else
        $sReaderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoReaderRelease", $sReaderDllType, $reader), "cudaVideoReaderRelease", @error)
EndFunc   ;==>_cudaVideoReaderRelease

Func _cudaVideoReaderNextFrame($reader, $frame, $stream)
    ; CVAPI(bool) cudaVideoReaderNextFrame(cv::cudacodec::VideoReader* reader, cv::cuda::GpuMat* frame, cv::cuda::Stream* stream);

    Local $sReaderDllType
    If IsDllStruct($reader) Then
        $sReaderDllType = "struct*"
    Else
        $sReaderDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaVideoReaderNextFrame", $sReaderDllType, $reader, $sFrameDllType, $frame, $sStreamDllType, $stream), "cudaVideoReaderNextFrame", @error)
EndFunc   ;==>_cudaVideoReaderNextFrame

Func _cudaVideoReaderFormat($reader, $formatInfo)
    ; CVAPI(void) cudaVideoReaderFormat(cv::cudacodec::VideoReader* reader, cv::cudacodec::FormatInfo* formatInfo);

    Local $sReaderDllType
    If IsDllStruct($reader) Then
        $sReaderDllType = "struct*"
    Else
        $sReaderDllType = "ptr"
    EndIf

    Local $sFormatInfoDllType
    If IsDllStruct($formatInfo) Then
        $sFormatInfoDllType = "struct*"
    Else
        $sFormatInfoDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoReaderFormat", $sReaderDllType, $reader, $sFormatInfoDllType, $formatInfo), "cudaVideoReaderFormat", @error)
EndFunc   ;==>_cudaVideoReaderFormat