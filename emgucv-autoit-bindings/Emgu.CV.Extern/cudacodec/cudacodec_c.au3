#include-once
#include "..\..\CVEUtils.au3"

Func _cudaVideoWriterCreate($fileName, $frameSize, $fps, $format, $sharedPtr)
    ; CVAPI(cv::cudacodec::VideoWriter*) cudaVideoWriterCreate(cv::String* fileName, CvSize* frameSize, double fps, cv::cudacodec::SurfaceFormat format, cv::Ptr<cv::cudacodec::VideoWriter>** sharedPtr);

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

    Local $bFrameSizeDllType
    If VarGetType($frameSize) == "DLLStruct" Then
        $bFrameSizeDllType = "struct*"
    Else
        $bFrameSizeDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaVideoWriterCreate", $bFileNameDllType, $fileName, $bFrameSizeDllType, $frameSize, "double", $fps, "int", $format, $bSharedPtrDllType, $sharedPtr), "cudaVideoWriterCreate", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cudaVideoWriterCreate

Func _cudaVideoWriterRelease($writer)
    ; CVAPI(void) cudaVideoWriterRelease(cv::Ptr<cv::cudacodec::VideoWriter>** writer);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoWriterRelease", $bWriterDllType, $writer), "cudaVideoWriterRelease", @error)
EndFunc   ;==>_cudaVideoWriterRelease

Func _cudaVideoWriterWrite($writer, $frame, $lastFrame)
    ; CVAPI(void) cudaVideoWriterWrite(cv::cudacodec::VideoWriter* writer, cv::_InputArray* frame, bool lastFrame);

    Local $bWriterDllType
    If VarGetType($writer) == "DLLStruct" Then
        $bWriterDllType = "struct*"
    Else
        $bWriterDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoWriterWrite", $bWriterDllType, $writer, $bFrameDllType, $frame, "boolean", $lastFrame), "cudaVideoWriterWrite", @error)
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

    Local $bFileNameDllType
    If VarGetType($fileName) == "DLLStruct" Then
        $bFileNameDllType = "struct*"
    Else
        $bFileNameDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaVideoReaderCreate", $bFileNameDllType, $fileName, $bSharedPtrDllType, $sharedPtr), "cudaVideoReaderCreate", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cudaVideoReaderCreate

Func _cudaVideoReaderRelease($reader)
    ; CVAPI(void) cudaVideoReaderRelease(cv::Ptr<cv::cudacodec::VideoReader>** reader);

    Local $bReaderDllType
    If VarGetType($reader) == "DLLStruct" Then
        $bReaderDllType = "struct*"
    Else
        $bReaderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoReaderRelease", $bReaderDllType, $reader), "cudaVideoReaderRelease", @error)
EndFunc   ;==>_cudaVideoReaderRelease

Func _cudaVideoReaderNextFrame($reader, $frame, $stream)
    ; CVAPI(bool) cudaVideoReaderNextFrame(cv::cudacodec::VideoReader* reader, cv::cuda::GpuMat* frame, cv::cuda::Stream* stream);

    Local $bReaderDllType
    If VarGetType($reader) == "DLLStruct" Then
        $bReaderDllType = "struct*"
    Else
        $bReaderDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaVideoReaderNextFrame", $bReaderDllType, $reader, $bFrameDllType, $frame, $bStreamDllType, $stream), "cudaVideoReaderNextFrame", @error)
EndFunc   ;==>_cudaVideoReaderNextFrame

Func _cudaVideoReaderFormat($reader, $formatInfo)
    ; CVAPI(void) cudaVideoReaderFormat(cv::cudacodec::VideoReader* reader, cv::cudacodec::FormatInfo* formatInfo);

    Local $bReaderDllType
    If VarGetType($reader) == "DLLStruct" Then
        $bReaderDllType = "struct*"
    Else
        $bReaderDllType = "ptr"
    EndIf

    Local $bFormatInfoDllType
    If VarGetType($formatInfo) == "DLLStruct" Then
        $bFormatInfoDllType = "struct*"
    Else
        $bFormatInfoDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoReaderFormat", $bReaderDllType, $reader, $bFormatInfoDllType, $formatInfo), "cudaVideoReaderFormat", @error)
EndFunc   ;==>_cudaVideoReaderFormat