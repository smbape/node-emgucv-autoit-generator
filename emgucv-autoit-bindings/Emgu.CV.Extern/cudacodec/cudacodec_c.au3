#include-once
#include <..\..\CVEUtils.au3>

Func _cudaVideoWriterCreate($fileName, ByRef $frameSize, $fps, $format, ByRef $sharedPtr)
    ; CVAPI(cv::cudacodec::VideoWriter*) cudaVideoWriterCreate(cv::String* fileName, CvSize* frameSize, double fps, cv::cudacodec::SurfaceFormat format, cv::Ptr<cv::cudacodec::VideoWriter>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaVideoWriterCreate", "ptr", $fileName, "struct*", $frameSize, "double", $fps, "cv::cudacodec::SurfaceFormat", $format, "ptr*", $sharedPtr), "cudaVideoWriterCreate", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cudaVideoWriterCreate

Func _cudaVideoWriterRelease(ByRef $writer)
    ; CVAPI(void) cudaVideoWriterRelease(cv::Ptr<cv::cudacodec::VideoWriter>** writer);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoWriterRelease", "ptr*", $writer), "cudaVideoWriterRelease", @error)
EndFunc   ;==>_cudaVideoWriterRelease

Func _cudaVideoWriterWrite(ByRef $writer, ByRef $frame, $lastFrame)
    ; CVAPI(void) cudaVideoWriterWrite(cv::cudacodec::VideoWriter* writer, cv::_InputArray* frame, bool lastFrame);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoWriterWrite", "ptr", $writer, "ptr", $frame, "boolean", $lastFrame), "cudaVideoWriterWrite", @error)
EndFunc   ;==>_cudaVideoWriterWrite

Func _cudaVideoWriterWriteMat(ByRef $writer, ByRef $matFrame, $lastFrame)
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

Func _cudaVideoReaderCreate($fileName, ByRef $sharedPtr)
    ; CVAPI(cv::cudacodec::VideoReader*) cudaVideoReaderCreate(cv::String* fileName, cv::Ptr<cv::cudacodec::VideoReader>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaVideoReaderCreate", "ptr", $fileName, "ptr*", $sharedPtr), "cudaVideoReaderCreate", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cudaVideoReaderCreate

Func _cudaVideoReaderRelease(ByRef $reader)
    ; CVAPI(void) cudaVideoReaderRelease(cv::Ptr<cv::cudacodec::VideoReader>** reader);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoReaderRelease", "ptr*", $reader), "cudaVideoReaderRelease", @error)
EndFunc   ;==>_cudaVideoReaderRelease

Func _cudaVideoReaderNextFrame(ByRef $reader, ByRef $frame, ByRef $stream)
    ; CVAPI(bool) cudaVideoReaderNextFrame(cv::cudacodec::VideoReader* reader, cv::cuda::GpuMat* frame, cv::cuda::Stream* stream);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cudaVideoReaderNextFrame", "ptr", $reader, "ptr", $frame, "ptr", $stream), "cudaVideoReaderNextFrame", @error)
EndFunc   ;==>_cudaVideoReaderNextFrame

Func _cudaVideoReaderFormat(ByRef $reader, ByRef $formatInfo)
    ; CVAPI(void) cudaVideoReaderFormat(cv::cudacodec::VideoReader* reader, cv::cudacodec::FormatInfo* formatInfo);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaVideoReaderFormat", "ptr", $reader, "ptr", $formatInfo), "cudaVideoReaderFormat", @error)
EndFunc   ;==>_cudaVideoReaderFormat