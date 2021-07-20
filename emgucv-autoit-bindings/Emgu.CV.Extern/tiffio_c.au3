#include-once
#include "..\CVEUtils.au3"

Func _tiffWriterOpen($fileName)
    ; CVAPI(TIFF*) tiffWriterOpen(char* fileName);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "tiffWriterOpen", "struct*", $fileName), "tiffWriterOpen", @error)
EndFunc   ;==>_tiffWriterOpen

Func _tiffTileRowSize($pTiff)
    ; CVAPI(int) tiffTileRowSize(TIFF* pTiff);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "tiffTileRowSize", "struct*", $pTiff), "tiffTileRowSize", @error)
EndFunc   ;==>_tiffTileRowSize

Func _tiffTileSize($pTiff)
    ; CVAPI(int) tiffTileSize(TIFF* pTiff);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "tiffTileSize", "struct*", $pTiff), "tiffTileSize", @error)
EndFunc   ;==>_tiffTileSize

Func _tiffWriteImageSize($pTiff, $imageSize)
    ; CVAPI(void) tiffWriteImageSize(TIFF* pTiff, CvSize* imageSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImageSize", "struct*", $pTiff, "struct*", $imageSize), "tiffWriteImageSize", @error)
EndFunc   ;==>_tiffWriteImageSize

Func _tiffWriteImageInfo($pTiff, $bitsPerSample, $samplesPerPixel)
    ; CVAPI(void) tiffWriteImageInfo(TIFF* pTiff, int bitsPerSample, int samplesPerPixel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImageInfo", "struct*", $pTiff, "int", $bitsPerSample, "int", $samplesPerPixel), "tiffWriteImageInfo", @error)
EndFunc   ;==>_tiffWriteImageInfo

Func _tiffWriteImage($pTiff, $image)
    ; CVAPI(void) tiffWriteImage(TIFF* pTiff, IplImage* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImage", "struct*", $pTiff, "struct*", $image), "tiffWriteImage", @error)
EndFunc   ;==>_tiffWriteImage

Func _tiffWriteTile($pTiff, $row, $col, $tileImage)
    ; CVAPI(void) tiffWriteTile(TIFF* pTiff, int row, int col, IplImage* tileImage);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteTile", "struct*", $pTiff, "int", $row, "int", $col, "struct*", $tileImage), "tiffWriteTile", @error)
EndFunc   ;==>_tiffWriteTile

Func _tiffWriteTileInfo($pTiff, $tileSize)
    ; CVAPI(void) tiffWriteTileInfo(TIFF* pTiff, CvSize* tileSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteTileInfo", "struct*", $pTiff, "struct*", $tileSize), "tiffWriteTileInfo", @error)
EndFunc   ;==>_tiffWriteTileInfo

Func _tiffWriterClose($pTiff)
    ; CVAPI(void) tiffWriterClose(TIFF** pTiff);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriterClose", $bPTiffDllType, $pTiff), "tiffWriterClose", @error)
EndFunc   ;==>_tiffWriterClose

Func _tiffWriteGeoTag($pTiff, $ModelTiepoint, $ModelPixelScale)
    ; CVAPI(void) tiffWriteGeoTag(TIFF* pTiff, double* ModelTiepoint, double* ModelPixelScale);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteGeoTag", "struct*", $pTiff, "struct*", $ModelTiepoint, "struct*", $ModelPixelScale), "tiffWriteGeoTag", @error)
EndFunc   ;==>_tiffWriteGeoTag