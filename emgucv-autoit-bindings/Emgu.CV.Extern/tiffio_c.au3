#include-once
#include "..\CVEUtils.au3"

Func _tiffWriterOpen($fileName)
    ; CVAPI(TIFF*) tiffWriterOpen(char* fileName);

    Local $bFileNameDllType
    If VarGetType($fileName) == "DLLStruct" Then
        $bFileNameDllType = "struct*"
    Else
        $bFileNameDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "tiffWriterOpen", $bFileNameDllType, $fileName), "tiffWriterOpen", @error)
EndFunc   ;==>_tiffWriterOpen

Func _tiffTileRowSize($pTiff)
    ; CVAPI(int) tiffTileRowSize(TIFF* pTiff);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "tiffTileRowSize", $bPTiffDllType, $pTiff), "tiffTileRowSize", @error)
EndFunc   ;==>_tiffTileRowSize

Func _tiffTileSize($pTiff)
    ; CVAPI(int) tiffTileSize(TIFF* pTiff);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "tiffTileSize", $bPTiffDllType, $pTiff), "tiffTileSize", @error)
EndFunc   ;==>_tiffTileSize

Func _tiffWriteImageSize($pTiff, $imageSize)
    ; CVAPI(void) tiffWriteImageSize(TIFF* pTiff, CvSize* imageSize);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf

    Local $bImageSizeDllType
    If VarGetType($imageSize) == "DLLStruct" Then
        $bImageSizeDllType = "struct*"
    Else
        $bImageSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImageSize", $bPTiffDllType, $pTiff, $bImageSizeDllType, $imageSize), "tiffWriteImageSize", @error)
EndFunc   ;==>_tiffWriteImageSize

Func _tiffWriteImageInfo($pTiff, $bitsPerSample, $samplesPerPixel)
    ; CVAPI(void) tiffWriteImageInfo(TIFF* pTiff, int bitsPerSample, int samplesPerPixel);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImageInfo", $bPTiffDllType, $pTiff, "int", $bitsPerSample, "int", $samplesPerPixel), "tiffWriteImageInfo", @error)
EndFunc   ;==>_tiffWriteImageInfo

Func _tiffWriteImage($pTiff, $image)
    ; CVAPI(void) tiffWriteImage(TIFF* pTiff, IplImage* image);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImage", $bPTiffDllType, $pTiff, $bImageDllType, $image), "tiffWriteImage", @error)
EndFunc   ;==>_tiffWriteImage

Func _tiffWriteTile($pTiff, $row, $col, $tileImage)
    ; CVAPI(void) tiffWriteTile(TIFF* pTiff, int row, int col, IplImage* tileImage);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf

    Local $bTileImageDllType
    If VarGetType($tileImage) == "DLLStruct" Then
        $bTileImageDllType = "struct*"
    Else
        $bTileImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteTile", $bPTiffDllType, $pTiff, "int", $row, "int", $col, $bTileImageDllType, $tileImage), "tiffWriteTile", @error)
EndFunc   ;==>_tiffWriteTile

Func _tiffWriteTileInfo($pTiff, $tileSize)
    ; CVAPI(void) tiffWriteTileInfo(TIFF* pTiff, CvSize* tileSize);

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf

    Local $bTileSizeDllType
    If VarGetType($tileSize) == "DLLStruct" Then
        $bTileSizeDllType = "struct*"
    Else
        $bTileSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteTileInfo", $bPTiffDllType, $pTiff, $bTileSizeDllType, $tileSize), "tiffWriteTileInfo", @error)
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

    Local $bPTiffDllType
    If VarGetType($pTiff) == "DLLStruct" Then
        $bPTiffDllType = "struct*"
    Else
        $bPTiffDllType = "ptr"
    EndIf

    Local $bModelTiepointDllType
    If VarGetType($ModelTiepoint) == "DLLStruct" Then
        $bModelTiepointDllType = "struct*"
    Else
        $bModelTiepointDllType = "double*"
    EndIf

    Local $bModelPixelScaleDllType
    If VarGetType($ModelPixelScale) == "DLLStruct" Then
        $bModelPixelScaleDllType = "struct*"
    Else
        $bModelPixelScaleDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteGeoTag", $bPTiffDllType, $pTiff, $bModelTiepointDllType, $ModelTiepoint, $bModelPixelScaleDllType, $ModelPixelScale), "tiffWriteGeoTag", @error)
EndFunc   ;==>_tiffWriteGeoTag