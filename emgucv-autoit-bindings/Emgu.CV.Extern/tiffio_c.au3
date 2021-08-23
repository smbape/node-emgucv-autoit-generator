#include-once
#include "..\CVEUtils.au3"

Func _tiffWriterOpen($fileName)
    ; CVAPI(TIFF*) tiffWriterOpen(char* fileName);

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "tiffWriterOpen", $sFileNameDllType, $fileName), "tiffWriterOpen", @error)
EndFunc   ;==>_tiffWriterOpen

Func _tiffTileRowSize($pTiff)
    ; CVAPI(int) tiffTileRowSize(TIFF* pTiff);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "tiffTileRowSize", $sPTiffDllType, $pTiff), "tiffTileRowSize", @error)
EndFunc   ;==>_tiffTileRowSize

Func _tiffTileSize($pTiff)
    ; CVAPI(int) tiffTileSize(TIFF* pTiff);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "tiffTileSize", $sPTiffDllType, $pTiff), "tiffTileSize", @error)
EndFunc   ;==>_tiffTileSize

Func _tiffWriteImageSize($pTiff, $imageSize)
    ; CVAPI(void) tiffWriteImageSize(TIFF* pTiff, CvSize* imageSize);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImageSize", $sPTiffDllType, $pTiff, $sImageSizeDllType, $imageSize), "tiffWriteImageSize", @error)
EndFunc   ;==>_tiffWriteImageSize

Func _tiffWriteImageInfo($pTiff, $bitsPerSample, $samplesPerPixel)
    ; CVAPI(void) tiffWriteImageInfo(TIFF* pTiff, int bitsPerSample, int samplesPerPixel);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImageInfo", $sPTiffDllType, $pTiff, "int", $bitsPerSample, "int", $samplesPerPixel), "tiffWriteImageInfo", @error)
EndFunc   ;==>_tiffWriteImageInfo

Func _tiffWriteImage($pTiff, $image)
    ; CVAPI(void) tiffWriteImage(TIFF* pTiff, IplImage* image);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteImage", $sPTiffDllType, $pTiff, $sImageDllType, $image), "tiffWriteImage", @error)
EndFunc   ;==>_tiffWriteImage

Func _tiffWriteTile($pTiff, $row, $col, $tileImage)
    ; CVAPI(void) tiffWriteTile(TIFF* pTiff, int row, int col, IplImage* tileImage);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf

    Local $sTileImageDllType
    If IsDllStruct($tileImage) Then
        $sTileImageDllType = "struct*"
    Else
        $sTileImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteTile", $sPTiffDllType, $pTiff, "int", $row, "int", $col, $sTileImageDllType, $tileImage), "tiffWriteTile", @error)
EndFunc   ;==>_tiffWriteTile

Func _tiffWriteTileInfo($pTiff, $tileSize)
    ; CVAPI(void) tiffWriteTileInfo(TIFF* pTiff, CvSize* tileSize);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf

    Local $sTileSizeDllType
    If IsDllStruct($tileSize) Then
        $sTileSizeDllType = "struct*"
    Else
        $sTileSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteTileInfo", $sPTiffDllType, $pTiff, $sTileSizeDllType, $tileSize), "tiffWriteTileInfo", @error)
EndFunc   ;==>_tiffWriteTileInfo

Func _tiffWriterClose($pTiff)
    ; CVAPI(void) tiffWriterClose(TIFF** pTiff);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    ElseIf $pTiff == Null Then
        $sPTiffDllType = "ptr"
    Else
        $sPTiffDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriterClose", $sPTiffDllType, $pTiff), "tiffWriterClose", @error)
EndFunc   ;==>_tiffWriterClose

Func _tiffWriteGeoTag($pTiff, $ModelTiepoint, $ModelPixelScale)
    ; CVAPI(void) tiffWriteGeoTag(TIFF* pTiff, double* ModelTiepoint, double* ModelPixelScale);

    Local $sPTiffDllType
    If IsDllStruct($pTiff) Then
        $sPTiffDllType = "struct*"
    Else
        $sPTiffDllType = "ptr"
    EndIf

    Local $sModelTiepointDllType
    If IsDllStruct($ModelTiepoint) Then
        $sModelTiepointDllType = "struct*"
    Else
        $sModelTiepointDllType = "double*"
    EndIf

    Local $sModelPixelScaleDllType
    If IsDllStruct($ModelPixelScale) Then
        $sModelPixelScaleDllType = "struct*"
    Else
        $sModelPixelScaleDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "tiffWriteGeoTag", $sPTiffDllType, $pTiff, $sModelTiepointDllType, $ModelTiepoint, $sModelPixelScaleDllType, $ModelPixelScale), "tiffWriteGeoTag", @error)
EndFunc   ;==>_tiffWriteGeoTag