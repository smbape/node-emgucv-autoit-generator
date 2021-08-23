#include-once
#include "..\CVEUtils.au3"

Func _zlib_compress_bound($length)
    ; CVAPI(int) zlib_compress_bound(int length);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "zlib_compress_bound", "int", $length), "zlib_compress_bound", @error)
EndFunc   ;==>_zlib_compress_bound

Func _zlib_compress2($dataCompressed, $sizeDataCompressed, $dataOriginal, $sizeDataOriginal, $compressionLevel)
    ; CVAPI(void) zlib_compress2(Byte* dataCompressed, int* sizeDataCompressed, Byte* dataOriginal, int sizeDataOriginal, int compressionLevel);

    Local $sDataCompressedDllType
    If IsDllStruct($dataCompressed) Then
        $sDataCompressedDllType = "struct*"
    Else
        $sDataCompressedDllType = "ptr"
    EndIf

    Local $sSizeDataCompressedDllType
    If IsDllStruct($sizeDataCompressed) Then
        $sSizeDataCompressedDllType = "struct*"
    Else
        $sSizeDataCompressedDllType = "int*"
    EndIf

    Local $sDataOriginalDllType
    If IsDllStruct($dataOriginal) Then
        $sDataOriginalDllType = "struct*"
    Else
        $sDataOriginalDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "zlib_compress2", $sDataCompressedDllType, $dataCompressed, $sSizeDataCompressedDllType, $sizeDataCompressed, $sDataOriginalDllType, $dataOriginal, "int", $sizeDataOriginal, "int", $compressionLevel), "zlib_compress2", @error)
EndFunc   ;==>_zlib_compress2

Func _zlib_uncompress($dataUncompressed, $sizeDataUncompressed, $compressedData, $sizeDataCompressed)
    ; CVAPI(void) zlib_uncompress(Byte* dataUncompressed, int* sizeDataUncompressed, Byte* compressedData, int sizeDataCompressed);

    Local $sDataUncompressedDllType
    If IsDllStruct($dataUncompressed) Then
        $sDataUncompressedDllType = "struct*"
    Else
        $sDataUncompressedDllType = "ptr"
    EndIf

    Local $sSizeDataUncompressedDllType
    If IsDllStruct($sizeDataUncompressed) Then
        $sSizeDataUncompressedDllType = "struct*"
    Else
        $sSizeDataUncompressedDllType = "int*"
    EndIf

    Local $sCompressedDataDllType
    If IsDllStruct($compressedData) Then
        $sCompressedDataDllType = "struct*"
    Else
        $sCompressedDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "zlib_uncompress", $sDataUncompressedDllType, $dataUncompressed, $sSizeDataUncompressedDllType, $sizeDataUncompressed, $sCompressedDataDllType, $compressedData, "int", $sizeDataCompressed), "zlib_uncompress", @error)
EndFunc   ;==>_zlib_uncompress