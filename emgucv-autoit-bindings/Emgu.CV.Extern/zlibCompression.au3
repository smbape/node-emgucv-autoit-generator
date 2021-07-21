#include-once
#include "..\CVEUtils.au3"

Func _zlib_compress_bound($length)
    ; CVAPI(int) zlib_compress_bound(int length);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "zlib_compress_bound", "int", $length), "zlib_compress_bound", @error)
EndFunc   ;==>_zlib_compress_bound

Func _zlib_compress2($dataCompressed, $sizeDataCompressed, $dataOriginal, $sizeDataOriginal, $compressionLevel)
    ; CVAPI(void) zlib_compress2(Byte* dataCompressed, int* sizeDataCompressed, Byte* dataOriginal, int sizeDataOriginal, int compressionLevel);

    Local $bDataCompressedDllType
    If VarGetType($dataCompressed) == "DLLStruct" Then
        $bDataCompressedDllType = "struct*"
    Else
        $bDataCompressedDllType = "ptr"
    EndIf

    Local $bSizeDataCompressedDllType
    If VarGetType($sizeDataCompressed) == "DLLStruct" Then
        $bSizeDataCompressedDllType = "struct*"
    Else
        $bSizeDataCompressedDllType = "int*"
    EndIf

    Local $bDataOriginalDllType
    If VarGetType($dataOriginal) == "DLLStruct" Then
        $bDataOriginalDllType = "struct*"
    Else
        $bDataOriginalDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "zlib_compress2", $bDataCompressedDllType, $dataCompressed, $bSizeDataCompressedDllType, $sizeDataCompressed, $bDataOriginalDllType, $dataOriginal, "int", $sizeDataOriginal, "int", $compressionLevel), "zlib_compress2", @error)
EndFunc   ;==>_zlib_compress2

Func _zlib_uncompress($dataUncompressed, $sizeDataUncompressed, $compressedData, $sizeDataCompressed)
    ; CVAPI(void) zlib_uncompress(Byte* dataUncompressed, int* sizeDataUncompressed, Byte* compressedData, int sizeDataCompressed);

    Local $bDataUncompressedDllType
    If VarGetType($dataUncompressed) == "DLLStruct" Then
        $bDataUncompressedDllType = "struct*"
    Else
        $bDataUncompressedDllType = "ptr"
    EndIf

    Local $bSizeDataUncompressedDllType
    If VarGetType($sizeDataUncompressed) == "DLLStruct" Then
        $bSizeDataUncompressedDllType = "struct*"
    Else
        $bSizeDataUncompressedDllType = "int*"
    EndIf

    Local $bCompressedDataDllType
    If VarGetType($compressedData) == "DLLStruct" Then
        $bCompressedDataDllType = "struct*"
    Else
        $bCompressedDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "zlib_uncompress", $bDataUncompressedDllType, $dataUncompressed, $bSizeDataUncompressedDllType, $sizeDataUncompressed, $bCompressedDataDllType, $compressedData, "int", $sizeDataCompressed), "zlib_uncompress", @error)
EndFunc   ;==>_zlib_uncompress