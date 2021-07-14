#include-once
#include <..\CVEUtils.au3>

Func _zlib_compress_bound($length)
    ; CVAPI(int) zlib_compress_bound(int length);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "zlib_compress_bound", "int", $length), "zlib_compress_bound", @error)
EndFunc   ;==>_zlib_compress_bound

Func _zlib_compress2(ByRef $dataCompressed, ByRef $sizeDataCompressed, ByRef $dataOriginal, $sizeDataOriginal, $compressionLevel)
    ; CVAPI(void) zlib_compress2(Byte* dataCompressed, int* sizeDataCompressed, Byte* dataOriginal, int sizeDataOriginal, int compressionLevel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "zlib_compress2", "struct*", $dataCompressed, "struct*", $sizeDataCompressed, "struct*", $dataOriginal, "int", $sizeDataOriginal, "int", $compressionLevel), "zlib_compress2", @error)
EndFunc   ;==>_zlib_compress2

Func _zlib_uncompress(ByRef $dataUncompressed, ByRef $sizeDataUncompressed, ByRef $compressedData, $sizeDataCompressed)
    ; CVAPI(void) zlib_uncompress(Byte* dataUncompressed, int* sizeDataUncompressed, Byte* compressedData, int sizeDataCompressed);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "zlib_uncompress", "struct*", $dataUncompressed, "struct*", $sizeDataUncompressed, "struct*", $compressedData, "int", $sizeDataCompressed), "zlib_uncompress", @error)
EndFunc   ;==>_zlib_uncompress