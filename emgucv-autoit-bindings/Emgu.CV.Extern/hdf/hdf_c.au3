#include-once
#include "..\..\CVEUtils.au3"

Func _cveHDF5Create($fileName, ByRef $sharedPtr)
    ; CVAPI(cv::hdf::HDF5*) cveHDF5Create(cv::String* fileName, cv::Ptr<cv::hdf::HDF5>** sharedPtr);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHDF5Create", "ptr", $fileName, "ptr*", $sharedPtr), "cveHDF5Create", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveHDF5Create

Func _cveHDF5Release(ByRef $hdfPtr)
    ; CVAPI(void) cveHDF5Release(cv::Ptr<cv::hdf::HDF5>** hdfPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5Release", "ptr*", $hdfPtr), "cveHDF5Release", @error)
EndFunc   ;==>_cveHDF5Release

Func _cveHDF5GrCreate(ByRef $hdf, $grlabel)
    ; CVAPI(void) cveHDF5GrCreate(cv::hdf::HDF5* hdf, cv::String* grlabel);

    Local $bGrlabelIsString = VarGetType($grlabel) == "String"
    If $bGrlabelIsString Then
        $grlabel = _cveStringCreateFromStr($grlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5GrCreate", "ptr", $hdf, "ptr", $grlabel), "cveHDF5GrCreate", @error)

    If $bGrlabelIsString Then
        _cveStringRelease($grlabel)
    EndIf
EndFunc   ;==>_cveHDF5GrCreate

Func _cveHDF5HlExists(ByRef $hdf, $label)
    ; CVAPI(bool) cveHDF5HlExists(cv::hdf::HDF5* hdf, cv::String* label);

    Local $bLabelIsString = VarGetType($label) == "String"
    If $bLabelIsString Then
        $label = _cveStringCreateFromStr($label)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHDF5HlExists", "ptr", $hdf, "ptr", $label), "cveHDF5HlExists", @error)

    If $bLabelIsString Then
        _cveStringRelease($label)
    EndIf

    Return $retval
EndFunc   ;==>_cveHDF5HlExists

Func _cveHDF5DsCreate(ByRef $hdf, $rows, $cols, $type, $dslabel, $compresslevel, ByRef $dims_chunks)
    ; CVAPI(void) cveHDF5DsCreate(cv::hdf::HDF5* hdf, int rows, int cols, int type, cv::String* dslabel, int compresslevel, std::vector<int>* dims_chunks);

    Local $bDslabelIsString = VarGetType($dslabel) == "String"
    If $bDslabelIsString Then
        $dslabel = _cveStringCreateFromStr($dslabel)
    EndIf

    Local $vecDims_chunks, $iArrDims_chunksSize
    Local $bDims_chunksIsArray = VarGetType($dims_chunks) == "Array"

    If $bDims_chunksIsArray Then
        $vecDims_chunks = _VectorOfIntCreate()

        $iArrDims_chunksSize = UBound($dims_chunks)
        For $i = 0 To $iArrDims_chunksSize - 1
            _VectorOfIntPush($vecDims_chunks, $dims_chunks[$i])
        Next
    Else
        $vecDims_chunks = $dims_chunks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5DsCreate", "ptr", $hdf, "int", $rows, "int", $cols, "int", $type, "ptr", $dslabel, "int", $compresslevel, "ptr", $vecDims_chunks), "cveHDF5DsCreate", @error)

    If $bDims_chunksIsArray Then
        _VectorOfIntRelease($vecDims_chunks)
    EndIf

    If $bDslabelIsString Then
        _cveStringRelease($dslabel)
    EndIf
EndFunc   ;==>_cveHDF5DsCreate

Func _cveHDF5DsWrite(ByRef $hdf, ByRef $Array, $dslabel)
    ; CVAPI(void) cveHDF5DsWrite(cv::hdf::HDF5* hdf, cv::_InputArray* Array, cv::String* dslabel);

    Local $bDslabelIsString = VarGetType($dslabel) == "String"
    If $bDslabelIsString Then
        $dslabel = _cveStringCreateFromStr($dslabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5DsWrite", "ptr", $hdf, "ptr", $Array, "ptr", $dslabel), "cveHDF5DsWrite", @error)

    If $bDslabelIsString Then
        _cveStringRelease($dslabel)
    EndIf
EndFunc   ;==>_cveHDF5DsWrite

Func _cveHDF5DsWriteMat(ByRef $hdf, ByRef $matArray, $dslabel)
    ; cveHDF5DsWrite using cv::Mat instead of _*Array

    Local $iArrArray, $vectorOfMatArray, $iArrArraySize
    Local $bArrayIsArray = VarGetType($matArray) == "Array"

    If $bArrayIsArray Then
        $vectorOfMatArray = _VectorOfMatCreate()

        $iArrArraySize = UBound($matArray)
        For $i = 0 To $iArrArraySize - 1
            _VectorOfMatPush($vectorOfMatArray, $matArray[$i])
        Next

        $iArrArray = _cveInputArrayFromVectorOfMat($vectorOfMatArray)
    Else
        $iArrArray = _cveInputArrayFromMat($matArray)
    EndIf

    _cveHDF5DsWrite($hdf, $iArrArray, $dslabel)

    If $bArrayIsArray Then
        _VectorOfMatRelease($vectorOfMatArray)
    EndIf

    _cveInputArrayRelease($iArrArray)
EndFunc   ;==>_cveHDF5DsWriteMat

Func _cveHDF5DsRead(ByRef $hdf, ByRef $Array, $dslabel)
    ; CVAPI(void) cveHDF5DsRead(cv::hdf::HDF5* hdf, cv::_OutputArray* Array, cv::String* dslabel);

    Local $bDslabelIsString = VarGetType($dslabel) == "String"
    If $bDslabelIsString Then
        $dslabel = _cveStringCreateFromStr($dslabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5DsRead", "ptr", $hdf, "ptr", $Array, "ptr", $dslabel), "cveHDF5DsRead", @error)

    If $bDslabelIsString Then
        _cveStringRelease($dslabel)
    EndIf
EndFunc   ;==>_cveHDF5DsRead

Func _cveHDF5DsReadMat(ByRef $hdf, ByRef $matArray, $dslabel)
    ; cveHDF5DsRead using cv::Mat instead of _*Array

    Local $oArrArray, $vectorOfMatArray, $iArrArraySize
    Local $bArrayIsArray = VarGetType($matArray) == "Array"

    If $bArrayIsArray Then
        $vectorOfMatArray = _VectorOfMatCreate()

        $iArrArraySize = UBound($matArray)
        For $i = 0 To $iArrArraySize - 1
            _VectorOfMatPush($vectorOfMatArray, $matArray[$i])
        Next

        $oArrArray = _cveOutputArrayFromVectorOfMat($vectorOfMatArray)
    Else
        $oArrArray = _cveOutputArrayFromMat($matArray)
    EndIf

    _cveHDF5DsRead($hdf, $oArrArray, $dslabel)

    If $bArrayIsArray Then
        _VectorOfMatRelease($vectorOfMatArray)
    EndIf

    _cveOutputArrayRelease($oArrArray)
EndFunc   ;==>_cveHDF5DsReadMat

Func _cveHDF5AtExists(ByRef $hdf, $atlabel)
    ; CVAPI(bool) cveHDF5AtExists(cv::hdf::HDF5* hdf, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHDF5AtExists", "ptr", $hdf, "ptr", $atlabel), "cveHDF5AtExists", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf

    Return $retval
EndFunc   ;==>_cveHDF5AtExists

Func _cveHDF5AtDelete(ByRef $hdf, $atlabel)
    ; CVAPI(void) cveHDF5AtDelete(cv::hdf::HDF5* hdf, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtDelete", "ptr", $hdf, "ptr", $atlabel), "cveHDF5AtDelete", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtDelete

Func _cveHDF5AtWriteInt(ByRef $hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteInt(cv::hdf::HDF5* hdf, int value, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteInt", "ptr", $hdf, "int", $value, "ptr", $atlabel), "cveHDF5AtWriteInt", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteInt

Func _cveHDF5AtReadInt(ByRef $hdf, ByRef $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadInt(cv::hdf::HDF5* hdf, int* value, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadInt", "ptr", $hdf, "struct*", $value, "ptr", $atlabel), "cveHDF5AtReadInt", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtReadInt

Func _cveHDF5AtWriteDouble(ByRef $hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteDouble(cv::hdf::HDF5* hdf, double value, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteDouble", "ptr", $hdf, "double", $value, "ptr", $atlabel), "cveHDF5AtWriteDouble", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteDouble

Func _cveHDF5AtReadDouble(ByRef $hdf, ByRef $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadDouble(cv::hdf::HDF5* hdf, double* value, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadDouble", "ptr", $hdf, "struct*", $value, "ptr", $atlabel), "cveHDF5AtReadDouble", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtReadDouble

Func _cveHDF5AtWriteString(ByRef $hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteString(cv::hdf::HDF5* hdf, cv::String* value, cv::String* atlabel);

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteString", "ptr", $hdf, "ptr", $value, "ptr", $atlabel), "cveHDF5AtWriteString", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteString

Func _cveHDF5AtReadString(ByRef $hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadString(cv::hdf::HDF5* hdf, cv::String* value, cv::String* atlabel);

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadString", "ptr", $hdf, "ptr", $value, "ptr", $atlabel), "cveHDF5AtReadString", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf
EndFunc   ;==>_cveHDF5AtReadString

Func _cveHDF5AtReadArray(ByRef $hdf, ByRef $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadArray(cv::hdf::HDF5* hdf, cv::_OutputArray* value, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadArray", "ptr", $hdf, "ptr", $value, "ptr", $atlabel), "cveHDF5AtReadArray", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtReadArray

Func _cveHDF5AtReadArrayMat(ByRef $hdf, ByRef $matValue, $atlabel)
    ; cveHDF5AtReadArray using cv::Mat instead of _*Array

    Local $oArrValue, $vectorOfMatValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($matValue) == "Array"

    If $bValueIsArray Then
        $vectorOfMatValue = _VectorOfMatCreate()

        $iArrValueSize = UBound($matValue)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfMatPush($vectorOfMatValue, $matValue[$i])
        Next

        $oArrValue = _cveOutputArrayFromVectorOfMat($vectorOfMatValue)
    Else
        $oArrValue = _cveOutputArrayFromMat($matValue)
    EndIf

    _cveHDF5AtReadArray($hdf, $oArrValue, $atlabel)

    If $bValueIsArray Then
        _VectorOfMatRelease($vectorOfMatValue)
    EndIf

    _cveOutputArrayRelease($oArrValue)
EndFunc   ;==>_cveHDF5AtReadArrayMat

Func _cveHDF5AtWriteArray(ByRef $hdf, ByRef $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteArray(cv::hdf::HDF5* hdf, cv::_InputArray* value, cv::String* atlabel);

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteArray", "ptr", $hdf, "ptr", $value, "ptr", $atlabel), "cveHDF5AtWriteArray", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteArray

Func _cveHDF5AtWriteArrayMat(ByRef $hdf, ByRef $matValue, $atlabel)
    ; cveHDF5AtWriteArray using cv::Mat instead of _*Array

    Local $iArrValue, $vectorOfMatValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($matValue) == "Array"

    If $bValueIsArray Then
        $vectorOfMatValue = _VectorOfMatCreate()

        $iArrValueSize = UBound($matValue)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfMatPush($vectorOfMatValue, $matValue[$i])
        Next

        $iArrValue = _cveInputArrayFromVectorOfMat($vectorOfMatValue)
    Else
        $iArrValue = _cveInputArrayFromMat($matValue)
    EndIf

    _cveHDF5AtWriteArray($hdf, $iArrValue, $atlabel)

    If $bValueIsArray Then
        _VectorOfMatRelease($vectorOfMatValue)
    EndIf

    _cveInputArrayRelease($iArrValue)
EndFunc   ;==>_cveHDF5AtWriteArrayMat

Func _cveHDF5KpRead(ByRef $hdf, ByRef $keypoints, $kplabel, $offset, $counts)
    ; CVAPI(void) cveHDF5KpRead(cv::hdf::HDF5* hdf, std::vector<cv::KeyPoint>* keypoints, cv::String* kplabel, int offset, int counts);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $bKplabelIsString = VarGetType($kplabel) == "String"
    If $bKplabelIsString Then
        $kplabel = _cveStringCreateFromStr($kplabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5KpRead", "ptr", $hdf, "ptr", $vecKeypoints, "ptr", $kplabel, "int", $offset, "int", $counts), "cveHDF5KpRead", @error)

    If $bKplabelIsString Then
        _cveStringRelease($kplabel)
    EndIf

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveHDF5KpRead

Func _cveHDF5KpWrite(ByRef $hdf, ByRef $keypoints, $kplabel, $offset, $counts)
    ; CVAPI(void) cveHDF5KpWrite(cv::hdf::HDF5* hdf, std::vector<cv::KeyPoint>* keypoints, cv::String* kplabel, int offset, int counts);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $bKplabelIsString = VarGetType($kplabel) == "String"
    If $bKplabelIsString Then
        $kplabel = _cveStringCreateFromStr($kplabel)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5KpWrite", "ptr", $hdf, "ptr", $vecKeypoints, "ptr", $kplabel, "int", $offset, "int", $counts), "cveHDF5KpWrite", @error)

    If $bKplabelIsString Then
        _cveStringRelease($kplabel)
    EndIf

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveHDF5KpWrite

Func _cveHDF5Close(ByRef $hdf)
    ; CVAPI(void) cveHDF5Close(cv::hdf::HDF5* hdf);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5Close", "ptr", $hdf), "cveHDF5Close", @error)
EndFunc   ;==>_cveHDF5Close