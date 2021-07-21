#include-once
#include "..\..\CVEUtils.au3"

Func _cveHDF5Create($fileName, $sharedPtr)
    ; CVAPI(cv::hdf::HDF5*) cveHDF5Create(cv::String* fileName, cv::Ptr<cv::hdf::HDF5>** sharedPtr);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHDF5Create", $bFileNameDllType, $fileName, $bSharedPtrDllType, $sharedPtr), "cveHDF5Create", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveHDF5Create

Func _cveHDF5Release($hdfPtr)
    ; CVAPI(void) cveHDF5Release(cv::Ptr<cv::hdf::HDF5>** hdfPtr);

    Local $bHdfPtrDllType
    If VarGetType($hdfPtr) == "DLLStruct" Then
        $bHdfPtrDllType = "struct*"
    Else
        $bHdfPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5Release", $bHdfPtrDllType, $hdfPtr), "cveHDF5Release", @error)
EndFunc   ;==>_cveHDF5Release

Func _cveHDF5GrCreate($hdf, $grlabel)
    ; CVAPI(void) cveHDF5GrCreate(cv::hdf::HDF5* hdf, cv::String* grlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bGrlabelIsString = VarGetType($grlabel) == "String"
    If $bGrlabelIsString Then
        $grlabel = _cveStringCreateFromStr($grlabel)
    EndIf

    Local $bGrlabelDllType
    If VarGetType($grlabel) == "DLLStruct" Then
        $bGrlabelDllType = "struct*"
    Else
        $bGrlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5GrCreate", $bHdfDllType, $hdf, $bGrlabelDllType, $grlabel), "cveHDF5GrCreate", @error)

    If $bGrlabelIsString Then
        _cveStringRelease($grlabel)
    EndIf
EndFunc   ;==>_cveHDF5GrCreate

Func _cveHDF5HlExists($hdf, $label)
    ; CVAPI(bool) cveHDF5HlExists(cv::hdf::HDF5* hdf, cv::String* label);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bLabelIsString = VarGetType($label) == "String"
    If $bLabelIsString Then
        $label = _cveStringCreateFromStr($label)
    EndIf

    Local $bLabelDllType
    If VarGetType($label) == "DLLStruct" Then
        $bLabelDllType = "struct*"
    Else
        $bLabelDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHDF5HlExists", $bHdfDllType, $hdf, $bLabelDllType, $label), "cveHDF5HlExists", @error)

    If $bLabelIsString Then
        _cveStringRelease($label)
    EndIf

    Return $retval
EndFunc   ;==>_cveHDF5HlExists

Func _cveHDF5DsCreate($hdf, $rows, $cols, $type, $dslabel, $compresslevel, $dims_chunks)
    ; CVAPI(void) cveHDF5DsCreate(cv::hdf::HDF5* hdf, int rows, int cols, int type, cv::String* dslabel, int compresslevel, std::vector<int>* dims_chunks);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bDslabelIsString = VarGetType($dslabel) == "String"
    If $bDslabelIsString Then
        $dslabel = _cveStringCreateFromStr($dslabel)
    EndIf

    Local $bDslabelDllType
    If VarGetType($dslabel) == "DLLStruct" Then
        $bDslabelDllType = "struct*"
    Else
        $bDslabelDllType = "ptr"
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

    Local $bDims_chunksDllType
    If VarGetType($dims_chunks) == "DLLStruct" Then
        $bDims_chunksDllType = "struct*"
    Else
        $bDims_chunksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5DsCreate", $bHdfDllType, $hdf, "int", $rows, "int", $cols, "int", $type, $bDslabelDllType, $dslabel, "int", $compresslevel, $bDims_chunksDllType, $vecDims_chunks), "cveHDF5DsCreate", @error)

    If $bDims_chunksIsArray Then
        _VectorOfIntRelease($vecDims_chunks)
    EndIf

    If $bDslabelIsString Then
        _cveStringRelease($dslabel)
    EndIf
EndFunc   ;==>_cveHDF5DsCreate

Func _cveHDF5DsWrite($hdf, $Array, $dslabel)
    ; CVAPI(void) cveHDF5DsWrite(cv::hdf::HDF5* hdf, cv::_InputArray* Array, cv::String* dslabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bArrayDllType
    If VarGetType($Array) == "DLLStruct" Then
        $bArrayDllType = "struct*"
    Else
        $bArrayDllType = "ptr"
    EndIf

    Local $bDslabelIsString = VarGetType($dslabel) == "String"
    If $bDslabelIsString Then
        $dslabel = _cveStringCreateFromStr($dslabel)
    EndIf

    Local $bDslabelDllType
    If VarGetType($dslabel) == "DLLStruct" Then
        $bDslabelDllType = "struct*"
    Else
        $bDslabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5DsWrite", $bHdfDllType, $hdf, $bArrayDllType, $Array, $bDslabelDllType, $dslabel), "cveHDF5DsWrite", @error)

    If $bDslabelIsString Then
        _cveStringRelease($dslabel)
    EndIf
EndFunc   ;==>_cveHDF5DsWrite

Func _cveHDF5DsWriteMat($hdf, $matArray, $dslabel)
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

Func _cveHDF5DsRead($hdf, $Array, $dslabel)
    ; CVAPI(void) cveHDF5DsRead(cv::hdf::HDF5* hdf, cv::_OutputArray* Array, cv::String* dslabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bArrayDllType
    If VarGetType($Array) == "DLLStruct" Then
        $bArrayDllType = "struct*"
    Else
        $bArrayDllType = "ptr"
    EndIf

    Local $bDslabelIsString = VarGetType($dslabel) == "String"
    If $bDslabelIsString Then
        $dslabel = _cveStringCreateFromStr($dslabel)
    EndIf

    Local $bDslabelDllType
    If VarGetType($dslabel) == "DLLStruct" Then
        $bDslabelDllType = "struct*"
    Else
        $bDslabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5DsRead", $bHdfDllType, $hdf, $bArrayDllType, $Array, $bDslabelDllType, $dslabel), "cveHDF5DsRead", @error)

    If $bDslabelIsString Then
        _cveStringRelease($dslabel)
    EndIf
EndFunc   ;==>_cveHDF5DsRead

Func _cveHDF5DsReadMat($hdf, $matArray, $dslabel)
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

Func _cveHDF5AtExists($hdf, $atlabel)
    ; CVAPI(bool) cveHDF5AtExists(cv::hdf::HDF5* hdf, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHDF5AtExists", $bHdfDllType, $hdf, $bAtlabelDllType, $atlabel), "cveHDF5AtExists", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf

    Return $retval
EndFunc   ;==>_cveHDF5AtExists

Func _cveHDF5AtDelete($hdf, $atlabel)
    ; CVAPI(void) cveHDF5AtDelete(cv::hdf::HDF5* hdf, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtDelete", $bHdfDllType, $hdf, $bAtlabelDllType, $atlabel), "cveHDF5AtDelete", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtDelete

Func _cveHDF5AtWriteInt($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteInt(cv::hdf::HDF5* hdf, int value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteInt", $bHdfDllType, $hdf, "int", $value, $bAtlabelDllType, $atlabel), "cveHDF5AtWriteInt", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteInt

Func _cveHDF5AtReadInt($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadInt(cv::hdf::HDF5* hdf, int* value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "int*"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadInt", $bHdfDllType, $hdf, $bValueDllType, $value, $bAtlabelDllType, $atlabel), "cveHDF5AtReadInt", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtReadInt

Func _cveHDF5AtWriteDouble($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteDouble(cv::hdf::HDF5* hdf, double value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteDouble", $bHdfDllType, $hdf, "double", $value, $bAtlabelDllType, $atlabel), "cveHDF5AtWriteDouble", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteDouble

Func _cveHDF5AtReadDouble($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadDouble(cv::hdf::HDF5* hdf, double* value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "double*"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadDouble", $bHdfDllType, $hdf, $bValueDllType, $value, $bAtlabelDllType, $atlabel), "cveHDF5AtReadDouble", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtReadDouble

Func _cveHDF5AtWriteString($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteString(cv::hdf::HDF5* hdf, cv::String* value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteString", $bHdfDllType, $hdf, $bValueDllType, $value, $bAtlabelDllType, $atlabel), "cveHDF5AtWriteString", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteString

Func _cveHDF5AtReadString($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadString(cv::hdf::HDF5* hdf, cv::String* value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadString", $bHdfDllType, $hdf, $bValueDllType, $value, $bAtlabelDllType, $atlabel), "cveHDF5AtReadString", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf
EndFunc   ;==>_cveHDF5AtReadString

Func _cveHDF5AtReadArray($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtReadArray(cv::hdf::HDF5* hdf, cv::_OutputArray* value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtReadArray", $bHdfDllType, $hdf, $bValueDllType, $value, $bAtlabelDllType, $atlabel), "cveHDF5AtReadArray", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtReadArray

Func _cveHDF5AtReadArrayMat($hdf, $matValue, $atlabel)
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

Func _cveHDF5AtWriteArray($hdf, $value, $atlabel)
    ; CVAPI(void) cveHDF5AtWriteArray(cv::hdf::HDF5* hdf, cv::_InputArray* value, cv::String* atlabel);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    Local $bAtlabelIsString = VarGetType($atlabel) == "String"
    If $bAtlabelIsString Then
        $atlabel = _cveStringCreateFromStr($atlabel)
    EndIf

    Local $bAtlabelDllType
    If VarGetType($atlabel) == "DLLStruct" Then
        $bAtlabelDllType = "struct*"
    Else
        $bAtlabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5AtWriteArray", $bHdfDllType, $hdf, $bValueDllType, $value, $bAtlabelDllType, $atlabel), "cveHDF5AtWriteArray", @error)

    If $bAtlabelIsString Then
        _cveStringRelease($atlabel)
    EndIf
EndFunc   ;==>_cveHDF5AtWriteArray

Func _cveHDF5AtWriteArrayMat($hdf, $matValue, $atlabel)
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

Func _cveHDF5KpRead($hdf, $keypoints, $kplabel, $offset, $counts)
    ; CVAPI(void) cveHDF5KpRead(cv::hdf::HDF5* hdf, std::vector<cv::KeyPoint>* keypoints, cv::String* kplabel, int offset, int counts);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bKplabelIsString = VarGetType($kplabel) == "String"
    If $bKplabelIsString Then
        $kplabel = _cveStringCreateFromStr($kplabel)
    EndIf

    Local $bKplabelDllType
    If VarGetType($kplabel) == "DLLStruct" Then
        $bKplabelDllType = "struct*"
    Else
        $bKplabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5KpRead", $bHdfDllType, $hdf, $bKeypointsDllType, $vecKeypoints, $bKplabelDllType, $kplabel, "int", $offset, "int", $counts), "cveHDF5KpRead", @error)

    If $bKplabelIsString Then
        _cveStringRelease($kplabel)
    EndIf

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveHDF5KpRead

Func _cveHDF5KpWrite($hdf, $keypoints, $kplabel, $offset, $counts)
    ; CVAPI(void) cveHDF5KpWrite(cv::hdf::HDF5* hdf, std::vector<cv::KeyPoint>* keypoints, cv::String* kplabel, int offset, int counts);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bKplabelIsString = VarGetType($kplabel) == "String"
    If $bKplabelIsString Then
        $kplabel = _cveStringCreateFromStr($kplabel)
    EndIf

    Local $bKplabelDllType
    If VarGetType($kplabel) == "DLLStruct" Then
        $bKplabelDllType = "struct*"
    Else
        $bKplabelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5KpWrite", $bHdfDllType, $hdf, $bKeypointsDllType, $vecKeypoints, $bKplabelDllType, $kplabel, "int", $offset, "int", $counts), "cveHDF5KpWrite", @error)

    If $bKplabelIsString Then
        _cveStringRelease($kplabel)
    EndIf

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveHDF5KpWrite

Func _cveHDF5Close($hdf)
    ; CVAPI(void) cveHDF5Close(cv::hdf::HDF5* hdf);

    Local $bHdfDllType
    If VarGetType($hdf) == "DLLStruct" Then
        $bHdfDllType = "struct*"
    Else
        $bHdfDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHDF5Close", $bHdfDllType, $hdf), "cveHDF5Close", @error)
EndFunc   ;==>_cveHDF5Close