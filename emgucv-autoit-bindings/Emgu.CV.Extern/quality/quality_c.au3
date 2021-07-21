#include-once
#include "..\..\CVEUtils.au3"

Func _cveQualityBaseCompute($qualityBase, $cmpImgs, $score)
    ; CVAPI(void) cveQualityBaseCompute(cv::quality::QualityBase* qualityBase, cv::_InputArray* cmpImgs, CvScalar* score);

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr"
    EndIf

    Local $bCmpImgsDllType
    If VarGetType($cmpImgs) == "DLLStruct" Then
        $bCmpImgsDllType = "struct*"
    Else
        $bCmpImgsDllType = "ptr"
    EndIf

    Local $bScoreDllType
    If VarGetType($score) == "DLLStruct" Then
        $bScoreDllType = "struct*"
    Else
        $bScoreDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBaseCompute", $bQualityBaseDllType, $qualityBase, $bCmpImgsDllType, $cmpImgs, $bScoreDllType, $score), "cveQualityBaseCompute", @error)
EndFunc   ;==>_cveQualityBaseCompute

Func _cveQualityBaseComputeMat($qualityBase, $matCmpImgs, $score)
    ; cveQualityBaseCompute using cv::Mat instead of _*Array

    Local $iArrCmpImgs, $vectorOfMatCmpImgs, $iArrCmpImgsSize
    Local $bCmpImgsIsArray = VarGetType($matCmpImgs) == "Array"

    If $bCmpImgsIsArray Then
        $vectorOfMatCmpImgs = _VectorOfMatCreate()

        $iArrCmpImgsSize = UBound($matCmpImgs)
        For $i = 0 To $iArrCmpImgsSize - 1
            _VectorOfMatPush($vectorOfMatCmpImgs, $matCmpImgs[$i])
        Next

        $iArrCmpImgs = _cveInputArrayFromVectorOfMat($vectorOfMatCmpImgs)
    Else
        $iArrCmpImgs = _cveInputArrayFromMat($matCmpImgs)
    EndIf

    _cveQualityBaseCompute($qualityBase, $iArrCmpImgs, $score)

    If $bCmpImgsIsArray Then
        _VectorOfMatRelease($vectorOfMatCmpImgs)
    EndIf

    _cveInputArrayRelease($iArrCmpImgs)
EndFunc   ;==>_cveQualityBaseComputeMat

Func _cveQualityBaseGetQualityMap($qualityBase, $dst)
    ; CVAPI(void) cveQualityBaseGetQualityMap(cv::quality::QualityBase* qualityBase, cv::_OutputArray* dst);

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBaseGetQualityMap", $bQualityBaseDllType, $qualityBase, $bDstDllType, $dst), "cveQualityBaseGetQualityMap", @error)
EndFunc   ;==>_cveQualityBaseGetQualityMap

Func _cveQualityBaseGetQualityMapMat($qualityBase, $matDst)
    ; cveQualityBaseGetQualityMap using cv::Mat instead of _*Array

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cveQualityBaseGetQualityMap($qualityBase, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_cveQualityBaseGetQualityMapMat

Func _cveQualityMSECreate($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityMSE*) cveQualityMSECreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityMSE>** sharedPtr);

    Local $bRefImgsDllType
    If VarGetType($refImgs) == "DLLStruct" Then
        $bRefImgsDllType = "struct*"
    Else
        $bRefImgsDllType = "ptr"
    EndIf

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityMSECreate", $bRefImgsDllType, $refImgs, $bQualityBaseDllType, $qualityBase, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveQualityMSECreate", @error)
EndFunc   ;==>_cveQualityMSECreate

Func _cveQualityMSECreateMat($matRefImgs, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualityMSECreate using cv::Mat instead of _*Array

    Local $iArrRefImgs, $vectorOfMatRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = VarGetType($matRefImgs) == "Array"

    If $bRefImgsIsArray Then
        $vectorOfMatRefImgs = _VectorOfMatCreate()

        $iArrRefImgsSize = UBound($matRefImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            _VectorOfMatPush($vectorOfMatRefImgs, $matRefImgs[$i])
        Next

        $iArrRefImgs = _cveInputArrayFromVectorOfMat($vectorOfMatRefImgs)
    Else
        $iArrRefImgs = _cveInputArrayFromMat($matRefImgs)
    EndIf

    Local $retval = _cveQualityMSECreate($iArrRefImgs, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        _VectorOfMatRelease($vectorOfMatRefImgs)
    EndIf

    _cveInputArrayRelease($iArrRefImgs)

    Return $retval
EndFunc   ;==>_cveQualityMSECreateMat

Func _cveQualityMSERelease($sharedPtr)
    ; CVAPI(void) cveQualityMSERelease(cv::Ptr<cv::quality::QualityMSE>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityMSERelease", $bSharedPtrDllType, $sharedPtr), "cveQualityMSERelease", @error)
EndFunc   ;==>_cveQualityMSERelease

Func _cveQualityBRISQUECreate($modelFilePath, $rangeFilePath, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityBRISQUE*) cveQualityBRISQUECreate(cv::String* modelFilePath, cv::String* rangeFilePath, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityBRISQUE>** sharedPtr);

    Local $bModelFilePathIsString = VarGetType($modelFilePath) == "String"
    If $bModelFilePathIsString Then
        $modelFilePath = _cveStringCreateFromStr($modelFilePath)
    EndIf

    Local $bModelFilePathDllType
    If VarGetType($modelFilePath) == "DLLStruct" Then
        $bModelFilePathDllType = "struct*"
    Else
        $bModelFilePathDllType = "ptr"
    EndIf

    Local $bRangeFilePathIsString = VarGetType($rangeFilePath) == "String"
    If $bRangeFilePathIsString Then
        $rangeFilePath = _cveStringCreateFromStr($rangeFilePath)
    EndIf

    Local $bRangeFilePathDllType
    If VarGetType($rangeFilePath) == "DLLStruct" Then
        $bRangeFilePathDllType = "struct*"
    Else
        $bRangeFilePathDllType = "ptr"
    EndIf

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityBRISQUECreate", $bModelFilePathDllType, $modelFilePath, $bRangeFilePathDllType, $rangeFilePath, $bQualityBaseDllType, $qualityBase, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveQualityBRISQUECreate", @error)

    If $bRangeFilePathIsString Then
        _cveStringRelease($rangeFilePath)
    EndIf

    If $bModelFilePathIsString Then
        _cveStringRelease($modelFilePath)
    EndIf

    Return $retval
EndFunc   ;==>_cveQualityBRISQUECreate

Func _cveQualityBRISQUERelease($sharedPtr)
    ; CVAPI(void) cveQualityBRISQUERelease(cv::Ptr<cv::quality::QualityBRISQUE>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBRISQUERelease", $bSharedPtrDllType, $sharedPtr), "cveQualityBRISQUERelease", @error)
EndFunc   ;==>_cveQualityBRISQUERelease

Func _cveQualityPSNRCreate($refImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityPSNR*) cveQualityPSNRCreate(cv::_InputArray* refImgs, double maxPixelValue, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityPSNR>** sharedPtr);

    Local $bRefImgsDllType
    If VarGetType($refImgs) == "DLLStruct" Then
        $bRefImgsDllType = "struct*"
    Else
        $bRefImgsDllType = "ptr"
    EndIf

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityPSNRCreate", $bRefImgsDllType, $refImgs, "double", $maxPixelValue, $bQualityBaseDllType, $qualityBase, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveQualityPSNRCreate", @error)
EndFunc   ;==>_cveQualityPSNRCreate

Func _cveQualityPSNRCreateMat($matRefImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualityPSNRCreate using cv::Mat instead of _*Array

    Local $iArrRefImgs, $vectorOfMatRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = VarGetType($matRefImgs) == "Array"

    If $bRefImgsIsArray Then
        $vectorOfMatRefImgs = _VectorOfMatCreate()

        $iArrRefImgsSize = UBound($matRefImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            _VectorOfMatPush($vectorOfMatRefImgs, $matRefImgs[$i])
        Next

        $iArrRefImgs = _cveInputArrayFromVectorOfMat($vectorOfMatRefImgs)
    Else
        $iArrRefImgs = _cveInputArrayFromMat($matRefImgs)
    EndIf

    Local $retval = _cveQualityPSNRCreate($iArrRefImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        _VectorOfMatRelease($vectorOfMatRefImgs)
    EndIf

    _cveInputArrayRelease($iArrRefImgs)

    Return $retval
EndFunc   ;==>_cveQualityPSNRCreateMat

Func _cveQualityPSNRRelease($sharedPtr)
    ; CVAPI(void) cveQualityPSNRRelease(cv::Ptr<cv::quality::QualityPSNR>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityPSNRRelease", $bSharedPtrDllType, $sharedPtr), "cveQualityPSNRRelease", @error)
EndFunc   ;==>_cveQualityPSNRRelease

Func _cveQualitySSIMCreate($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualitySSIM*) cveQualitySSIMCreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualitySSIM>** sharedPtr);

    Local $bRefImgsDllType
    If VarGetType($refImgs) == "DLLStruct" Then
        $bRefImgsDllType = "struct*"
    Else
        $bRefImgsDllType = "ptr"
    EndIf

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualitySSIMCreate", $bRefImgsDllType, $refImgs, $bQualityBaseDllType, $qualityBase, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveQualitySSIMCreate", @error)
EndFunc   ;==>_cveQualitySSIMCreate

Func _cveQualitySSIMCreateMat($matRefImgs, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualitySSIMCreate using cv::Mat instead of _*Array

    Local $iArrRefImgs, $vectorOfMatRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = VarGetType($matRefImgs) == "Array"

    If $bRefImgsIsArray Then
        $vectorOfMatRefImgs = _VectorOfMatCreate()

        $iArrRefImgsSize = UBound($matRefImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            _VectorOfMatPush($vectorOfMatRefImgs, $matRefImgs[$i])
        Next

        $iArrRefImgs = _cveInputArrayFromVectorOfMat($vectorOfMatRefImgs)
    Else
        $iArrRefImgs = _cveInputArrayFromMat($matRefImgs)
    EndIf

    Local $retval = _cveQualitySSIMCreate($iArrRefImgs, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        _VectorOfMatRelease($vectorOfMatRefImgs)
    EndIf

    _cveInputArrayRelease($iArrRefImgs)

    Return $retval
EndFunc   ;==>_cveQualitySSIMCreateMat

Func _cveQualitySSIMRelease($sharedPtr)
    ; CVAPI(void) cveQualitySSIMRelease(cv::Ptr<cv::quality::QualitySSIM>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualitySSIMRelease", $bSharedPtrDllType, $sharedPtr), "cveQualitySSIMRelease", @error)
EndFunc   ;==>_cveQualitySSIMRelease

Func _cveQualityGMSDCreate($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityGMSD*) cveQualityGMSDCreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityGMSD>** sharedPtr);

    Local $bRefImgsDllType
    If VarGetType($refImgs) == "DLLStruct" Then
        $bRefImgsDllType = "struct*"
    Else
        $bRefImgsDllType = "ptr"
    EndIf

    Local $bQualityBaseDllType
    If VarGetType($qualityBase) == "DLLStruct" Then
        $bQualityBaseDllType = "struct*"
    Else
        $bQualityBaseDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityGMSDCreate", $bRefImgsDllType, $refImgs, $bQualityBaseDllType, $qualityBase, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveQualityGMSDCreate", @error)
EndFunc   ;==>_cveQualityGMSDCreate

Func _cveQualityGMSDCreateMat($matRefImgs, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualityGMSDCreate using cv::Mat instead of _*Array

    Local $iArrRefImgs, $vectorOfMatRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = VarGetType($matRefImgs) == "Array"

    If $bRefImgsIsArray Then
        $vectorOfMatRefImgs = _VectorOfMatCreate()

        $iArrRefImgsSize = UBound($matRefImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            _VectorOfMatPush($vectorOfMatRefImgs, $matRefImgs[$i])
        Next

        $iArrRefImgs = _cveInputArrayFromVectorOfMat($vectorOfMatRefImgs)
    Else
        $iArrRefImgs = _cveInputArrayFromMat($matRefImgs)
    EndIf

    Local $retval = _cveQualityGMSDCreate($iArrRefImgs, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        _VectorOfMatRelease($vectorOfMatRefImgs)
    EndIf

    _cveInputArrayRelease($iArrRefImgs)

    Return $retval
EndFunc   ;==>_cveQualityGMSDCreateMat

Func _cveQualityGMSDRelease($sharedPtr)
    ; CVAPI(void) cveQualityGMSDRelease(cv::Ptr<cv::quality::QualityGMSD>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityGMSDRelease", $bSharedPtrDllType, $sharedPtr), "cveQualityGMSDRelease", @error)
EndFunc   ;==>_cveQualityGMSDRelease