#include-once
#include <..\..\CVEUtils.au3>

Func _cveQualityBaseCompute(ByRef $qualityBase, ByRef $cmpImgs, ByRef $score)
    ; CVAPI(void) cveQualityBaseCompute(cv::quality::QualityBase* qualityBase, cv::_InputArray* cmpImgs, CvScalar* score);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBaseCompute", "ptr", $qualityBase, "ptr", $cmpImgs, "struct*", $score), "cveQualityBaseCompute", @error)
EndFunc   ;==>_cveQualityBaseCompute

Func _cveQualityBaseComputeMat(ByRef $qualityBase, ByRef $matCmpImgs, ByRef $score)
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

Func _cveQualityBaseGetQualityMap(ByRef $qualityBase, ByRef $dst)
    ; CVAPI(void) cveQualityBaseGetQualityMap(cv::quality::QualityBase* qualityBase, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBaseGetQualityMap", "ptr", $qualityBase, "ptr", $dst), "cveQualityBaseGetQualityMap", @error)
EndFunc   ;==>_cveQualityBaseGetQualityMap

Func _cveQualityBaseGetQualityMapMat(ByRef $qualityBase, ByRef $matDst)
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

Func _cveQualityMSECreate(ByRef $refImgs, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::quality::QualityMSE*) cveQualityMSECreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityMSE>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityMSECreate", "ptr", $refImgs, "ptr*", $qualityBase, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveQualityMSECreate", @error)
EndFunc   ;==>_cveQualityMSECreate

Func _cveQualityMSECreateMat(ByRef $matRefImgs, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
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

Func _cveQualityMSERelease(ByRef $sharedPtr)
    ; CVAPI(void) cveQualityMSERelease(cv::Ptr<cv::quality::QualityMSE>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityMSERelease", "ptr*", $sharedPtr), "cveQualityMSERelease", @error)
EndFunc   ;==>_cveQualityMSERelease

Func _cveQualityBRISQUECreate($modelFilePath, $rangeFilePath, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::quality::QualityBRISQUE*) cveQualityBRISQUECreate(cv::String* modelFilePath, cv::String* rangeFilePath, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityBRISQUE>** sharedPtr);

    Local $bModelFilePathIsString = VarGetType($modelFilePath) == "String"
    If $bModelFilePathIsString Then
        $modelFilePath = _cveStringCreateFromStr($modelFilePath)
    EndIf

    Local $bRangeFilePathIsString = VarGetType($rangeFilePath) == "String"
    If $bRangeFilePathIsString Then
        $rangeFilePath = _cveStringCreateFromStr($rangeFilePath)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityBRISQUECreate", "ptr", $modelFilePath, "ptr", $rangeFilePath, "ptr*", $qualityBase, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveQualityBRISQUECreate", @error)

    If $bRangeFilePathIsString Then
        _cveStringRelease($rangeFilePath)
    EndIf

    If $bModelFilePathIsString Then
        _cveStringRelease($modelFilePath)
    EndIf

    Return $retval
EndFunc   ;==>_cveQualityBRISQUECreate

Func _cveQualityBRISQUERelease(ByRef $sharedPtr)
    ; CVAPI(void) cveQualityBRISQUERelease(cv::Ptr<cv::quality::QualityBRISQUE>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBRISQUERelease", "ptr*", $sharedPtr), "cveQualityBRISQUERelease", @error)
EndFunc   ;==>_cveQualityBRISQUERelease

Func _cveQualityPSNRCreate(ByRef $refImgs, $maxPixelValue, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::quality::QualityPSNR*) cveQualityPSNRCreate(cv::_InputArray* refImgs, double maxPixelValue, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityPSNR>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityPSNRCreate", "ptr", $refImgs, "double", $maxPixelValue, "ptr*", $qualityBase, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveQualityPSNRCreate", @error)
EndFunc   ;==>_cveQualityPSNRCreate

Func _cveQualityPSNRCreateMat(ByRef $matRefImgs, $maxPixelValue, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
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

Func _cveQualityPSNRRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveQualityPSNRRelease(cv::Ptr<cv::quality::QualityPSNR>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityPSNRRelease", "ptr*", $sharedPtr), "cveQualityPSNRRelease", @error)
EndFunc   ;==>_cveQualityPSNRRelease

Func _cveQualitySSIMCreate(ByRef $refImgs, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::quality::QualitySSIM*) cveQualitySSIMCreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualitySSIM>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualitySSIMCreate", "ptr", $refImgs, "ptr*", $qualityBase, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveQualitySSIMCreate", @error)
EndFunc   ;==>_cveQualitySSIMCreate

Func _cveQualitySSIMCreateMat(ByRef $matRefImgs, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
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

Func _cveQualitySSIMRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveQualitySSIMRelease(cv::Ptr<cv::quality::QualitySSIM>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualitySSIMRelease", "ptr*", $sharedPtr), "cveQualitySSIMRelease", @error)
EndFunc   ;==>_cveQualitySSIMRelease

Func _cveQualityGMSDCreate(ByRef $refImgs, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::quality::QualityGMSD*) cveQualityGMSDCreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityGMSD>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityGMSDCreate", "ptr", $refImgs, "ptr*", $qualityBase, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveQualityGMSDCreate", @error)
EndFunc   ;==>_cveQualityGMSDCreate

Func _cveQualityGMSDCreateMat(ByRef $matRefImgs, ByRef $qualityBase, ByRef $algorithm, ByRef $sharedPtr)
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

Func _cveQualityGMSDRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveQualityGMSDRelease(cv::Ptr<cv::quality::QualityGMSD>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityGMSDRelease", "ptr*", $sharedPtr), "cveQualityGMSDRelease", @error)
EndFunc   ;==>_cveQualityGMSDRelease