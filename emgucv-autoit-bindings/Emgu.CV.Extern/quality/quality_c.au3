#include-once
#include "..\..\CVEUtils.au3"

Func _cveQualityBaseCompute($qualityBase, $cmpImgs, $score)
    ; CVAPI(void) cveQualityBaseCompute(cv::quality::QualityBase* qualityBase, cv::_InputArray* cmpImgs, CvScalar* score);

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    Else
        $sQualityBaseDllType = "ptr"
    EndIf

    Local $sCmpImgsDllType
    If IsDllStruct($cmpImgs) Then
        $sCmpImgsDllType = "struct*"
    Else
        $sCmpImgsDllType = "ptr"
    EndIf

    Local $sScoreDllType
    If IsDllStruct($score) Then
        $sScoreDllType = "struct*"
    Else
        $sScoreDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBaseCompute", $sQualityBaseDllType, $qualityBase, $sCmpImgsDllType, $cmpImgs, $sScoreDllType, $score), "cveQualityBaseCompute", @error)
EndFunc   ;==>_cveQualityBaseCompute

Func _cveQualityBaseComputeTyped($qualityBase, $typeOfCmpImgs, $cmpImgs, $score)

    Local $iArrCmpImgs, $vectorCmpImgs, $iArrCmpImgsSize
    Local $bCmpImgsIsArray = IsArray($cmpImgs)
    Local $bCmpImgsCreate = IsDllStruct($cmpImgs) And $typeOfCmpImgs == "Scalar"

    If $typeOfCmpImgs == Default Then
        $iArrCmpImgs = $cmpImgs
    ElseIf $bCmpImgsIsArray Then
        $vectorCmpImgs = Call("_VectorOf" & $typeOfCmpImgs & "Create")

        $iArrCmpImgsSize = UBound($cmpImgs)
        For $i = 0 To $iArrCmpImgsSize - 1
            Call("_VectorOf" & $typeOfCmpImgs & "Push", $vectorCmpImgs, $cmpImgs[$i])
        Next

        $iArrCmpImgs = Call("_cveInputArrayFromVectorOf" & $typeOfCmpImgs, $vectorCmpImgs)
    Else
        If $bCmpImgsCreate Then
            $cmpImgs = Call("_cve" & $typeOfCmpImgs & "Create", $cmpImgs)
        EndIf
        $iArrCmpImgs = Call("_cveInputArrayFrom" & $typeOfCmpImgs, $cmpImgs)
    EndIf

    _cveQualityBaseCompute($qualityBase, $iArrCmpImgs, $score)

    If $bCmpImgsIsArray Then
        Call("_VectorOf" & $typeOfCmpImgs & "Release", $vectorCmpImgs)
    EndIf

    If $typeOfCmpImgs <> Default Then
        _cveInputArrayRelease($iArrCmpImgs)
        If $bCmpImgsCreate Then
            Call("_cve" & $typeOfCmpImgs & "Release", $cmpImgs)
        EndIf
    EndIf
EndFunc   ;==>_cveQualityBaseComputeTyped

Func _cveQualityBaseComputeMat($qualityBase, $cmpImgs, $score)
    ; cveQualityBaseCompute using cv::Mat instead of _*Array
    _cveQualityBaseComputeTyped($qualityBase, "Mat", $cmpImgs, $score)
EndFunc   ;==>_cveQualityBaseComputeMat

Func _cveQualityBaseGetQualityMap($qualityBase, $dst)
    ; CVAPI(void) cveQualityBaseGetQualityMap(cv::quality::QualityBase* qualityBase, cv::_OutputArray* dst);

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    Else
        $sQualityBaseDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBaseGetQualityMap", $sQualityBaseDllType, $qualityBase, $sDstDllType, $dst), "cveQualityBaseGetQualityMap", @error)
EndFunc   ;==>_cveQualityBaseGetQualityMap

Func _cveQualityBaseGetQualityMapTyped($qualityBase, $typeOfDst, $dst)

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveQualityBaseGetQualityMap($qualityBase, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveQualityBaseGetQualityMapTyped

Func _cveQualityBaseGetQualityMapMat($qualityBase, $dst)
    ; cveQualityBaseGetQualityMap using cv::Mat instead of _*Array
    _cveQualityBaseGetQualityMapTyped($qualityBase, "Mat", $dst)
EndFunc   ;==>_cveQualityBaseGetQualityMapMat

Func _cveQualityMSECreate($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityMSE*) cveQualityMSECreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityMSE>** sharedPtr);

    Local $sRefImgsDllType
    If IsDllStruct($refImgs) Then
        $sRefImgsDllType = "struct*"
    Else
        $sRefImgsDllType = "ptr"
    EndIf

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    ElseIf $qualityBase == Null Then
        $sQualityBaseDllType = "ptr"
    Else
        $sQualityBaseDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityMSECreate", $sRefImgsDllType, $refImgs, $sQualityBaseDllType, $qualityBase, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveQualityMSECreate", @error)
EndFunc   ;==>_cveQualityMSECreate

Func _cveQualityMSECreateTyped($typeOfRefImgs, $refImgs, $qualityBase, $algorithm, $sharedPtr)

    Local $iArrRefImgs, $vectorRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = IsArray($refImgs)
    Local $bRefImgsCreate = IsDllStruct($refImgs) And $typeOfRefImgs == "Scalar"

    If $typeOfRefImgs == Default Then
        $iArrRefImgs = $refImgs
    ElseIf $bRefImgsIsArray Then
        $vectorRefImgs = Call("_VectorOf" & $typeOfRefImgs & "Create")

        $iArrRefImgsSize = UBound($refImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            Call("_VectorOf" & $typeOfRefImgs & "Push", $vectorRefImgs, $refImgs[$i])
        Next

        $iArrRefImgs = Call("_cveInputArrayFromVectorOf" & $typeOfRefImgs, $vectorRefImgs)
    Else
        If $bRefImgsCreate Then
            $refImgs = Call("_cve" & $typeOfRefImgs & "Create", $refImgs)
        EndIf
        $iArrRefImgs = Call("_cveInputArrayFrom" & $typeOfRefImgs, $refImgs)
    EndIf

    Local $retval = _cveQualityMSECreate($iArrRefImgs, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        Call("_VectorOf" & $typeOfRefImgs & "Release", $vectorRefImgs)
    EndIf

    If $typeOfRefImgs <> Default Then
        _cveInputArrayRelease($iArrRefImgs)
        If $bRefImgsCreate Then
            Call("_cve" & $typeOfRefImgs & "Release", $refImgs)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveQualityMSECreateTyped

Func _cveQualityMSECreateMat($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualityMSECreate using cv::Mat instead of _*Array
    Local $retval = _cveQualityMSECreateTyped("Mat", $refImgs, $qualityBase, $algorithm, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveQualityMSECreateMat

Func _cveQualityMSERelease($sharedPtr)
    ; CVAPI(void) cveQualityMSERelease(cv::Ptr<cv::quality::QualityMSE>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityMSERelease", $sSharedPtrDllType, $sharedPtr), "cveQualityMSERelease", @error)
EndFunc   ;==>_cveQualityMSERelease

Func _cveQualityBRISQUECreate($modelFilePath, $rangeFilePath, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityBRISQUE*) cveQualityBRISQUECreate(cv::String* modelFilePath, cv::String* rangeFilePath, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityBRISQUE>** sharedPtr);

    Local $bModelFilePathIsString = IsString($modelFilePath)
    If $bModelFilePathIsString Then
        $modelFilePath = _cveStringCreateFromStr($modelFilePath)
    EndIf

    Local $sModelFilePathDllType
    If IsDllStruct($modelFilePath) Then
        $sModelFilePathDllType = "struct*"
    Else
        $sModelFilePathDllType = "ptr"
    EndIf

    Local $bRangeFilePathIsString = IsString($rangeFilePath)
    If $bRangeFilePathIsString Then
        $rangeFilePath = _cveStringCreateFromStr($rangeFilePath)
    EndIf

    Local $sRangeFilePathDllType
    If IsDllStruct($rangeFilePath) Then
        $sRangeFilePathDllType = "struct*"
    Else
        $sRangeFilePathDllType = "ptr"
    EndIf

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    ElseIf $qualityBase == Null Then
        $sQualityBaseDllType = "ptr"
    Else
        $sQualityBaseDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityBRISQUECreate", $sModelFilePathDllType, $modelFilePath, $sRangeFilePathDllType, $rangeFilePath, $sQualityBaseDllType, $qualityBase, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveQualityBRISQUECreate", @error)

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

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityBRISQUERelease", $sSharedPtrDllType, $sharedPtr), "cveQualityBRISQUERelease", @error)
EndFunc   ;==>_cveQualityBRISQUERelease

Func _cveQualityPSNRCreate($refImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityPSNR*) cveQualityPSNRCreate(cv::_InputArray* refImgs, double maxPixelValue, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityPSNR>** sharedPtr);

    Local $sRefImgsDllType
    If IsDllStruct($refImgs) Then
        $sRefImgsDllType = "struct*"
    Else
        $sRefImgsDllType = "ptr"
    EndIf

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    ElseIf $qualityBase == Null Then
        $sQualityBaseDllType = "ptr"
    Else
        $sQualityBaseDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityPSNRCreate", $sRefImgsDllType, $refImgs, "double", $maxPixelValue, $sQualityBaseDllType, $qualityBase, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveQualityPSNRCreate", @error)
EndFunc   ;==>_cveQualityPSNRCreate

Func _cveQualityPSNRCreateTyped($typeOfRefImgs, $refImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)

    Local $iArrRefImgs, $vectorRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = IsArray($refImgs)
    Local $bRefImgsCreate = IsDllStruct($refImgs) And $typeOfRefImgs == "Scalar"

    If $typeOfRefImgs == Default Then
        $iArrRefImgs = $refImgs
    ElseIf $bRefImgsIsArray Then
        $vectorRefImgs = Call("_VectorOf" & $typeOfRefImgs & "Create")

        $iArrRefImgsSize = UBound($refImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            Call("_VectorOf" & $typeOfRefImgs & "Push", $vectorRefImgs, $refImgs[$i])
        Next

        $iArrRefImgs = Call("_cveInputArrayFromVectorOf" & $typeOfRefImgs, $vectorRefImgs)
    Else
        If $bRefImgsCreate Then
            $refImgs = Call("_cve" & $typeOfRefImgs & "Create", $refImgs)
        EndIf
        $iArrRefImgs = Call("_cveInputArrayFrom" & $typeOfRefImgs, $refImgs)
    EndIf

    Local $retval = _cveQualityPSNRCreate($iArrRefImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        Call("_VectorOf" & $typeOfRefImgs & "Release", $vectorRefImgs)
    EndIf

    If $typeOfRefImgs <> Default Then
        _cveInputArrayRelease($iArrRefImgs)
        If $bRefImgsCreate Then
            Call("_cve" & $typeOfRefImgs & "Release", $refImgs)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveQualityPSNRCreateTyped

Func _cveQualityPSNRCreateMat($refImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualityPSNRCreate using cv::Mat instead of _*Array
    Local $retval = _cveQualityPSNRCreateTyped("Mat", $refImgs, $maxPixelValue, $qualityBase, $algorithm, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveQualityPSNRCreateMat

Func _cveQualityPSNRRelease($sharedPtr)
    ; CVAPI(void) cveQualityPSNRRelease(cv::Ptr<cv::quality::QualityPSNR>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityPSNRRelease", $sSharedPtrDllType, $sharedPtr), "cveQualityPSNRRelease", @error)
EndFunc   ;==>_cveQualityPSNRRelease

Func _cveQualitySSIMCreate($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualitySSIM*) cveQualitySSIMCreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualitySSIM>** sharedPtr);

    Local $sRefImgsDllType
    If IsDllStruct($refImgs) Then
        $sRefImgsDllType = "struct*"
    Else
        $sRefImgsDllType = "ptr"
    EndIf

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    ElseIf $qualityBase == Null Then
        $sQualityBaseDllType = "ptr"
    Else
        $sQualityBaseDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualitySSIMCreate", $sRefImgsDllType, $refImgs, $sQualityBaseDllType, $qualityBase, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveQualitySSIMCreate", @error)
EndFunc   ;==>_cveQualitySSIMCreate

Func _cveQualitySSIMCreateTyped($typeOfRefImgs, $refImgs, $qualityBase, $algorithm, $sharedPtr)

    Local $iArrRefImgs, $vectorRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = IsArray($refImgs)
    Local $bRefImgsCreate = IsDllStruct($refImgs) And $typeOfRefImgs == "Scalar"

    If $typeOfRefImgs == Default Then
        $iArrRefImgs = $refImgs
    ElseIf $bRefImgsIsArray Then
        $vectorRefImgs = Call("_VectorOf" & $typeOfRefImgs & "Create")

        $iArrRefImgsSize = UBound($refImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            Call("_VectorOf" & $typeOfRefImgs & "Push", $vectorRefImgs, $refImgs[$i])
        Next

        $iArrRefImgs = Call("_cveInputArrayFromVectorOf" & $typeOfRefImgs, $vectorRefImgs)
    Else
        If $bRefImgsCreate Then
            $refImgs = Call("_cve" & $typeOfRefImgs & "Create", $refImgs)
        EndIf
        $iArrRefImgs = Call("_cveInputArrayFrom" & $typeOfRefImgs, $refImgs)
    EndIf

    Local $retval = _cveQualitySSIMCreate($iArrRefImgs, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        Call("_VectorOf" & $typeOfRefImgs & "Release", $vectorRefImgs)
    EndIf

    If $typeOfRefImgs <> Default Then
        _cveInputArrayRelease($iArrRefImgs)
        If $bRefImgsCreate Then
            Call("_cve" & $typeOfRefImgs & "Release", $refImgs)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveQualitySSIMCreateTyped

Func _cveQualitySSIMCreateMat($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualitySSIMCreate using cv::Mat instead of _*Array
    Local $retval = _cveQualitySSIMCreateTyped("Mat", $refImgs, $qualityBase, $algorithm, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveQualitySSIMCreateMat

Func _cveQualitySSIMRelease($sharedPtr)
    ; CVAPI(void) cveQualitySSIMRelease(cv::Ptr<cv::quality::QualitySSIM>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualitySSIMRelease", $sSharedPtrDllType, $sharedPtr), "cveQualitySSIMRelease", @error)
EndFunc   ;==>_cveQualitySSIMRelease

Func _cveQualityGMSDCreate($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; CVAPI(cv::quality::QualityGMSD*) cveQualityGMSDCreate(cv::_InputArray* refImgs, cv::quality::QualityBase** qualityBase, cv::Algorithm** algorithm, cv::Ptr<cv::quality::QualityGMSD>** sharedPtr);

    Local $sRefImgsDllType
    If IsDllStruct($refImgs) Then
        $sRefImgsDllType = "struct*"
    Else
        $sRefImgsDllType = "ptr"
    EndIf

    Local $sQualityBaseDllType
    If IsDllStruct($qualityBase) Then
        $sQualityBaseDllType = "struct*"
    ElseIf $qualityBase == Null Then
        $sQualityBaseDllType = "ptr"
    Else
        $sQualityBaseDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQualityGMSDCreate", $sRefImgsDllType, $refImgs, $sQualityBaseDllType, $qualityBase, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveQualityGMSDCreate", @error)
EndFunc   ;==>_cveQualityGMSDCreate

Func _cveQualityGMSDCreateTyped($typeOfRefImgs, $refImgs, $qualityBase, $algorithm, $sharedPtr)

    Local $iArrRefImgs, $vectorRefImgs, $iArrRefImgsSize
    Local $bRefImgsIsArray = IsArray($refImgs)
    Local $bRefImgsCreate = IsDllStruct($refImgs) And $typeOfRefImgs == "Scalar"

    If $typeOfRefImgs == Default Then
        $iArrRefImgs = $refImgs
    ElseIf $bRefImgsIsArray Then
        $vectorRefImgs = Call("_VectorOf" & $typeOfRefImgs & "Create")

        $iArrRefImgsSize = UBound($refImgs)
        For $i = 0 To $iArrRefImgsSize - 1
            Call("_VectorOf" & $typeOfRefImgs & "Push", $vectorRefImgs, $refImgs[$i])
        Next

        $iArrRefImgs = Call("_cveInputArrayFromVectorOf" & $typeOfRefImgs, $vectorRefImgs)
    Else
        If $bRefImgsCreate Then
            $refImgs = Call("_cve" & $typeOfRefImgs & "Create", $refImgs)
        EndIf
        $iArrRefImgs = Call("_cveInputArrayFrom" & $typeOfRefImgs, $refImgs)
    EndIf

    Local $retval = _cveQualityGMSDCreate($iArrRefImgs, $qualityBase, $algorithm, $sharedPtr)

    If $bRefImgsIsArray Then
        Call("_VectorOf" & $typeOfRefImgs & "Release", $vectorRefImgs)
    EndIf

    If $typeOfRefImgs <> Default Then
        _cveInputArrayRelease($iArrRefImgs)
        If $bRefImgsCreate Then
            Call("_cve" & $typeOfRefImgs & "Release", $refImgs)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveQualityGMSDCreateTyped

Func _cveQualityGMSDCreateMat($refImgs, $qualityBase, $algorithm, $sharedPtr)
    ; cveQualityGMSDCreate using cv::Mat instead of _*Array
    Local $retval = _cveQualityGMSDCreateTyped("Mat", $refImgs, $qualityBase, $algorithm, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveQualityGMSDCreateMat

Func _cveQualityGMSDRelease($sharedPtr)
    ; CVAPI(void) cveQualityGMSDRelease(cv::Ptr<cv::quality::QualityGMSD>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQualityGMSDRelease", $sSharedPtrDllType, $sharedPtr), "cveQualityGMSDRelease", @error)
EndFunc   ;==>_cveQualityGMSDRelease