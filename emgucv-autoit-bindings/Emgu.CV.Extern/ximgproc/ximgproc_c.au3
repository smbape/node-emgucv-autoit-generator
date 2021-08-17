#include-once
#include "..\..\CVEUtils.au3"

Func _cveDtFilter($guide, $src, $dst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
    ; CVAPI(void) cveDtFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, double sigmaSpatial, double sigmaColor, int mode, int numIters);

    Local $bGuideDllType
    If VarGetType($guide) == "DLLStruct" Then
        $bGuideDllType = "struct*"
    Else
        $bGuideDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDtFilter", $bGuideDllType, $guide, $bSrcDllType, $src, $bDstDllType, $dst, "double", $sigmaSpatial, "double", $sigmaColor, "int", $mode, "int", $numIters), "cveDtFilter", @error)
EndFunc   ;==>_cveDtFilter

Func _cveDtFilterMat($matGuide, $matSrc, $matDst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
    ; cveDtFilter using cv::Mat instead of _*Array

    Local $iArrGuide, $vectorOfMatGuide, $iArrGuideSize
    Local $bGuideIsArray = VarGetType($matGuide) == "Array"

    If $bGuideIsArray Then
        $vectorOfMatGuide = _VectorOfMatCreate()

        $iArrGuideSize = UBound($matGuide)
        For $i = 0 To $iArrGuideSize - 1
            _VectorOfMatPush($vectorOfMatGuide, $matGuide[$i])
        Next

        $iArrGuide = _cveInputArrayFromVectorOfMat($vectorOfMatGuide)
    Else
        $iArrGuide = _cveInputArrayFromMat($matGuide)
    EndIf

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveDtFilter($iArrGuide, $iArrSrc, $oArrDst, $sigmaSpatial, $sigmaColor, $mode, $numIters)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    If $bGuideIsArray Then
        _VectorOfMatRelease($vectorOfMatGuide)
    EndIf

    _cveInputArrayRelease($iArrGuide)
EndFunc   ;==>_cveDtFilterMat

Func _cveGuidedFilter($guide, $src, $dst, $radius, $eps, $dDepth = -1)
    ; CVAPI(void) cveGuidedFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, int radius, double eps, int dDepth);

    Local $bGuideDllType
    If VarGetType($guide) == "DLLStruct" Then
        $bGuideDllType = "struct*"
    Else
        $bGuideDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGuidedFilter", $bGuideDllType, $guide, $bSrcDllType, $src, $bDstDllType, $dst, "int", $radius, "double", $eps, "int", $dDepth), "cveGuidedFilter", @error)
EndFunc   ;==>_cveGuidedFilter

Func _cveGuidedFilterMat($matGuide, $matSrc, $matDst, $radius, $eps, $dDepth = -1)
    ; cveGuidedFilter using cv::Mat instead of _*Array

    Local $iArrGuide, $vectorOfMatGuide, $iArrGuideSize
    Local $bGuideIsArray = VarGetType($matGuide) == "Array"

    If $bGuideIsArray Then
        $vectorOfMatGuide = _VectorOfMatCreate()

        $iArrGuideSize = UBound($matGuide)
        For $i = 0 To $iArrGuideSize - 1
            _VectorOfMatPush($vectorOfMatGuide, $matGuide[$i])
        Next

        $iArrGuide = _cveInputArrayFromVectorOfMat($vectorOfMatGuide)
    Else
        $iArrGuide = _cveInputArrayFromMat($matGuide)
    EndIf

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveGuidedFilter($iArrGuide, $iArrSrc, $oArrDst, $radius, $eps, $dDepth)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    If $bGuideIsArray Then
        _VectorOfMatRelease($vectorOfMatGuide)
    EndIf

    _cveInputArrayRelease($iArrGuide)
EndFunc   ;==>_cveGuidedFilterMat

Func _cveAmFilter($joint, $src, $dst, $sigmaS, $sigmaR, $adjustOutliers)
    ; CVAPI(void) cveAmFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, double sigmaS, double sigmaR, bool adjustOutliers);

    Local $bJointDllType
    If VarGetType($joint) == "DLLStruct" Then
        $bJointDllType = "struct*"
    Else
        $bJointDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAmFilter", $bJointDllType, $joint, $bSrcDllType, $src, $bDstDllType, $dst, "double", $sigmaS, "double", $sigmaR, "boolean", $adjustOutliers), "cveAmFilter", @error)
EndFunc   ;==>_cveAmFilter

Func _cveAmFilterMat($matJoint, $matSrc, $matDst, $sigmaS, $sigmaR, $adjustOutliers)
    ; cveAmFilter using cv::Mat instead of _*Array

    Local $iArrJoint, $vectorOfMatJoint, $iArrJointSize
    Local $bJointIsArray = VarGetType($matJoint) == "Array"

    If $bJointIsArray Then
        $vectorOfMatJoint = _VectorOfMatCreate()

        $iArrJointSize = UBound($matJoint)
        For $i = 0 To $iArrJointSize - 1
            _VectorOfMatPush($vectorOfMatJoint, $matJoint[$i])
        Next

        $iArrJoint = _cveInputArrayFromVectorOfMat($vectorOfMatJoint)
    Else
        $iArrJoint = _cveInputArrayFromMat($matJoint)
    EndIf

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveAmFilter($iArrJoint, $iArrSrc, $oArrDst, $sigmaS, $sigmaR, $adjustOutliers)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    If $bJointIsArray Then
        _VectorOfMatRelease($vectorOfMatJoint)
    EndIf

    _cveInputArrayRelease($iArrJoint)
EndFunc   ;==>_cveAmFilterMat

Func _cveJointBilateralFilter($joint, $src, $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(void) cveJointBilateralFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int borderType);

    Local $bJointDllType
    If VarGetType($joint) == "DLLStruct" Then
        $bJointDllType = "struct*"
    Else
        $bJointDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveJointBilateralFilter", $bJointDllType, $joint, $bSrcDllType, $src, $bDstDllType, $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveJointBilateralFilter", @error)
EndFunc   ;==>_cveJointBilateralFilter

Func _cveJointBilateralFilterMat($matJoint, $matSrc, $matDst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; cveJointBilateralFilter using cv::Mat instead of _*Array

    Local $iArrJoint, $vectorOfMatJoint, $iArrJointSize
    Local $bJointIsArray = VarGetType($matJoint) == "Array"

    If $bJointIsArray Then
        $vectorOfMatJoint = _VectorOfMatCreate()

        $iArrJointSize = UBound($matJoint)
        For $i = 0 To $iArrJointSize - 1
            _VectorOfMatPush($vectorOfMatJoint, $matJoint[$i])
        Next

        $iArrJoint = _cveInputArrayFromVectorOfMat($vectorOfMatJoint)
    Else
        $iArrJoint = _cveInputArrayFromMat($matJoint)
    EndIf

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveJointBilateralFilter($iArrJoint, $iArrSrc, $oArrDst, $d, $sigmaColor, $sigmaSpace, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    If $bJointIsArray Then
        _VectorOfMatRelease($vectorOfMatJoint)
    EndIf

    _cveInputArrayRelease($iArrJoint)
EndFunc   ;==>_cveJointBilateralFilterMat

Func _cveBilateralTextureFilter($src, $dst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
    ; CVAPI(void) cveBilateralTextureFilter(cv::_InputArray* src, cv::_OutputArray* dst, int fr, int numIter, double sigmaAlpha, double sigmaAvg);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBilateralTextureFilter", $bSrcDllType, $src, $bDstDllType, $dst, "int", $fr, "int", $numIter, "double", $sigmaAlpha, "double", $sigmaAvg), "cveBilateralTextureFilter", @error)
EndFunc   ;==>_cveBilateralTextureFilter

Func _cveBilateralTextureFilterMat($matSrc, $matDst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
    ; cveBilateralTextureFilter using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveBilateralTextureFilter($iArrSrc, $oArrDst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBilateralTextureFilterMat

Func _cveRollingGuidanceFilter($src, $dst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
    ; CVAPI(void) cveRollingGuidanceFilter(cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int numOfIter, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRollingGuidanceFilter", $bSrcDllType, $src, $bDstDllType, $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $numOfIter, "int", $borderType), "cveRollingGuidanceFilter", @error)
EndFunc   ;==>_cveRollingGuidanceFilter

Func _cveRollingGuidanceFilterMat($matSrc, $matDst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
    ; cveRollingGuidanceFilter using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveRollingGuidanceFilter($iArrSrc, $oArrDst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRollingGuidanceFilterMat

Func _cveFastGlobalSmootherFilter($guide, $src, $dst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
    ; CVAPI(void) cveFastGlobalSmootherFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, double lambda, double sigmaColor, double lambdaAttenuation, int numIter);

    Local $bGuideDllType
    If VarGetType($guide) == "DLLStruct" Then
        $bGuideDllType = "struct*"
    Else
        $bGuideDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastGlobalSmootherFilter", $bGuideDllType, $guide, $bSrcDllType, $src, $bDstDllType, $dst, "double", $lambda, "double", $sigmaColor, "double", $lambdaAttenuation, "int", $numIter), "cveFastGlobalSmootherFilter", @error)
EndFunc   ;==>_cveFastGlobalSmootherFilter

Func _cveFastGlobalSmootherFilterMat($matGuide, $matSrc, $matDst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
    ; cveFastGlobalSmootherFilter using cv::Mat instead of _*Array

    Local $iArrGuide, $vectorOfMatGuide, $iArrGuideSize
    Local $bGuideIsArray = VarGetType($matGuide) == "Array"

    If $bGuideIsArray Then
        $vectorOfMatGuide = _VectorOfMatCreate()

        $iArrGuideSize = UBound($matGuide)
        For $i = 0 To $iArrGuideSize - 1
            _VectorOfMatPush($vectorOfMatGuide, $matGuide[$i])
        Next

        $iArrGuide = _cveInputArrayFromVectorOfMat($vectorOfMatGuide)
    Else
        $iArrGuide = _cveInputArrayFromMat($matGuide)
    EndIf

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveFastGlobalSmootherFilter($iArrGuide, $iArrSrc, $oArrDst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    If $bGuideIsArray Then
        _VectorOfMatRelease($vectorOfMatGuide)
    EndIf

    _cveInputArrayRelease($iArrGuide)
EndFunc   ;==>_cveFastGlobalSmootherFilterMat

Func _cveL0Smooth($src, $dst, $lambda = 0.02, $kappa = 2.0)
    ; CVAPI(void) cveL0Smooth(cv::_InputArray* src, cv::_OutputArray* dst, double lambda, double kappa);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveL0Smooth", $bSrcDllType, $src, $bDstDllType, $dst, "double", $lambda, "double", $kappa), "cveL0Smooth", @error)
EndFunc   ;==>_cveL0Smooth

Func _cveL0SmoothMat($matSrc, $matDst, $lambda = 0.02, $kappa = 2.0)
    ; cveL0Smooth using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveL0Smooth($iArrSrc, $oArrDst, $lambda, $kappa)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveL0SmoothMat

Func _cveNiBlackThreshold($src, $dst, $maxValue, $type, $blockSize, $delta)
    ; CVAPI(void) cveNiBlackThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double maxValue, int type, int blockSize, double delta);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNiBlackThreshold", $bSrcDllType, $src, $bDstDllType, $dst, "double", $maxValue, "int", $type, "int", $blockSize, "double", $delta), "cveNiBlackThreshold", @error)
EndFunc   ;==>_cveNiBlackThreshold

Func _cveNiBlackThresholdMat($matSrc, $matDst, $maxValue, $type, $blockSize, $delta)
    ; cveNiBlackThreshold using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveNiBlackThreshold($iArrSrc, $oArrDst, $maxValue, $type, $blockSize, $delta)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveNiBlackThresholdMat

Func _cveCovarianceEstimation($src, $dst, $windowRows, $windowCols)
    ; CVAPI(void) cveCovarianceEstimation(cv::_InputArray* src, cv::_OutputArray* dst, int windowRows, int windowCols);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCovarianceEstimation", $bSrcDllType, $src, $bDstDllType, $dst, "int", $windowRows, "int", $windowCols), "cveCovarianceEstimation", @error)
EndFunc   ;==>_cveCovarianceEstimation

Func _cveCovarianceEstimationMat($matSrc, $matDst, $windowRows, $windowCols)
    ; cveCovarianceEstimation using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveCovarianceEstimation($iArrSrc, $oArrDst, $windowRows, $windowCols)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveCovarianceEstimationMat

Func _cveDTFilterCreate($guide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)
    ; CVAPI(cv::ximgproc::DTFilter*) cveDTFilterCreate(cv::_InputArray* guide, double sigmaSpatial, double sigmaColor, int mode, int numIters, cv::Ptr<cv::ximgproc::DTFilter>** sharedPtr);

    Local $bGuideDllType
    If VarGetType($guide) == "DLLStruct" Then
        $bGuideDllType = "struct*"
    Else
        $bGuideDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDTFilterCreate", $bGuideDllType, $guide, "double", $sigmaSpatial, "double", $sigmaColor, "int", $mode, "int", $numIters, $bSharedPtrDllType, $sharedPtr), "cveDTFilterCreate", @error)
EndFunc   ;==>_cveDTFilterCreate

Func _cveDTFilterCreateMat($matGuide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)
    ; cveDTFilterCreate using cv::Mat instead of _*Array

    Local $iArrGuide, $vectorOfMatGuide, $iArrGuideSize
    Local $bGuideIsArray = VarGetType($matGuide) == "Array"

    If $bGuideIsArray Then
        $vectorOfMatGuide = _VectorOfMatCreate()

        $iArrGuideSize = UBound($matGuide)
        For $i = 0 To $iArrGuideSize - 1
            _VectorOfMatPush($vectorOfMatGuide, $matGuide[$i])
        Next

        $iArrGuide = _cveInputArrayFromVectorOfMat($vectorOfMatGuide)
    Else
        $iArrGuide = _cveInputArrayFromMat($matGuide)
    EndIf

    Local $retval = _cveDTFilterCreate($iArrGuide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)

    If $bGuideIsArray Then
        _VectorOfMatRelease($vectorOfMatGuide)
    EndIf

    _cveInputArrayRelease($iArrGuide)

    Return $retval
EndFunc   ;==>_cveDTFilterCreateMat

Func _cveDTFilterFilter($filter, $src, $dst, $dDepth)
    ; CVAPI(void) cveDTFilterFilter(cv::ximgproc::DTFilter* filter, cv::_InputArray* src, cv::_OutputArray* dst, int dDepth);

    Local $bFilterDllType
    If VarGetType($filter) == "DLLStruct" Then
        $bFilterDllType = "struct*"
    Else
        $bFilterDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTFilterFilter", $bFilterDllType, $filter, $bSrcDllType, $src, $bDstDllType, $dst, "int", $dDepth), "cveDTFilterFilter", @error)
EndFunc   ;==>_cveDTFilterFilter

Func _cveDTFilterFilterMat($filter, $matSrc, $matDst, $dDepth)
    ; cveDTFilterFilter using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveDTFilterFilter($filter, $iArrSrc, $oArrDst, $dDepth)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveDTFilterFilterMat

Func _cveDTFilterRelease($filter, $sharedPtr)
    ; CVAPI(void) cveDTFilterRelease(cv::ximgproc::DTFilter** filter, cv::Ptr<cv::ximgproc::DTFilter>** sharedPtr);

    Local $bFilterDllType
    If VarGetType($filter) == "DLLStruct" Then
        $bFilterDllType = "struct*"
    Else
        $bFilterDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTFilterRelease", $bFilterDllType, $filter, $bSharedPtrDllType, $sharedPtr), "cveDTFilterRelease", @error)
EndFunc   ;==>_cveDTFilterRelease

Func _cveRFFeatureGetterCreate($sharedPtr)
    ; CVAPI(cv::ximgproc::RFFeatureGetter*) cveRFFeatureGetterCreate(cv::Ptr<cv::ximgproc::RFFeatureGetter>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRFFeatureGetterCreate", $bSharedPtrDllType, $sharedPtr), "cveRFFeatureGetterCreate", @error)
EndFunc   ;==>_cveRFFeatureGetterCreate

Func _cveRFFeatureGetterRelease($getter, $sharedPtr)
    ; CVAPI(void) cveRFFeatureGetterRelease(cv::ximgproc::RFFeatureGetter** getter, cv::Ptr<cv::ximgproc::RFFeatureGetter>** sharedPtr);

    Local $bGetterDllType
    If VarGetType($getter) == "DLLStruct" Then
        $bGetterDllType = "struct*"
    Else
        $bGetterDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRFFeatureGetterRelease", $bGetterDllType, $getter, $bSharedPtrDllType, $sharedPtr), "cveRFFeatureGetterRelease", @error)
EndFunc   ;==>_cveRFFeatureGetterRelease

Func _cveStructuredEdgeDetectionCreate($model, $howToGetFeatures, $sharedPtr)
    ; CVAPI(cv::ximgproc::StructuredEdgeDetection*) cveStructuredEdgeDetectionCreate(cv::String* model, cv::ximgproc::RFFeatureGetter* howToGetFeatures, cv::Ptr<cv::ximgproc::StructuredEdgeDetection>** sharedPtr);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bHowToGetFeaturesDllType
    If VarGetType($howToGetFeatures) == "DLLStruct" Then
        $bHowToGetFeaturesDllType = "struct*"
    Else
        $bHowToGetFeaturesDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStructuredEdgeDetectionCreate", $bModelDllType, $model, $bHowToGetFeaturesDllType, $howToGetFeatures, $bSharedPtrDllType, $sharedPtr), "cveStructuredEdgeDetectionCreate", @error)

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveStructuredEdgeDetectionCreate

Func _cveStructuredEdgeDetectionDetectEdges($detection, $src, $dst)
    ; CVAPI(void) cveStructuredEdgeDetectionDetectEdges(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $bDetectionDllType
    If VarGetType($detection) == "DLLStruct" Then
        $bDetectionDllType = "struct*"
    Else
        $bDetectionDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionDetectEdges", $bDetectionDllType, $detection, $bSrcDllType, $src, $bDstDllType, $dst), "cveStructuredEdgeDetectionDetectEdges", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionDetectEdges

Func _cveStructuredEdgeDetectionDetectEdgesMat($detection, $matSrc, $matDst)
    ; cveStructuredEdgeDetectionDetectEdges using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveStructuredEdgeDetectionDetectEdges($detection, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveStructuredEdgeDetectionDetectEdgesMat

Func _cveStructuredEdgeDetectionComputeOrientation($detection, $src, $dst)
    ; CVAPI(void) cveStructuredEdgeDetectionComputeOrientation(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $bDetectionDllType
    If VarGetType($detection) == "DLLStruct" Then
        $bDetectionDllType = "struct*"
    Else
        $bDetectionDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionComputeOrientation", $bDetectionDllType, $detection, $bSrcDllType, $src, $bDstDllType, $dst), "cveStructuredEdgeDetectionComputeOrientation", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionComputeOrientation

Func _cveStructuredEdgeDetectionComputeOrientationMat($detection, $matSrc, $matDst)
    ; cveStructuredEdgeDetectionComputeOrientation using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveStructuredEdgeDetectionComputeOrientation($detection, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveStructuredEdgeDetectionComputeOrientationMat

Func _cveStructuredEdgeDetectionEdgesNms($detection, $edgeImage, $orientationImage, $dst, $r, $s, $m, $isParallel)
    ; CVAPI(void) cveStructuredEdgeDetectionEdgesNms(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* edgeImage, cv::_InputArray* orientationImage, cv::_OutputArray* dst, int r, int s, float m, bool isParallel);

    Local $bDetectionDllType
    If VarGetType($detection) == "DLLStruct" Then
        $bDetectionDllType = "struct*"
    Else
        $bDetectionDllType = "ptr"
    EndIf

    Local $bEdgeImageDllType
    If VarGetType($edgeImage) == "DLLStruct" Then
        $bEdgeImageDllType = "struct*"
    Else
        $bEdgeImageDllType = "ptr"
    EndIf

    Local $bOrientationImageDllType
    If VarGetType($orientationImage) == "DLLStruct" Then
        $bOrientationImageDllType = "struct*"
    Else
        $bOrientationImageDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionEdgesNms", $bDetectionDllType, $detection, $bEdgeImageDllType, $edgeImage, $bOrientationImageDllType, $orientationImage, $bDstDllType, $dst, "int", $r, "int", $s, "float", $m, "boolean", $isParallel), "cveStructuredEdgeDetectionEdgesNms", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionEdgesNms

Func _cveStructuredEdgeDetectionEdgesNmsMat($detection, $matEdgeImage, $matOrientationImage, $matDst, $r, $s, $m, $isParallel)
    ; cveStructuredEdgeDetectionEdgesNms using cv::Mat instead of _*Array

    Local $iArrEdgeImage, $vectorOfMatEdgeImage, $iArrEdgeImageSize
    Local $bEdgeImageIsArray = VarGetType($matEdgeImage) == "Array"

    If $bEdgeImageIsArray Then
        $vectorOfMatEdgeImage = _VectorOfMatCreate()

        $iArrEdgeImageSize = UBound($matEdgeImage)
        For $i = 0 To $iArrEdgeImageSize - 1
            _VectorOfMatPush($vectorOfMatEdgeImage, $matEdgeImage[$i])
        Next

        $iArrEdgeImage = _cveInputArrayFromVectorOfMat($vectorOfMatEdgeImage)
    Else
        $iArrEdgeImage = _cveInputArrayFromMat($matEdgeImage)
    EndIf

    Local $iArrOrientationImage, $vectorOfMatOrientationImage, $iArrOrientationImageSize
    Local $bOrientationImageIsArray = VarGetType($matOrientationImage) == "Array"

    If $bOrientationImageIsArray Then
        $vectorOfMatOrientationImage = _VectorOfMatCreate()

        $iArrOrientationImageSize = UBound($matOrientationImage)
        For $i = 0 To $iArrOrientationImageSize - 1
            _VectorOfMatPush($vectorOfMatOrientationImage, $matOrientationImage[$i])
        Next

        $iArrOrientationImage = _cveInputArrayFromVectorOfMat($vectorOfMatOrientationImage)
    Else
        $iArrOrientationImage = _cveInputArrayFromMat($matOrientationImage)
    EndIf

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

    _cveStructuredEdgeDetectionEdgesNms($detection, $iArrEdgeImage, $iArrOrientationImage, $oArrDst, $r, $s, $m, $isParallel)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bOrientationImageIsArray Then
        _VectorOfMatRelease($vectorOfMatOrientationImage)
    EndIf

    _cveInputArrayRelease($iArrOrientationImage)

    If $bEdgeImageIsArray Then
        _VectorOfMatRelease($vectorOfMatEdgeImage)
    EndIf

    _cveInputArrayRelease($iArrEdgeImage)
EndFunc   ;==>_cveStructuredEdgeDetectionEdgesNmsMat

Func _cveStructuredEdgeDetectionRelease($detection, $sharedPtr)
    ; CVAPI(void) cveStructuredEdgeDetectionRelease(cv::ximgproc::StructuredEdgeDetection** detection, cv::Ptr<cv::ximgproc::StructuredEdgeDetection>** sharedPtr);

    Local $bDetectionDllType
    If VarGetType($detection) == "DLLStruct" Then
        $bDetectionDllType = "struct*"
    Else
        $bDetectionDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionRelease", $bDetectionDllType, $detection, $bSharedPtrDllType, $sharedPtr), "cveStructuredEdgeDetectionRelease", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionRelease

Func _cveSuperpixelSEEDSCreate($imageWidth, $imageHeight, $imageChannels, $numSuperpixels, $numLevels, $prior, $histogramBins, $doubleStep, $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelSEEDS*) cveSuperpixelSEEDSCreate(int imageWidth, int imageHeight, int imageChannels, int numSuperpixels, int numLevels, int prior, int histogramBins, bool doubleStep, cv::Ptr<cv::ximgproc::SuperpixelSEEDS>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelSEEDSCreate", "int", $imageWidth, "int", $imageHeight, "int", $imageChannels, "int", $numSuperpixels, "int", $numLevels, "int", $prior, "int", $histogramBins, "boolean", $doubleStep, $bSharedPtrDllType, $sharedPtr), "cveSuperpixelSEEDSCreate", @error)
EndFunc   ;==>_cveSuperpixelSEEDSCreate

Func _cveSuperpixelSEEDSGetNumberOfSuperpixels($seeds)
    ; CVAPI(int) cveSuperpixelSEEDSGetNumberOfSuperpixels(cv::ximgproc::SuperpixelSEEDS* seeds);

    Local $bSeedsDllType
    If VarGetType($seeds) == "DLLStruct" Then
        $bSeedsDllType = "struct*"
    Else
        $bSeedsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelSEEDSGetNumberOfSuperpixels", $bSeedsDllType, $seeds), "cveSuperpixelSEEDSGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetNumberOfSuperpixels

Func _cveSuperpixelSEEDSGetLabels($seeds, $labelsOut)
    ; CVAPI(void) cveSuperpixelSEEDSGetLabels(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_OutputArray* labelsOut);

    Local $bSeedsDllType
    If VarGetType($seeds) == "DLLStruct" Then
        $bSeedsDllType = "struct*"
    Else
        $bSeedsDllType = "ptr"
    EndIf

    Local $bLabelsOutDllType
    If VarGetType($labelsOut) == "DLLStruct" Then
        $bLabelsOutDllType = "struct*"
    Else
        $bLabelsOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSGetLabels", $bSeedsDllType, $seeds, $bLabelsOutDllType, $labelsOut), "cveSuperpixelSEEDSGetLabels", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabels

Func _cveSuperpixelSEEDSGetLabelsMat($seeds, $matLabelsOut)
    ; cveSuperpixelSEEDSGetLabels using cv::Mat instead of _*Array

    Local $oArrLabelsOut, $vectorOfMatLabelsOut, $iArrLabelsOutSize
    Local $bLabelsOutIsArray = VarGetType($matLabelsOut) == "Array"

    If $bLabelsOutIsArray Then
        $vectorOfMatLabelsOut = _VectorOfMatCreate()

        $iArrLabelsOutSize = UBound($matLabelsOut)
        For $i = 0 To $iArrLabelsOutSize - 1
            _VectorOfMatPush($vectorOfMatLabelsOut, $matLabelsOut[$i])
        Next

        $oArrLabelsOut = _cveOutputArrayFromVectorOfMat($vectorOfMatLabelsOut)
    Else
        $oArrLabelsOut = _cveOutputArrayFromMat($matLabelsOut)
    EndIf

    _cveSuperpixelSEEDSGetLabels($seeds, $oArrLabelsOut)

    If $bLabelsOutIsArray Then
        _VectorOfMatRelease($vectorOfMatLabelsOut)
    EndIf

    _cveOutputArrayRelease($oArrLabelsOut)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelsMat

Func _cveSuperpixelSEEDSGetLabelContourMask($seeds, $image, $thickLine)
    ; CVAPI(void) cveSuperpixelSEEDSGetLabelContourMask(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_OutputArray* image, bool thickLine);

    Local $bSeedsDllType
    If VarGetType($seeds) == "DLLStruct" Then
        $bSeedsDllType = "struct*"
    Else
        $bSeedsDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSGetLabelContourMask", $bSeedsDllType, $seeds, $bImageDllType, $image, "boolean", $thickLine), "cveSuperpixelSEEDSGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelContourMask

Func _cveSuperpixelSEEDSGetLabelContourMaskMat($seeds, $matImage, $thickLine)
    ; cveSuperpixelSEEDSGetLabelContourMask using cv::Mat instead of _*Array

    Local $oArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $oArrImage = _cveOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $oArrImage = _cveOutputArrayFromMat($matImage)
    EndIf

    _cveSuperpixelSEEDSGetLabelContourMask($seeds, $oArrImage, $thickLine)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveOutputArrayRelease($oArrImage)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelContourMaskMat

Func _cveSuperpixelSEEDSIterate($seeds, $img, $numIterations)
    ; CVAPI(void) cveSuperpixelSEEDSIterate(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_InputArray* img, int numIterations);

    Local $bSeedsDllType
    If VarGetType($seeds) == "DLLStruct" Then
        $bSeedsDllType = "struct*"
    Else
        $bSeedsDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSIterate", $bSeedsDllType, $seeds, $bImgDllType, $img, "int", $numIterations), "cveSuperpixelSEEDSIterate", @error)
EndFunc   ;==>_cveSuperpixelSEEDSIterate

Func _cveSuperpixelSEEDSIterateMat($seeds, $matImg, $numIterations)
    ; cveSuperpixelSEEDSIterate using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    _cveSuperpixelSEEDSIterate($seeds, $iArrImg, $numIterations)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveSuperpixelSEEDSIterateMat

Func _cveSuperpixelSEEDSRelease($seeds, $sharedPtr)
    ; CVAPI(void) cveSuperpixelSEEDSRelease(cv::ximgproc::SuperpixelSEEDS** seeds, cv::Ptr<cv::ximgproc::SuperpixelSEEDS>** sharedPtr);

    Local $bSeedsDllType
    If VarGetType($seeds) == "DLLStruct" Then
        $bSeedsDllType = "struct*"
    Else
        $bSeedsDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSRelease", $bSeedsDllType, $seeds, $bSharedPtrDllType, $sharedPtr), "cveSuperpixelSEEDSRelease", @error)
EndFunc   ;==>_cveSuperpixelSEEDSRelease

Func _cveSuperpixelLSCCreate($image, $regionSize, $ratio, $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelLSC*) cveSuperpixelLSCCreate(cv::_InputArray* image, int regionSize, float ratio, cv::Ptr<cv::ximgproc::SuperpixelLSC>** sharedPtr);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelLSCCreate", $bImageDllType, $image, "int", $regionSize, "float", $ratio, $bSharedPtrDllType, $sharedPtr), "cveSuperpixelLSCCreate", @error)
EndFunc   ;==>_cveSuperpixelLSCCreate

Func _cveSuperpixelLSCCreateMat($matImage, $regionSize, $ratio, $sharedPtr)
    ; cveSuperpixelLSCCreate using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $retval = _cveSuperpixelLSCCreate($iArrImage, $regionSize, $ratio, $sharedPtr)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveSuperpixelLSCCreateMat

Func _cveSuperpixelLSCGetNumberOfSuperpixels($lsc)
    ; CVAPI(int) cveSuperpixelLSCGetNumberOfSuperpixels(cv::ximgproc::SuperpixelLSC* lsc);

    Local $bLscDllType
    If VarGetType($lsc) == "DLLStruct" Then
        $bLscDllType = "struct*"
    Else
        $bLscDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelLSCGetNumberOfSuperpixels", $bLscDllType, $lsc), "cveSuperpixelLSCGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelLSCGetNumberOfSuperpixels

Func _cveSuperpixelLSCIterate($lsc, $numIterations)
    ; CVAPI(void) cveSuperpixelLSCIterate(cv::ximgproc::SuperpixelLSC* lsc, int numIterations);

    Local $bLscDllType
    If VarGetType($lsc) == "DLLStruct" Then
        $bLscDllType = "struct*"
    Else
        $bLscDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCIterate", $bLscDllType, $lsc, "int", $numIterations), "cveSuperpixelLSCIterate", @error)
EndFunc   ;==>_cveSuperpixelLSCIterate

Func _cveSuperpixelLSCGetLabels($lsc, $labelsOut)
    ; CVAPI(void) cveSuperpixelLSCGetLabels(cv::ximgproc::SuperpixelLSC* lsc, cv::_OutputArray* labelsOut);

    Local $bLscDllType
    If VarGetType($lsc) == "DLLStruct" Then
        $bLscDllType = "struct*"
    Else
        $bLscDllType = "ptr"
    EndIf

    Local $bLabelsOutDllType
    If VarGetType($labelsOut) == "DLLStruct" Then
        $bLabelsOutDllType = "struct*"
    Else
        $bLabelsOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCGetLabels", $bLscDllType, $lsc, $bLabelsOutDllType, $labelsOut), "cveSuperpixelLSCGetLabels", @error)
EndFunc   ;==>_cveSuperpixelLSCGetLabels

Func _cveSuperpixelLSCGetLabelsMat($lsc, $matLabelsOut)
    ; cveSuperpixelLSCGetLabels using cv::Mat instead of _*Array

    Local $oArrLabelsOut, $vectorOfMatLabelsOut, $iArrLabelsOutSize
    Local $bLabelsOutIsArray = VarGetType($matLabelsOut) == "Array"

    If $bLabelsOutIsArray Then
        $vectorOfMatLabelsOut = _VectorOfMatCreate()

        $iArrLabelsOutSize = UBound($matLabelsOut)
        For $i = 0 To $iArrLabelsOutSize - 1
            _VectorOfMatPush($vectorOfMatLabelsOut, $matLabelsOut[$i])
        Next

        $oArrLabelsOut = _cveOutputArrayFromVectorOfMat($vectorOfMatLabelsOut)
    Else
        $oArrLabelsOut = _cveOutputArrayFromMat($matLabelsOut)
    EndIf

    _cveSuperpixelLSCGetLabels($lsc, $oArrLabelsOut)

    If $bLabelsOutIsArray Then
        _VectorOfMatRelease($vectorOfMatLabelsOut)
    EndIf

    _cveOutputArrayRelease($oArrLabelsOut)
EndFunc   ;==>_cveSuperpixelLSCGetLabelsMat

Func _cveSuperpixelLSCGetLabelContourMask($lsc, $image, $thickLine)
    ; CVAPI(void) cveSuperpixelLSCGetLabelContourMask(cv::ximgproc::SuperpixelLSC* lsc, cv::_OutputArray* image, bool thickLine);

    Local $bLscDllType
    If VarGetType($lsc) == "DLLStruct" Then
        $bLscDllType = "struct*"
    Else
        $bLscDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCGetLabelContourMask", $bLscDllType, $lsc, $bImageDllType, $image, "boolean", $thickLine), "cveSuperpixelLSCGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelLSCGetLabelContourMask

Func _cveSuperpixelLSCGetLabelContourMaskMat($lsc, $matImage, $thickLine)
    ; cveSuperpixelLSCGetLabelContourMask using cv::Mat instead of _*Array

    Local $oArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $oArrImage = _cveOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $oArrImage = _cveOutputArrayFromMat($matImage)
    EndIf

    _cveSuperpixelLSCGetLabelContourMask($lsc, $oArrImage, $thickLine)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveOutputArrayRelease($oArrImage)
EndFunc   ;==>_cveSuperpixelLSCGetLabelContourMaskMat

Func _cveSuperpixelLSCEnforceLabelConnectivity($lsc, $minElementSize)
    ; CVAPI(void) cveSuperpixelLSCEnforceLabelConnectivity(cv::ximgproc::SuperpixelLSC* lsc, int minElementSize);

    Local $bLscDllType
    If VarGetType($lsc) == "DLLStruct" Then
        $bLscDllType = "struct*"
    Else
        $bLscDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCEnforceLabelConnectivity", $bLscDllType, $lsc, "int", $minElementSize), "cveSuperpixelLSCEnforceLabelConnectivity", @error)
EndFunc   ;==>_cveSuperpixelLSCEnforceLabelConnectivity

Func _cveSuperpixelLSCRelease($lsc, $sharedPtr)
    ; CVAPI(void) cveSuperpixelLSCRelease(cv::ximgproc::SuperpixelLSC** lsc, cv::Ptr<cv::ximgproc::SuperpixelLSC>** sharedPtr);

    Local $bLscDllType
    If VarGetType($lsc) == "DLLStruct" Then
        $bLscDllType = "struct*"
    Else
        $bLscDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCRelease", $bLscDllType, $lsc, $bSharedPtrDllType, $sharedPtr), "cveSuperpixelLSCRelease", @error)
EndFunc   ;==>_cveSuperpixelLSCRelease

Func _cveSuperpixelSLICCreate($image, $algorithm, $regionSize, $ruler, $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelSLIC*) cveSuperpixelSLICCreate(cv::_InputArray* image, int algorithm, int regionSize, float ruler, cv::Ptr<cv::ximgproc::SuperpixelSLIC>** sharedPtr);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelSLICCreate", $bImageDllType, $image, "int", $algorithm, "int", $regionSize, "float", $ruler, $bSharedPtrDllType, $sharedPtr), "cveSuperpixelSLICCreate", @error)
EndFunc   ;==>_cveSuperpixelSLICCreate

Func _cveSuperpixelSLICCreateMat($matImage, $algorithm, $regionSize, $ruler, $sharedPtr)
    ; cveSuperpixelSLICCreate using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $retval = _cveSuperpixelSLICCreate($iArrImage, $algorithm, $regionSize, $ruler, $sharedPtr)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveSuperpixelSLICCreateMat

Func _cveSuperpixelSLICGetNumberOfSuperpixels($slic)
    ; CVAPI(int) cveSuperpixelSLICGetNumberOfSuperpixels(cv::ximgproc::SuperpixelSLIC* slic);

    Local $bSlicDllType
    If VarGetType($slic) == "DLLStruct" Then
        $bSlicDllType = "struct*"
    Else
        $bSlicDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelSLICGetNumberOfSuperpixels", $bSlicDllType, $slic), "cveSuperpixelSLICGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelSLICGetNumberOfSuperpixels

Func _cveSuperpixelSLICIterate($slic, $numIterations)
    ; CVAPI(void) cveSuperpixelSLICIterate(cv::ximgproc::SuperpixelSLIC* slic, int numIterations);

    Local $bSlicDllType
    If VarGetType($slic) == "DLLStruct" Then
        $bSlicDllType = "struct*"
    Else
        $bSlicDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICIterate", $bSlicDllType, $slic, "int", $numIterations), "cveSuperpixelSLICIterate", @error)
EndFunc   ;==>_cveSuperpixelSLICIterate

Func _cveSuperpixelSLICGetLabels($slic, $labelsOut)
    ; CVAPI(void) cveSuperpixelSLICGetLabels(cv::ximgproc::SuperpixelSLIC* slic, cv::_OutputArray* labelsOut);

    Local $bSlicDllType
    If VarGetType($slic) == "DLLStruct" Then
        $bSlicDllType = "struct*"
    Else
        $bSlicDllType = "ptr"
    EndIf

    Local $bLabelsOutDllType
    If VarGetType($labelsOut) == "DLLStruct" Then
        $bLabelsOutDllType = "struct*"
    Else
        $bLabelsOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICGetLabels", $bSlicDllType, $slic, $bLabelsOutDllType, $labelsOut), "cveSuperpixelSLICGetLabels", @error)
EndFunc   ;==>_cveSuperpixelSLICGetLabels

Func _cveSuperpixelSLICGetLabelsMat($slic, $matLabelsOut)
    ; cveSuperpixelSLICGetLabels using cv::Mat instead of _*Array

    Local $oArrLabelsOut, $vectorOfMatLabelsOut, $iArrLabelsOutSize
    Local $bLabelsOutIsArray = VarGetType($matLabelsOut) == "Array"

    If $bLabelsOutIsArray Then
        $vectorOfMatLabelsOut = _VectorOfMatCreate()

        $iArrLabelsOutSize = UBound($matLabelsOut)
        For $i = 0 To $iArrLabelsOutSize - 1
            _VectorOfMatPush($vectorOfMatLabelsOut, $matLabelsOut[$i])
        Next

        $oArrLabelsOut = _cveOutputArrayFromVectorOfMat($vectorOfMatLabelsOut)
    Else
        $oArrLabelsOut = _cveOutputArrayFromMat($matLabelsOut)
    EndIf

    _cveSuperpixelSLICGetLabels($slic, $oArrLabelsOut)

    If $bLabelsOutIsArray Then
        _VectorOfMatRelease($vectorOfMatLabelsOut)
    EndIf

    _cveOutputArrayRelease($oArrLabelsOut)
EndFunc   ;==>_cveSuperpixelSLICGetLabelsMat

Func _cveSuperpixelSLICGetLabelContourMask($slic, $image, $thickLine)
    ; CVAPI(void) cveSuperpixelSLICGetLabelContourMask(cv::ximgproc::SuperpixelSLIC* slic, cv::_OutputArray* image, bool thickLine);

    Local $bSlicDllType
    If VarGetType($slic) == "DLLStruct" Then
        $bSlicDllType = "struct*"
    Else
        $bSlicDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICGetLabelContourMask", $bSlicDllType, $slic, $bImageDllType, $image, "boolean", $thickLine), "cveSuperpixelSLICGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelSLICGetLabelContourMask

Func _cveSuperpixelSLICGetLabelContourMaskMat($slic, $matImage, $thickLine)
    ; cveSuperpixelSLICGetLabelContourMask using cv::Mat instead of _*Array

    Local $oArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $oArrImage = _cveOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $oArrImage = _cveOutputArrayFromMat($matImage)
    EndIf

    _cveSuperpixelSLICGetLabelContourMask($slic, $oArrImage, $thickLine)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveOutputArrayRelease($oArrImage)
EndFunc   ;==>_cveSuperpixelSLICGetLabelContourMaskMat

Func _cveSuperpixelSLICEnforceLabelConnectivity($slic, $minElementSize)
    ; CVAPI(void) cveSuperpixelSLICEnforceLabelConnectivity(cv::ximgproc::SuperpixelSLIC* slic, int minElementSize);

    Local $bSlicDllType
    If VarGetType($slic) == "DLLStruct" Then
        $bSlicDllType = "struct*"
    Else
        $bSlicDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICEnforceLabelConnectivity", $bSlicDllType, $slic, "int", $minElementSize), "cveSuperpixelSLICEnforceLabelConnectivity", @error)
EndFunc   ;==>_cveSuperpixelSLICEnforceLabelConnectivity

Func _cveSuperpixelSLICRelease($slic, $sharedPtr)
    ; CVAPI(void) cveSuperpixelSLICRelease(cv::ximgproc::SuperpixelSLIC** slic, cv::Ptr<cv::ximgproc::SuperpixelSLIC>** sharedPtr);

    Local $bSlicDllType
    If VarGetType($slic) == "DLLStruct" Then
        $bSlicDllType = "struct*"
    Else
        $bSlicDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICRelease", $bSlicDllType, $slic, $bSharedPtrDllType, $sharedPtr), "cveSuperpixelSLICRelease", @error)
EndFunc   ;==>_cveSuperpixelSLICRelease

Func _cveGraphSegmentationCreate($sigma, $k, $minSize, $sharedPtr)
    ; CVAPI(cv::ximgproc::segmentation::GraphSegmentation*) cveGraphSegmentationCreate(double sigma, float k, int minSize, cv::Ptr<cv::ximgproc::segmentation::GraphSegmentation>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGraphSegmentationCreate", "double", $sigma, "float", $k, "int", $minSize, $bSharedPtrDllType, $sharedPtr), "cveGraphSegmentationCreate", @error)
EndFunc   ;==>_cveGraphSegmentationCreate

Func _cveGraphSegmentationProcessImage($segmentation, $src, $dst)
    ; CVAPI(void) cveGraphSegmentationProcessImage(cv::ximgproc::segmentation::GraphSegmentation* segmentation, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphSegmentationProcessImage", $bSegmentationDllType, $segmentation, $bSrcDllType, $src, $bDstDllType, $dst), "cveGraphSegmentationProcessImage", @error)
EndFunc   ;==>_cveGraphSegmentationProcessImage

Func _cveGraphSegmentationProcessImageMat($segmentation, $matSrc, $matDst)
    ; cveGraphSegmentationProcessImage using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveGraphSegmentationProcessImage($segmentation, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveGraphSegmentationProcessImageMat

Func _cveGraphSegmentationRelease($segmentation, $sharedPtr)
    ; CVAPI(void) cveGraphSegmentationRelease(cv::ximgproc::segmentation::GraphSegmentation** segmentation, cv::Ptr<cv::ximgproc::segmentation::GraphSegmentation>** sharedPtr);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphSegmentationRelease", $bSegmentationDllType, $segmentation, $bSharedPtrDllType, $sharedPtr), "cveGraphSegmentationRelease", @error)
EndFunc   ;==>_cveGraphSegmentationRelease

Func _cveWeightedMedianFilter($joint, $src, $dst, $r, $sigma = 25.5, $weightType = $CV_WMF_EXP, $mask = _cveNoArray())
    ; CVAPI(void) cveWeightedMedianFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, int r, double sigma, cv::ximgproc::WMFWeightType weightType, cv::Mat* mask);

    Local $bJointDllType
    If VarGetType($joint) == "DLLStruct" Then
        $bJointDllType = "struct*"
    Else
        $bJointDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeightedMedianFilter", $bJointDllType, $joint, $bSrcDllType, $src, $bDstDllType, $dst, "int", $r, "double", $sigma, "int", $weightType, $bMaskDllType, $mask), "cveWeightedMedianFilter", @error)
EndFunc   ;==>_cveWeightedMedianFilter

Func _cveWeightedMedianFilterMat($matJoint, $matSrc, $matDst, $r, $sigma = 25.5, $weightType = $CV_WMF_EXP, $mask = _cveNoArrayMat())
    ; cveWeightedMedianFilter using cv::Mat instead of _*Array

    Local $iArrJoint, $vectorOfMatJoint, $iArrJointSize
    Local $bJointIsArray = VarGetType($matJoint) == "Array"

    If $bJointIsArray Then
        $vectorOfMatJoint = _VectorOfMatCreate()

        $iArrJointSize = UBound($matJoint)
        For $i = 0 To $iArrJointSize - 1
            _VectorOfMatPush($vectorOfMatJoint, $matJoint[$i])
        Next

        $iArrJoint = _cveInputArrayFromVectorOfMat($vectorOfMatJoint)
    Else
        $iArrJoint = _cveInputArrayFromMat($matJoint)
    EndIf

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveWeightedMedianFilter($iArrJoint, $iArrSrc, $oArrDst, $r, $sigma, $weightType, $mask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    If $bJointIsArray Then
        _VectorOfMatRelease($vectorOfMatJoint)
    EndIf

    _cveInputArrayRelease($iArrJoint)
EndFunc   ;==>_cveWeightedMedianFilterMat

Func _cveSelectiveSearchSegmentationCreate($sharedPtr)
    ; CVAPI(cv::ximgproc::segmentation::SelectiveSearchSegmentation*) cveSelectiveSearchSegmentationCreate(cv::Ptr<cv::ximgproc::segmentation::SelectiveSearchSegmentation>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSelectiveSearchSegmentationCreate", $bSharedPtrDllType, $sharedPtr), "cveSelectiveSearchSegmentationCreate", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationCreate

Func _cveSelectiveSearchSegmentationSetBaseImage($segmentation, $image)
    ; CVAPI(void) cveSelectiveSearchSegmentationSetBaseImage(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, cv::_InputArray* image);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSetBaseImage", $bSegmentationDllType, $segmentation, $bImageDllType, $image), "cveSelectiveSearchSegmentationSetBaseImage", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSetBaseImage

Func _cveSelectiveSearchSegmentationSetBaseImageMat($segmentation, $matImage)
    ; cveSelectiveSearchSegmentationSetBaseImage using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    _cveSelectiveSearchSegmentationSetBaseImage($segmentation, $iArrImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveSelectiveSearchSegmentationSetBaseImageMat

Func _cveSelectiveSearchSegmentationSwitchToSingleStrategy($segmentation, $k, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSingleStrategy(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int k, float sigma);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSingleStrategy", $bSegmentationDllType, $segmentation, "int", $k, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSingleStrategy", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSingleStrategy

Func _cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast($segmentation, $baseK, $incK, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int baseK, int incK, float sigma);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast", $bSegmentationDllType, $segmentation, "int", $baseK, "int", $incK, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast

Func _cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality($segmentation, $baseK, $incK, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int baseK, int incK, float sigma);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality", $bSegmentationDllType, $segmentation, "int", $baseK, "int", $incK, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality

Func _cveSelectiveSearchSegmentationAddImage($segmentation, $img)
    ; CVAPI(void) cveSelectiveSearchSegmentationAddImage(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, cv::_InputArray* img);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationAddImage", $bSegmentationDllType, $segmentation, $bImgDllType, $img), "cveSelectiveSearchSegmentationAddImage", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationAddImage

Func _cveSelectiveSearchSegmentationAddImageMat($segmentation, $matImg)
    ; cveSelectiveSearchSegmentationAddImage using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    _cveSelectiveSearchSegmentationAddImage($segmentation, $iArrImg)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveSelectiveSearchSegmentationAddImageMat

Func _cveSelectiveSearchSegmentationProcess($segmentation, $rects)
    ; CVAPI(void) cveSelectiveSearchSegmentationProcess(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, std::vector<cv::Rect>* rects);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr"
    EndIf

    Local $vecRects, $iArrRectsSize
    Local $bRectsIsArray = VarGetType($rects) == "Array"

    If $bRectsIsArray Then
        $vecRects = _VectorOfRectCreate()

        $iArrRectsSize = UBound($rects)
        For $i = 0 To $iArrRectsSize - 1
            _VectorOfRectPush($vecRects, $rects[$i])
        Next
    Else
        $vecRects = $rects
    EndIf

    Local $bRectsDllType
    If VarGetType($rects) == "DLLStruct" Then
        $bRectsDllType = "struct*"
    Else
        $bRectsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationProcess", $bSegmentationDllType, $segmentation, $bRectsDllType, $vecRects), "cveSelectiveSearchSegmentationProcess", @error)

    If $bRectsIsArray Then
        _VectorOfRectRelease($vecRects)
    EndIf
EndFunc   ;==>_cveSelectiveSearchSegmentationProcess

Func _cveSelectiveSearchSegmentationRelease($segmentation, $sharedPtr)
    ; CVAPI(void) cveSelectiveSearchSegmentationRelease(cv::ximgproc::segmentation::SelectiveSearchSegmentation** segmentation, cv::Ptr<cv::ximgproc::segmentation::SelectiveSearchSegmentation>** sharedPtr);

    Local $bSegmentationDllType
    If VarGetType($segmentation) == "DLLStruct" Then
        $bSegmentationDllType = "struct*"
    Else
        $bSegmentationDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationRelease", $bSegmentationDllType, $segmentation, $bSharedPtrDllType, $sharedPtr), "cveSelectiveSearchSegmentationRelease", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationRelease

Func _cveGradientPaillouY($op, $dst, $alpha, $omega)
    ; CVAPI(void) cveGradientPaillouY(cv::_InputArray* op, cv::_OutputArray* dst, double alpha, double omega);

    Local $bOpDllType
    If VarGetType($op) == "DLLStruct" Then
        $bOpDllType = "struct*"
    Else
        $bOpDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientPaillouY", $bOpDllType, $op, $bDstDllType, $dst, "double", $alpha, "double", $omega), "cveGradientPaillouY", @error)
EndFunc   ;==>_cveGradientPaillouY

Func _cveGradientPaillouYMat($matOp, $matDst, $alpha, $omega)
    ; cveGradientPaillouY using cv::Mat instead of _*Array

    Local $iArrOp, $vectorOfMatOp, $iArrOpSize
    Local $bOpIsArray = VarGetType($matOp) == "Array"

    If $bOpIsArray Then
        $vectorOfMatOp = _VectorOfMatCreate()

        $iArrOpSize = UBound($matOp)
        For $i = 0 To $iArrOpSize - 1
            _VectorOfMatPush($vectorOfMatOp, $matOp[$i])
        Next

        $iArrOp = _cveInputArrayFromVectorOfMat($vectorOfMatOp)
    Else
        $iArrOp = _cveInputArrayFromMat($matOp)
    EndIf

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

    _cveGradientPaillouY($iArrOp, $oArrDst, $alpha, $omega)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bOpIsArray Then
        _VectorOfMatRelease($vectorOfMatOp)
    EndIf

    _cveInputArrayRelease($iArrOp)
EndFunc   ;==>_cveGradientPaillouYMat

Func _cveGradientPaillouX($op, $dst, $alpha, $omega)
    ; CVAPI(void) cveGradientPaillouX(cv::_InputArray* op, cv::_OutputArray* dst, double alpha, double omega);

    Local $bOpDllType
    If VarGetType($op) == "DLLStruct" Then
        $bOpDllType = "struct*"
    Else
        $bOpDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientPaillouX", $bOpDllType, $op, $bDstDllType, $dst, "double", $alpha, "double", $omega), "cveGradientPaillouX", @error)
EndFunc   ;==>_cveGradientPaillouX

Func _cveGradientPaillouXMat($matOp, $matDst, $alpha, $omega)
    ; cveGradientPaillouX using cv::Mat instead of _*Array

    Local $iArrOp, $vectorOfMatOp, $iArrOpSize
    Local $bOpIsArray = VarGetType($matOp) == "Array"

    If $bOpIsArray Then
        $vectorOfMatOp = _VectorOfMatCreate()

        $iArrOpSize = UBound($matOp)
        For $i = 0 To $iArrOpSize - 1
            _VectorOfMatPush($vectorOfMatOp, $matOp[$i])
        Next

        $iArrOp = _cveInputArrayFromVectorOfMat($vectorOfMatOp)
    Else
        $iArrOp = _cveInputArrayFromMat($matOp)
    EndIf

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

    _cveGradientPaillouX($iArrOp, $oArrDst, $alpha, $omega)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bOpIsArray Then
        _VectorOfMatRelease($vectorOfMatOp)
    EndIf

    _cveInputArrayRelease($iArrOp)
EndFunc   ;==>_cveGradientPaillouXMat

Func _cveGradientDericheY($op, $dst, $alphaDerive, $alphaMean)
    ; CVAPI(void) cveGradientDericheY(cv::_InputArray* op, cv::_OutputArray* dst, double alphaDerive, double alphaMean);

    Local $bOpDllType
    If VarGetType($op) == "DLLStruct" Then
        $bOpDllType = "struct*"
    Else
        $bOpDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientDericheY", $bOpDllType, $op, $bDstDllType, $dst, "double", $alphaDerive, "double", $alphaMean), "cveGradientDericheY", @error)
EndFunc   ;==>_cveGradientDericheY

Func _cveGradientDericheYMat($matOp, $matDst, $alphaDerive, $alphaMean)
    ; cveGradientDericheY using cv::Mat instead of _*Array

    Local $iArrOp, $vectorOfMatOp, $iArrOpSize
    Local $bOpIsArray = VarGetType($matOp) == "Array"

    If $bOpIsArray Then
        $vectorOfMatOp = _VectorOfMatCreate()

        $iArrOpSize = UBound($matOp)
        For $i = 0 To $iArrOpSize - 1
            _VectorOfMatPush($vectorOfMatOp, $matOp[$i])
        Next

        $iArrOp = _cveInputArrayFromVectorOfMat($vectorOfMatOp)
    Else
        $iArrOp = _cveInputArrayFromMat($matOp)
    EndIf

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

    _cveGradientDericheY($iArrOp, $oArrDst, $alphaDerive, $alphaMean)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bOpIsArray Then
        _VectorOfMatRelease($vectorOfMatOp)
    EndIf

    _cveInputArrayRelease($iArrOp)
EndFunc   ;==>_cveGradientDericheYMat

Func _cveGradientDericheX($op, $dst, $alphaDerive, $alphaMean)
    ; CVAPI(void) cveGradientDericheX(cv::_InputArray* op, cv::_OutputArray* dst, double alphaDerive, double alphaMean);

    Local $bOpDllType
    If VarGetType($op) == "DLLStruct" Then
        $bOpDllType = "struct*"
    Else
        $bOpDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientDericheX", $bOpDllType, $op, $bDstDllType, $dst, "double", $alphaDerive, "double", $alphaMean), "cveGradientDericheX", @error)
EndFunc   ;==>_cveGradientDericheX

Func _cveGradientDericheXMat($matOp, $matDst, $alphaDerive, $alphaMean)
    ; cveGradientDericheX using cv::Mat instead of _*Array

    Local $iArrOp, $vectorOfMatOp, $iArrOpSize
    Local $bOpIsArray = VarGetType($matOp) == "Array"

    If $bOpIsArray Then
        $vectorOfMatOp = _VectorOfMatCreate()

        $iArrOpSize = UBound($matOp)
        For $i = 0 To $iArrOpSize - 1
            _VectorOfMatPush($vectorOfMatOp, $matOp[$i])
        Next

        $iArrOp = _cveInputArrayFromVectorOfMat($vectorOfMatOp)
    Else
        $iArrOp = _cveInputArrayFromMat($matOp)
    EndIf

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

    _cveGradientDericheX($iArrOp, $oArrDst, $alphaDerive, $alphaMean)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bOpIsArray Then
        _VectorOfMatRelease($vectorOfMatOp)
    EndIf

    _cveInputArrayRelease($iArrOp)
EndFunc   ;==>_cveGradientDericheXMat

Func _cveThinning($src, $dst, $thinningType = $CV_THINNING_ZHANGSUEN)
    ; CVAPI(void) cveThinning(cv::_InputArray* src, cv::_OutputArray* dst, int thinningType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveThinning", $bSrcDllType, $src, $bDstDllType, $dst, "int", $thinningType), "cveThinning", @error)
EndFunc   ;==>_cveThinning

Func _cveThinningMat($matSrc, $matDst, $thinningType = $CV_THINNING_ZHANGSUEN)
    ; cveThinning using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveThinning($iArrSrc, $oArrDst, $thinningType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveThinningMat

Func _cveAnisotropicDiffusion($src, $dst, $alpha, $K, $niters)
    ; CVAPI(void) cveAnisotropicDiffusion(cv::_InputArray* src, cv::_OutputArray* dst, float alpha, float K, int niters);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAnisotropicDiffusion", $bSrcDllType, $src, $bDstDllType, $dst, "float", $alpha, "float", $K, "int", $niters), "cveAnisotropicDiffusion", @error)
EndFunc   ;==>_cveAnisotropicDiffusion

Func _cveAnisotropicDiffusionMat($matSrc, $matDst, $alpha, $K, $niters)
    ; cveAnisotropicDiffusion using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

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

    _cveAnisotropicDiffusion($iArrSrc, $oArrDst, $alpha, $K, $niters)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveAnisotropicDiffusionMat

Func _cveFastLineDetectorCreate($length_threshold, $distance_threshold, $canny_th1, $canny_th2, $canny_aperture_size, $do_merge, $sharedPtr)
    ; CVAPI(cv::ximgproc::FastLineDetector*) cveFastLineDetectorCreate(int length_threshold, float distance_threshold, double canny_th1, double canny_th2, int canny_aperture_size, bool do_merge, cv::Ptr<cv::ximgproc::FastLineDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFastLineDetectorCreate", "int", $length_threshold, "float", $distance_threshold, "double", $canny_th1, "double", $canny_th2, "int", $canny_aperture_size, "boolean", $do_merge, $bSharedPtrDllType, $sharedPtr), "cveFastLineDetectorCreate", @error)
EndFunc   ;==>_cveFastLineDetectorCreate

Func _cveFastLineDetectorDetect($fld, $image, $lines)
    ; CVAPI(void) cveFastLineDetectorDetect(cv::ximgproc::FastLineDetector* fld, cv::_InputArray* image, cv::_OutputArray* lines);

    Local $bFldDllType
    If VarGetType($fld) == "DLLStruct" Then
        $bFldDllType = "struct*"
    Else
        $bFldDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLinesDllType
    If VarGetType($lines) == "DLLStruct" Then
        $bLinesDllType = "struct*"
    Else
        $bLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorDetect", $bFldDllType, $fld, $bImageDllType, $image, $bLinesDllType, $lines), "cveFastLineDetectorDetect", @error)
EndFunc   ;==>_cveFastLineDetectorDetect

Func _cveFastLineDetectorDetectMat($fld, $matImage, $matLines)
    ; cveFastLineDetectorDetect using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cveFastLineDetectorDetect($fld, $iArrImage, $oArrLines)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveFastLineDetectorDetectMat

Func _cveFastLineDetectorDrawSegments($fld, $image, $lines, $draw_arrow)
    ; CVAPI(void) cveFastLineDetectorDrawSegments(cv::ximgproc::FastLineDetector* fld, cv::_InputOutputArray* image, cv::_InputArray* lines, bool draw_arrow);

    Local $bFldDllType
    If VarGetType($fld) == "DLLStruct" Then
        $bFldDllType = "struct*"
    Else
        $bFldDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLinesDllType
    If VarGetType($lines) == "DLLStruct" Then
        $bLinesDllType = "struct*"
    Else
        $bLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorDrawSegments", $bFldDllType, $fld, $bImageDllType, $image, $bLinesDllType, $lines, "boolean", $draw_arrow), "cveFastLineDetectorDrawSegments", @error)
EndFunc   ;==>_cveFastLineDetectorDrawSegments

Func _cveFastLineDetectorDrawSegmentsMat($fld, $matImage, $matLines, $draw_arrow)
    ; cveFastLineDetectorDrawSegments using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $iArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $iArrLines = _cveInputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $iArrLines = _cveInputArrayFromMat($matLines)
    EndIf

    _cveFastLineDetectorDrawSegments($fld, $ioArrImage, $iArrLines, $draw_arrow)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveInputArrayRelease($iArrLines)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
EndFunc   ;==>_cveFastLineDetectorDrawSegmentsMat

Func _cveFastLineDetectorRelease($fld)
    ; CVAPI(void) cveFastLineDetectorRelease(cv::Ptr<cv::ximgproc::FastLineDetector>** fld);

    Local $bFldDllType
    If VarGetType($fld) == "DLLStruct" Then
        $bFldDllType = "struct*"
    Else
        $bFldDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorRelease", $bFldDllType, $fld), "cveFastLineDetectorRelease", @error)
EndFunc   ;==>_cveFastLineDetectorRelease

Func _cveBrightEdges($original, $edgeview, $contrast, $shortrange, $longrange)
    ; CVAPI(void) cveBrightEdges(cv::Mat* original, cv::Mat* edgeview, int contrast, int shortrange, int longrange);

    Local $bOriginalDllType
    If VarGetType($original) == "DLLStruct" Then
        $bOriginalDllType = "struct*"
    Else
        $bOriginalDllType = "ptr"
    EndIf

    Local $bEdgeviewDllType
    If VarGetType($edgeview) == "DLLStruct" Then
        $bEdgeviewDllType = "struct*"
    Else
        $bEdgeviewDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBrightEdges", $bOriginalDllType, $original, $bEdgeviewDllType, $edgeview, "int", $contrast, "int", $shortrange, "int", $longrange), "cveBrightEdges", @error)
EndFunc   ;==>_cveBrightEdges

Func _cveCreateDisparityWLSFilter($matcherLeft, $disparityFilter, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::DisparityWLSFilter*) cveCreateDisparityWLSFilter(cv::StereoMatcher* matcherLeft, cv::ximgproc::DisparityFilter** disparityFilter, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);

    Local $bMatcherLeftDllType
    If VarGetType($matcherLeft) == "DLLStruct" Then
        $bMatcherLeftDllType = "struct*"
    Else
        $bMatcherLeftDllType = "ptr"
    EndIf

    Local $bDisparityFilterDllType
    If VarGetType($disparityFilter) == "DLLStruct" Then
        $bDisparityFilterDllType = "struct*"
    Else
        $bDisparityFilterDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateDisparityWLSFilter", $bMatcherLeftDllType, $matcherLeft, $bDisparityFilterDllType, $disparityFilter, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveCreateDisparityWLSFilter", @error)
EndFunc   ;==>_cveCreateDisparityWLSFilter

Func _cveCreateRightMatcher($matcherLeft, $sharedPtr)
    ; CVAPI(cv::StereoMatcher*) cveCreateRightMatcher(cv::StereoMatcher* matcherLeft, cv::Ptr<cv::StereoMatcher>** sharedPtr);

    Local $bMatcherLeftDllType
    If VarGetType($matcherLeft) == "DLLStruct" Then
        $bMatcherLeftDllType = "struct*"
    Else
        $bMatcherLeftDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateRightMatcher", $bMatcherLeftDllType, $matcherLeft, $bSharedPtrDllType, $sharedPtr), "cveCreateRightMatcher", @error)
EndFunc   ;==>_cveCreateRightMatcher

Func _cveCreateDisparityWLSFilterGeneric($use_confidence, $disparityFilter, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::DisparityWLSFilter*) cveCreateDisparityWLSFilterGeneric(bool use_confidence, cv::ximgproc::DisparityFilter** disparityFilter, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);

    Local $bDisparityFilterDllType
    If VarGetType($disparityFilter) == "DLLStruct" Then
        $bDisparityFilterDllType = "struct*"
    Else
        $bDisparityFilterDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateDisparityWLSFilterGeneric", "boolean", $use_confidence, $bDisparityFilterDllType, $disparityFilter, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveCreateDisparityWLSFilterGeneric", @error)
EndFunc   ;==>_cveCreateDisparityWLSFilterGeneric

Func _cveDisparityWLSFilterRelease($sharedPtr)
    ; CVAPI(void) cveDisparityWLSFilterRelease(cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDisparityWLSFilterRelease", $bSharedPtrDllType, $sharedPtr), "cveDisparityWLSFilterRelease", @error)
EndFunc   ;==>_cveDisparityWLSFilterRelease

Func _cveDisparityFilterFilter($disparityFilter, $disparity_map_left, $left_view, $filtered_disparity_map, $disparity_map_right, $ROI, $right_view)
    ; CVAPI(void) cveDisparityFilterFilter(cv::ximgproc::DisparityFilter* disparityFilter, cv::_InputArray* disparity_map_left, cv::_InputArray* left_view, cv::_OutputArray* filtered_disparity_map, cv::_InputArray* disparity_map_right, CvRect* ROI, cv::_InputArray* right_view);

    Local $bDisparityFilterDllType
    If VarGetType($disparityFilter) == "DLLStruct" Then
        $bDisparityFilterDllType = "struct*"
    Else
        $bDisparityFilterDllType = "ptr"
    EndIf

    Local $bDisparity_map_leftDllType
    If VarGetType($disparity_map_left) == "DLLStruct" Then
        $bDisparity_map_leftDllType = "struct*"
    Else
        $bDisparity_map_leftDllType = "ptr"
    EndIf

    Local $bLeft_viewDllType
    If VarGetType($left_view) == "DLLStruct" Then
        $bLeft_viewDllType = "struct*"
    Else
        $bLeft_viewDllType = "ptr"
    EndIf

    Local $bFiltered_disparity_mapDllType
    If VarGetType($filtered_disparity_map) == "DLLStruct" Then
        $bFiltered_disparity_mapDllType = "struct*"
    Else
        $bFiltered_disparity_mapDllType = "ptr"
    EndIf

    Local $bDisparity_map_rightDllType
    If VarGetType($disparity_map_right) == "DLLStruct" Then
        $bDisparity_map_rightDllType = "struct*"
    Else
        $bDisparity_map_rightDllType = "ptr"
    EndIf

    Local $bROIDllType
    If VarGetType($ROI) == "DLLStruct" Then
        $bROIDllType = "struct*"
    Else
        $bROIDllType = "ptr"
    EndIf

    Local $bRight_viewDllType
    If VarGetType($right_view) == "DLLStruct" Then
        $bRight_viewDllType = "struct*"
    Else
        $bRight_viewDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDisparityFilterFilter", $bDisparityFilterDllType, $disparityFilter, $bDisparity_map_leftDllType, $disparity_map_left, $bLeft_viewDllType, $left_view, $bFiltered_disparity_mapDllType, $filtered_disparity_map, $bDisparity_map_rightDllType, $disparity_map_right, $bROIDllType, $ROI, $bRight_viewDllType, $right_view), "cveDisparityFilterFilter", @error)
EndFunc   ;==>_cveDisparityFilterFilter

Func _cveDisparityFilterFilterMat($disparityFilter, $matDisparity_map_left, $matLeft_view, $matFiltered_disparity_map, $matDisparity_map_right, $ROI, $matRight_view)
    ; cveDisparityFilterFilter using cv::Mat instead of _*Array

    Local $iArrDisparity_map_left, $vectorOfMatDisparity_map_left, $iArrDisparity_map_leftSize
    Local $bDisparity_map_leftIsArray = VarGetType($matDisparity_map_left) == "Array"

    If $bDisparity_map_leftIsArray Then
        $vectorOfMatDisparity_map_left = _VectorOfMatCreate()

        $iArrDisparity_map_leftSize = UBound($matDisparity_map_left)
        For $i = 0 To $iArrDisparity_map_leftSize - 1
            _VectorOfMatPush($vectorOfMatDisparity_map_left, $matDisparity_map_left[$i])
        Next

        $iArrDisparity_map_left = _cveInputArrayFromVectorOfMat($vectorOfMatDisparity_map_left)
    Else
        $iArrDisparity_map_left = _cveInputArrayFromMat($matDisparity_map_left)
    EndIf

    Local $iArrLeft_view, $vectorOfMatLeft_view, $iArrLeft_viewSize
    Local $bLeft_viewIsArray = VarGetType($matLeft_view) == "Array"

    If $bLeft_viewIsArray Then
        $vectorOfMatLeft_view = _VectorOfMatCreate()

        $iArrLeft_viewSize = UBound($matLeft_view)
        For $i = 0 To $iArrLeft_viewSize - 1
            _VectorOfMatPush($vectorOfMatLeft_view, $matLeft_view[$i])
        Next

        $iArrLeft_view = _cveInputArrayFromVectorOfMat($vectorOfMatLeft_view)
    Else
        $iArrLeft_view = _cveInputArrayFromMat($matLeft_view)
    EndIf

    Local $oArrFiltered_disparity_map, $vectorOfMatFiltered_disparity_map, $iArrFiltered_disparity_mapSize
    Local $bFiltered_disparity_mapIsArray = VarGetType($matFiltered_disparity_map) == "Array"

    If $bFiltered_disparity_mapIsArray Then
        $vectorOfMatFiltered_disparity_map = _VectorOfMatCreate()

        $iArrFiltered_disparity_mapSize = UBound($matFiltered_disparity_map)
        For $i = 0 To $iArrFiltered_disparity_mapSize - 1
            _VectorOfMatPush($vectorOfMatFiltered_disparity_map, $matFiltered_disparity_map[$i])
        Next

        $oArrFiltered_disparity_map = _cveOutputArrayFromVectorOfMat($vectorOfMatFiltered_disparity_map)
    Else
        $oArrFiltered_disparity_map = _cveOutputArrayFromMat($matFiltered_disparity_map)
    EndIf

    Local $iArrDisparity_map_right, $vectorOfMatDisparity_map_right, $iArrDisparity_map_rightSize
    Local $bDisparity_map_rightIsArray = VarGetType($matDisparity_map_right) == "Array"

    If $bDisparity_map_rightIsArray Then
        $vectorOfMatDisparity_map_right = _VectorOfMatCreate()

        $iArrDisparity_map_rightSize = UBound($matDisparity_map_right)
        For $i = 0 To $iArrDisparity_map_rightSize - 1
            _VectorOfMatPush($vectorOfMatDisparity_map_right, $matDisparity_map_right[$i])
        Next

        $iArrDisparity_map_right = _cveInputArrayFromVectorOfMat($vectorOfMatDisparity_map_right)
    Else
        $iArrDisparity_map_right = _cveInputArrayFromMat($matDisparity_map_right)
    EndIf

    Local $iArrRight_view, $vectorOfMatRight_view, $iArrRight_viewSize
    Local $bRight_viewIsArray = VarGetType($matRight_view) == "Array"

    If $bRight_viewIsArray Then
        $vectorOfMatRight_view = _VectorOfMatCreate()

        $iArrRight_viewSize = UBound($matRight_view)
        For $i = 0 To $iArrRight_viewSize - 1
            _VectorOfMatPush($vectorOfMatRight_view, $matRight_view[$i])
        Next

        $iArrRight_view = _cveInputArrayFromVectorOfMat($vectorOfMatRight_view)
    Else
        $iArrRight_view = _cveInputArrayFromMat($matRight_view)
    EndIf

    _cveDisparityFilterFilter($disparityFilter, $iArrDisparity_map_left, $iArrLeft_view, $oArrFiltered_disparity_map, $iArrDisparity_map_right, $ROI, $iArrRight_view)

    If $bRight_viewIsArray Then
        _VectorOfMatRelease($vectorOfMatRight_view)
    EndIf

    _cveInputArrayRelease($iArrRight_view)

    If $bDisparity_map_rightIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity_map_right)
    EndIf

    _cveInputArrayRelease($iArrDisparity_map_right)

    If $bFiltered_disparity_mapIsArray Then
        _VectorOfMatRelease($vectorOfMatFiltered_disparity_map)
    EndIf

    _cveOutputArrayRelease($oArrFiltered_disparity_map)

    If $bLeft_viewIsArray Then
        _VectorOfMatRelease($vectorOfMatLeft_view)
    EndIf

    _cveInputArrayRelease($iArrLeft_view)

    If $bDisparity_map_leftIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity_map_left)
    EndIf

    _cveInputArrayRelease($iArrDisparity_map_left)
EndFunc   ;==>_cveDisparityFilterFilterMat

Func _cveRidgeDetectionFilterCreate($ddepth, $dx, $dy, $ksize, $outDtype, $scale, $delta, $borderType, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::RidgeDetectionFilter*) cveRidgeDetectionFilterCreate(int ddepth, int dx, int dy, int ksize, int outDtype, double scale, double delta, int borderType, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::RidgeDetectionFilter>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRidgeDetectionFilterCreate", "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "int", $outDtype, "double", $scale, "double", $delta, "int", $borderType, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveRidgeDetectionFilterCreate", @error)
EndFunc   ;==>_cveRidgeDetectionFilterCreate

Func _cveRidgeDetectionFilterRelease($sharedPtr)
    ; CVAPI(void) cveRidgeDetectionFilterRelease(cv::Ptr<cv::ximgproc::RidgeDetectionFilter>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRidgeDetectionFilterRelease", $bSharedPtrDllType, $sharedPtr), "cveRidgeDetectionFilterRelease", @error)
EndFunc   ;==>_cveRidgeDetectionFilterRelease

Func _cveRidgeDetectionFilterGetRidgeFilteredImage($ridgeDetection, $img, $out)
    ; CVAPI(void) cveRidgeDetectionFilterGetRidgeFilteredImage(cv::ximgproc::RidgeDetectionFilter* ridgeDetection, cv::_InputArray* img, cv::_OutputArray* out);

    Local $bRidgeDetectionDllType
    If VarGetType($ridgeDetection) == "DLLStruct" Then
        $bRidgeDetectionDllType = "struct*"
    Else
        $bRidgeDetectionDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bOutDllType
    If VarGetType($out) == "DLLStruct" Then
        $bOutDllType = "struct*"
    Else
        $bOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRidgeDetectionFilterGetRidgeFilteredImage", $bRidgeDetectionDllType, $ridgeDetection, $bImgDllType, $img, $bOutDllType, $out), "cveRidgeDetectionFilterGetRidgeFilteredImage", @error)
EndFunc   ;==>_cveRidgeDetectionFilterGetRidgeFilteredImage

Func _cveRidgeDetectionFilterGetRidgeFilteredImageMat($ridgeDetection, $matImg, $matOut)
    ; cveRidgeDetectionFilterGetRidgeFilteredImage using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrOut, $vectorOfMatOut, $iArrOutSize
    Local $bOutIsArray = VarGetType($matOut) == "Array"

    If $bOutIsArray Then
        $vectorOfMatOut = _VectorOfMatCreate()

        $iArrOutSize = UBound($matOut)
        For $i = 0 To $iArrOutSize - 1
            _VectorOfMatPush($vectorOfMatOut, $matOut[$i])
        Next

        $oArrOut = _cveOutputArrayFromVectorOfMat($vectorOfMatOut)
    Else
        $oArrOut = _cveOutputArrayFromMat($matOut)
    EndIf

    _cveRidgeDetectionFilterGetRidgeFilteredImage($ridgeDetection, $iArrImg, $oArrOut)

    If $bOutIsArray Then
        _VectorOfMatRelease($vectorOfMatOut)
    EndIf

    _cveOutputArrayRelease($oArrOut)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveRidgeDetectionFilterGetRidgeFilteredImageMat

Func _cveEdgeBoxesCreate($alpha, $beta, $eta, $minScore, $maxBoxes, $edgeMinMag, $edgeMergeThr, $clusterMinMag, $maxAspectRatio, $minBoxArea, $gamma, $kappa, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::EdgeBoxes*) cveEdgeBoxesCreate(float alpha, float beta, float eta, float minScore, int maxBoxes, float edgeMinMag, float edgeMergeThr, float clusterMinMag, float maxAspectRatio, float minBoxArea, float gamma, float kappa, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::EdgeBoxes>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEdgeBoxesCreate", "float", $alpha, "float", $beta, "float", $eta, "float", $minScore, "int", $maxBoxes, "float", $edgeMinMag, "float", $edgeMergeThr, "float", $clusterMinMag, "float", $maxAspectRatio, "float", $minBoxArea, "float", $gamma, "float", $kappa, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveEdgeBoxesCreate", @error)
EndFunc   ;==>_cveEdgeBoxesCreate

Func _cveEdgeBoxesGetBoundingBoxes($edgeBoxes, $edgeMap, $orientationMap, $boxes)
    ; CVAPI(void) cveEdgeBoxesGetBoundingBoxes(cv::ximgproc::EdgeBoxes* edgeBoxes, cv::_InputArray* edgeMap, cv::_InputArray* orientationMap, std::vector<cv::Rect>* boxes);

    Local $bEdgeBoxesDllType
    If VarGetType($edgeBoxes) == "DLLStruct" Then
        $bEdgeBoxesDllType = "struct*"
    Else
        $bEdgeBoxesDllType = "ptr"
    EndIf

    Local $bEdgeMapDllType
    If VarGetType($edgeMap) == "DLLStruct" Then
        $bEdgeMapDllType = "struct*"
    Else
        $bEdgeMapDllType = "ptr"
    EndIf

    Local $bOrientationMapDllType
    If VarGetType($orientationMap) == "DLLStruct" Then
        $bOrientationMapDllType = "struct*"
    Else
        $bOrientationMapDllType = "ptr"
    EndIf

    Local $vecBoxes, $iArrBoxesSize
    Local $bBoxesIsArray = VarGetType($boxes) == "Array"

    If $bBoxesIsArray Then
        $vecBoxes = _VectorOfRectCreate()

        $iArrBoxesSize = UBound($boxes)
        For $i = 0 To $iArrBoxesSize - 1
            _VectorOfRectPush($vecBoxes, $boxes[$i])
        Next
    Else
        $vecBoxes = $boxes
    EndIf

    Local $bBoxesDllType
    If VarGetType($boxes) == "DLLStruct" Then
        $bBoxesDllType = "struct*"
    Else
        $bBoxesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeBoxesGetBoundingBoxes", $bEdgeBoxesDllType, $edgeBoxes, $bEdgeMapDllType, $edgeMap, $bOrientationMapDllType, $orientationMap, $bBoxesDllType, $vecBoxes), "cveEdgeBoxesGetBoundingBoxes", @error)

    If $bBoxesIsArray Then
        _VectorOfRectRelease($vecBoxes)
    EndIf
EndFunc   ;==>_cveEdgeBoxesGetBoundingBoxes

Func _cveEdgeBoxesGetBoundingBoxesMat($edgeBoxes, $matEdgeMap, $matOrientationMap, $boxes)
    ; cveEdgeBoxesGetBoundingBoxes using cv::Mat instead of _*Array

    Local $iArrEdgeMap, $vectorOfMatEdgeMap, $iArrEdgeMapSize
    Local $bEdgeMapIsArray = VarGetType($matEdgeMap) == "Array"

    If $bEdgeMapIsArray Then
        $vectorOfMatEdgeMap = _VectorOfMatCreate()

        $iArrEdgeMapSize = UBound($matEdgeMap)
        For $i = 0 To $iArrEdgeMapSize - 1
            _VectorOfMatPush($vectorOfMatEdgeMap, $matEdgeMap[$i])
        Next

        $iArrEdgeMap = _cveInputArrayFromVectorOfMat($vectorOfMatEdgeMap)
    Else
        $iArrEdgeMap = _cveInputArrayFromMat($matEdgeMap)
    EndIf

    Local $iArrOrientationMap, $vectorOfMatOrientationMap, $iArrOrientationMapSize
    Local $bOrientationMapIsArray = VarGetType($matOrientationMap) == "Array"

    If $bOrientationMapIsArray Then
        $vectorOfMatOrientationMap = _VectorOfMatCreate()

        $iArrOrientationMapSize = UBound($matOrientationMap)
        For $i = 0 To $iArrOrientationMapSize - 1
            _VectorOfMatPush($vectorOfMatOrientationMap, $matOrientationMap[$i])
        Next

        $iArrOrientationMap = _cveInputArrayFromVectorOfMat($vectorOfMatOrientationMap)
    Else
        $iArrOrientationMap = _cveInputArrayFromMat($matOrientationMap)
    EndIf

    _cveEdgeBoxesGetBoundingBoxes($edgeBoxes, $iArrEdgeMap, $iArrOrientationMap, $boxes)

    If $bOrientationMapIsArray Then
        _VectorOfMatRelease($vectorOfMatOrientationMap)
    EndIf

    _cveInputArrayRelease($iArrOrientationMap)

    If $bEdgeMapIsArray Then
        _VectorOfMatRelease($vectorOfMatEdgeMap)
    EndIf

    _cveInputArrayRelease($iArrEdgeMap)
EndFunc   ;==>_cveEdgeBoxesGetBoundingBoxesMat

Func _cveEdgeBoxesRelease($sharedPtr)
    ; CVAPI(void) cveEdgeBoxesRelease(cv::Ptr<cv::ximgproc::EdgeBoxes>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeBoxesRelease", $bSharedPtrDllType, $sharedPtr), "cveEdgeBoxesRelease", @error)
EndFunc   ;==>_cveEdgeBoxesRelease

Func _cveEdgeDrawingCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::EdgeDrawing*) cveEdgeDrawingCreate(cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::EdgeDrawing>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEdgeDrawingCreate", $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveEdgeDrawingCreate", @error)
EndFunc   ;==>_cveEdgeDrawingCreate

Func _cveEdgeDrawingDetectEdges($edgeDrawing, $src)
    ; CVAPI(void) cveEdgeDrawingDetectEdges(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_InputArray* src);

    Local $bEdgeDrawingDllType
    If VarGetType($edgeDrawing) == "DLLStruct" Then
        $bEdgeDrawingDllType = "struct*"
    Else
        $bEdgeDrawingDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectEdges", $bEdgeDrawingDllType, $edgeDrawing, $bSrcDllType, $src), "cveEdgeDrawingDetectEdges", @error)
EndFunc   ;==>_cveEdgeDrawingDetectEdges

Func _cveEdgeDrawingDetectEdgesMat($edgeDrawing, $matSrc)
    ; cveEdgeDrawingDetectEdges using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    _cveEdgeDrawingDetectEdges($edgeDrawing, $iArrSrc)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveEdgeDrawingDetectEdgesMat

Func _cveEdgeDrawingGetEdgeImage($edgeDrawing, $dst)
    ; CVAPI(void) cveEdgeDrawingGetEdgeImage(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* dst);

    Local $bEdgeDrawingDllType
    If VarGetType($edgeDrawing) == "DLLStruct" Then
        $bEdgeDrawingDllType = "struct*"
    Else
        $bEdgeDrawingDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingGetEdgeImage", $bEdgeDrawingDllType, $edgeDrawing, $bDstDllType, $dst), "cveEdgeDrawingGetEdgeImage", @error)
EndFunc   ;==>_cveEdgeDrawingGetEdgeImage

Func _cveEdgeDrawingGetEdgeImageMat($edgeDrawing, $matDst)
    ; cveEdgeDrawingGetEdgeImage using cv::Mat instead of _*Array

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

    _cveEdgeDrawingGetEdgeImage($edgeDrawing, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_cveEdgeDrawingGetEdgeImageMat

Func _cveEdgeDrawingGetGradientImage($edgeDrawing, $dst)
    ; CVAPI(void) cveEdgeDrawingGetGradientImage(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* dst);

    Local $bEdgeDrawingDllType
    If VarGetType($edgeDrawing) == "DLLStruct" Then
        $bEdgeDrawingDllType = "struct*"
    Else
        $bEdgeDrawingDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingGetGradientImage", $bEdgeDrawingDllType, $edgeDrawing, $bDstDllType, $dst), "cveEdgeDrawingGetGradientImage", @error)
EndFunc   ;==>_cveEdgeDrawingGetGradientImage

Func _cveEdgeDrawingGetGradientImageMat($edgeDrawing, $matDst)
    ; cveEdgeDrawingGetGradientImage using cv::Mat instead of _*Array

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

    _cveEdgeDrawingGetGradientImage($edgeDrawing, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_cveEdgeDrawingGetGradientImageMat

Func _cveEdgeDrawingDetectLines($edgeDrawing, $lines)
    ; CVAPI(void) cveEdgeDrawingDetectLines(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* lines);

    Local $bEdgeDrawingDllType
    If VarGetType($edgeDrawing) == "DLLStruct" Then
        $bEdgeDrawingDllType = "struct*"
    Else
        $bEdgeDrawingDllType = "ptr"
    EndIf

    Local $bLinesDllType
    If VarGetType($lines) == "DLLStruct" Then
        $bLinesDllType = "struct*"
    Else
        $bLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectLines", $bEdgeDrawingDllType, $edgeDrawing, $bLinesDllType, $lines), "cveEdgeDrawingDetectLines", @error)
EndFunc   ;==>_cveEdgeDrawingDetectLines

Func _cveEdgeDrawingDetectLinesMat($edgeDrawing, $matLines)
    ; cveEdgeDrawingDetectLines using cv::Mat instead of _*Array

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cveEdgeDrawingDetectLines($edgeDrawing, $oArrLines)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)
EndFunc   ;==>_cveEdgeDrawingDetectLinesMat

Func _cveEdgeDrawingDetectEllipses($edgeDrawing, $ellipses)
    ; CVAPI(void) cveEdgeDrawingDetectEllipses(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* ellipses);

    Local $bEdgeDrawingDllType
    If VarGetType($edgeDrawing) == "DLLStruct" Then
        $bEdgeDrawingDllType = "struct*"
    Else
        $bEdgeDrawingDllType = "ptr"
    EndIf

    Local $bEllipsesDllType
    If VarGetType($ellipses) == "DLLStruct" Then
        $bEllipsesDllType = "struct*"
    Else
        $bEllipsesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectEllipses", $bEdgeDrawingDllType, $edgeDrawing, $bEllipsesDllType, $ellipses), "cveEdgeDrawingDetectEllipses", @error)
EndFunc   ;==>_cveEdgeDrawingDetectEllipses

Func _cveEdgeDrawingDetectEllipsesMat($edgeDrawing, $matEllipses)
    ; cveEdgeDrawingDetectEllipses using cv::Mat instead of _*Array

    Local $oArrEllipses, $vectorOfMatEllipses, $iArrEllipsesSize
    Local $bEllipsesIsArray = VarGetType($matEllipses) == "Array"

    If $bEllipsesIsArray Then
        $vectorOfMatEllipses = _VectorOfMatCreate()

        $iArrEllipsesSize = UBound($matEllipses)
        For $i = 0 To $iArrEllipsesSize - 1
            _VectorOfMatPush($vectorOfMatEllipses, $matEllipses[$i])
        Next

        $oArrEllipses = _cveOutputArrayFromVectorOfMat($vectorOfMatEllipses)
    Else
        $oArrEllipses = _cveOutputArrayFromMat($matEllipses)
    EndIf

    _cveEdgeDrawingDetectEllipses($edgeDrawing, $oArrEllipses)

    If $bEllipsesIsArray Then
        _VectorOfMatRelease($vectorOfMatEllipses)
    EndIf

    _cveOutputArrayRelease($oArrEllipses)
EndFunc   ;==>_cveEdgeDrawingDetectEllipsesMat

Func _cveEdgeDrawingRelease($sharedPtr)
    ; CVAPI(void) cveEdgeDrawingRelease(cv::Ptr<cv::ximgproc::EdgeDrawing>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingRelease", $bSharedPtrDllType, $sharedPtr), "cveEdgeDrawingRelease", @error)
EndFunc   ;==>_cveEdgeDrawingRelease