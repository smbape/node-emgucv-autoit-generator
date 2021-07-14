#include-once
#include "..\..\CVEUtils.au3"

Func _cveDtFilter(ByRef $guide, ByRef $src, ByRef $dst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
    ; CVAPI(void) cveDtFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, double sigmaSpatial, double sigmaColor, int mode, int numIters);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDtFilter", "ptr", $guide, "ptr", $src, "ptr", $dst, "double", $sigmaSpatial, "double", $sigmaColor, "int", $mode, "int", $numIters), "cveDtFilter", @error)
EndFunc   ;==>_cveDtFilter

Func _cveDtFilterMat(ByRef $matGuide, ByRef $matSrc, ByRef $matDst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
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

Func _cveGuidedFilter(ByRef $guide, ByRef $src, ByRef $dst, $radius, $eps, $dDepth)
    ; CVAPI(void) cveGuidedFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, int radius, double eps, int dDepth);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGuidedFilter", "ptr", $guide, "ptr", $src, "ptr", $dst, "int", $radius, "double", $eps, "int", $dDepth), "cveGuidedFilter", @error)
EndFunc   ;==>_cveGuidedFilter

Func _cveGuidedFilterMat(ByRef $matGuide, ByRef $matSrc, ByRef $matDst, $radius, $eps, $dDepth)
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

Func _cveAmFilter(ByRef $joint, ByRef $src, ByRef $dst, $sigmaS, $sigmaR, $adjustOutliers)
    ; CVAPI(void) cveAmFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, double sigmaS, double sigmaR, bool adjustOutliers);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAmFilter", "ptr", $joint, "ptr", $src, "ptr", $dst, "double", $sigmaS, "double", $sigmaR, "boolean", $adjustOutliers), "cveAmFilter", @error)
EndFunc   ;==>_cveAmFilter

Func _cveAmFilterMat(ByRef $matJoint, ByRef $matSrc, ByRef $matDst, $sigmaS, $sigmaR, $adjustOutliers)
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

Func _cveJointBilateralFilter(ByRef $joint, ByRef $src, ByRef $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(void) cveJointBilateralFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveJointBilateralFilter", "ptr", $joint, "ptr", $src, "ptr", $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveJointBilateralFilter", @error)
EndFunc   ;==>_cveJointBilateralFilter

Func _cveJointBilateralFilterMat(ByRef $matJoint, ByRef $matSrc, ByRef $matDst, $d, $sigmaColor, $sigmaSpace, $borderType)
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

Func _cveBilateralTextureFilter(ByRef $src, ByRef $dst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
    ; CVAPI(void) cveBilateralTextureFilter(cv::_InputArray* src, cv::_OutputArray* dst, int fr, int numIter, double sigmaAlpha, double sigmaAvg);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBilateralTextureFilter", "ptr", $src, "ptr", $dst, "int", $fr, "int", $numIter, "double", $sigmaAlpha, "double", $sigmaAvg), "cveBilateralTextureFilter", @error)
EndFunc   ;==>_cveBilateralTextureFilter

Func _cveBilateralTextureFilterMat(ByRef $matSrc, ByRef $matDst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
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

Func _cveRollingGuidanceFilter(ByRef $src, ByRef $dst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
    ; CVAPI(void) cveRollingGuidanceFilter(cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int numOfIter, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRollingGuidanceFilter", "ptr", $src, "ptr", $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $numOfIter, "int", $borderType), "cveRollingGuidanceFilter", @error)
EndFunc   ;==>_cveRollingGuidanceFilter

Func _cveRollingGuidanceFilterMat(ByRef $matSrc, ByRef $matDst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
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

Func _cveFastGlobalSmootherFilter(ByRef $guide, ByRef $src, ByRef $dst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
    ; CVAPI(void) cveFastGlobalSmootherFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, double lambda, double sigmaColor, double lambdaAttenuation, int numIter);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastGlobalSmootherFilter", "ptr", $guide, "ptr", $src, "ptr", $dst, "double", $lambda, "double", $sigmaColor, "double", $lambdaAttenuation, "int", $numIter), "cveFastGlobalSmootherFilter", @error)
EndFunc   ;==>_cveFastGlobalSmootherFilter

Func _cveFastGlobalSmootherFilterMat(ByRef $matGuide, ByRef $matSrc, ByRef $matDst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
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

Func _cveL0Smooth(ByRef $src, ByRef $dst, $lambda, $kappa)
    ; CVAPI(void) cveL0Smooth(cv::_InputArray* src, cv::_OutputArray* dst, double lambda, double kappa);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveL0Smooth", "ptr", $src, "ptr", $dst, "double", $lambda, "double", $kappa), "cveL0Smooth", @error)
EndFunc   ;==>_cveL0Smooth

Func _cveL0SmoothMat(ByRef $matSrc, ByRef $matDst, $lambda, $kappa)
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

Func _cveNiBlackThreshold(ByRef $src, ByRef $dst, $maxValue, $type, $blockSize, $delta)
    ; CVAPI(void) cveNiBlackThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double maxValue, int type, int blockSize, double delta);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNiBlackThreshold", "ptr", $src, "ptr", $dst, "double", $maxValue, "int", $type, "int", $blockSize, "double", $delta), "cveNiBlackThreshold", @error)
EndFunc   ;==>_cveNiBlackThreshold

Func _cveNiBlackThresholdMat(ByRef $matSrc, ByRef $matDst, $maxValue, $type, $blockSize, $delta)
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

Func _cveCovarianceEstimation(ByRef $src, ByRef $dst, $windowRows, $windowCols)
    ; CVAPI(void) cveCovarianceEstimation(cv::_InputArray* src, cv::_OutputArray* dst, int windowRows, int windowCols);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCovarianceEstimation", "ptr", $src, "ptr", $dst, "int", $windowRows, "int", $windowCols), "cveCovarianceEstimation", @error)
EndFunc   ;==>_cveCovarianceEstimation

Func _cveCovarianceEstimationMat(ByRef $matSrc, ByRef $matDst, $windowRows, $windowCols)
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

Func _cveDTFilterCreate(ByRef $guide, $sigmaSpatial, $sigmaColor, $mode, $numIters, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::DTFilter*) cveDTFilterCreate(cv::_InputArray* guide, double sigmaSpatial, double sigmaColor, int mode, int numIters, cv::Ptr<cv::ximgproc::DTFilter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDTFilterCreate", "ptr", $guide, "double", $sigmaSpatial, "double", $sigmaColor, "int", $mode, "int", $numIters, "ptr*", $sharedPtr), "cveDTFilterCreate", @error)
EndFunc   ;==>_cveDTFilterCreate

Func _cveDTFilterCreateMat(ByRef $matGuide, $sigmaSpatial, $sigmaColor, $mode, $numIters, ByRef $sharedPtr)
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

Func _cveDTFilterFilter(ByRef $filter, ByRef $src, ByRef $dst, $dDepth)
    ; CVAPI(void) cveDTFilterFilter(cv::ximgproc::DTFilter* filter, cv::_InputArray* src, cv::_OutputArray* dst, int dDepth);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTFilterFilter", "ptr", $filter, "ptr", $src, "ptr", $dst, "int", $dDepth), "cveDTFilterFilter", @error)
EndFunc   ;==>_cveDTFilterFilter

Func _cveDTFilterFilterMat(ByRef $filter, ByRef $matSrc, ByRef $matDst, $dDepth)
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

Func _cveDTFilterRelease(ByRef $filter, ByRef $sharedPtr)
    ; CVAPI(void) cveDTFilterRelease(cv::ximgproc::DTFilter** filter, cv::Ptr<cv::ximgproc::DTFilter>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTFilterRelease", "ptr*", $filter, "ptr*", $sharedPtr), "cveDTFilterRelease", @error)
EndFunc   ;==>_cveDTFilterRelease

Func _cveRFFeatureGetterCreate(ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::RFFeatureGetter*) cveRFFeatureGetterCreate(cv::Ptr<cv::ximgproc::RFFeatureGetter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRFFeatureGetterCreate", "ptr*", $sharedPtr), "cveRFFeatureGetterCreate", @error)
EndFunc   ;==>_cveRFFeatureGetterCreate

Func _cveRFFeatureGetterRelease(ByRef $getter, ByRef $sharedPtr)
    ; CVAPI(void) cveRFFeatureGetterRelease(cv::ximgproc::RFFeatureGetter** getter, cv::Ptr<cv::ximgproc::RFFeatureGetter>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRFFeatureGetterRelease", "ptr*", $getter, "ptr*", $sharedPtr), "cveRFFeatureGetterRelease", @error)
EndFunc   ;==>_cveRFFeatureGetterRelease

Func _cveStructuredEdgeDetectionCreate($model, ByRef $howToGetFeatures, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::StructuredEdgeDetection*) cveStructuredEdgeDetectionCreate(cv::String* model, cv::ximgproc::RFFeatureGetter* howToGetFeatures, cv::Ptr<cv::ximgproc::StructuredEdgeDetection>** sharedPtr);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStructuredEdgeDetectionCreate", "ptr", $model, "ptr", $howToGetFeatures, "ptr*", $sharedPtr), "cveStructuredEdgeDetectionCreate", @error)

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveStructuredEdgeDetectionCreate

Func _cveStructuredEdgeDetectionDetectEdges(ByRef $detection, ByRef $src, ByRef $dst)
    ; CVAPI(void) cveStructuredEdgeDetectionDetectEdges(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionDetectEdges", "ptr", $detection, "ptr", $src, "ptr", $dst), "cveStructuredEdgeDetectionDetectEdges", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionDetectEdges

Func _cveStructuredEdgeDetectionDetectEdgesMat(ByRef $detection, ByRef $matSrc, ByRef $matDst)
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

Func _cveStructuredEdgeDetectionComputeOrientation(ByRef $detection, ByRef $src, ByRef $dst)
    ; CVAPI(void) cveStructuredEdgeDetectionComputeOrientation(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionComputeOrientation", "ptr", $detection, "ptr", $src, "ptr", $dst), "cveStructuredEdgeDetectionComputeOrientation", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionComputeOrientation

Func _cveStructuredEdgeDetectionComputeOrientationMat(ByRef $detection, ByRef $matSrc, ByRef $matDst)
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

Func _cveStructuredEdgeDetectionEdgesNms(ByRef $detection, ByRef $edgeImage, ByRef $orientationImage, ByRef $dst, $r, $s, $m, $isParallel)
    ; CVAPI(void) cveStructuredEdgeDetectionEdgesNms(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* edgeImage, cv::_InputArray* orientationImage, cv::_OutputArray* dst, int r, int s, float m, bool isParallel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionEdgesNms", "ptr", $detection, "ptr", $edgeImage, "ptr", $orientationImage, "ptr", $dst, "int", $r, "int", $s, "float", $m, "boolean", $isParallel), "cveStructuredEdgeDetectionEdgesNms", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionEdgesNms

Func _cveStructuredEdgeDetectionEdgesNmsMat(ByRef $detection, ByRef $matEdgeImage, ByRef $matOrientationImage, ByRef $matDst, $r, $s, $m, $isParallel)
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

Func _cveStructuredEdgeDetectionRelease(ByRef $detection, ByRef $sharedPtr)
    ; CVAPI(void) cveStructuredEdgeDetectionRelease(cv::ximgproc::StructuredEdgeDetection** detection, cv::Ptr<cv::ximgproc::StructuredEdgeDetection>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionRelease", "ptr*", $detection, "ptr*", $sharedPtr), "cveStructuredEdgeDetectionRelease", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionRelease

Func _cveSuperpixelSEEDSCreate($imageWidth, $imageHeight, $imageChannels, $numSuperpixels, $numLevels, $prior, $histogramBins, $doubleStep, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelSEEDS*) cveSuperpixelSEEDSCreate(int imageWidth, int imageHeight, int imageChannels, int numSuperpixels, int numLevels, int prior, int histogramBins, bool doubleStep, cv::Ptr<cv::ximgproc::SuperpixelSEEDS>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelSEEDSCreate", "int", $imageWidth, "int", $imageHeight, "int", $imageChannels, "int", $numSuperpixels, "int", $numLevels, "int", $prior, "int", $histogramBins, "boolean", $doubleStep, "ptr*", $sharedPtr), "cveSuperpixelSEEDSCreate", @error)
EndFunc   ;==>_cveSuperpixelSEEDSCreate

Func _cveSuperpixelSEEDSGetNumberOfSuperpixels(ByRef $seeds)
    ; CVAPI(int) cveSuperpixelSEEDSGetNumberOfSuperpixels(cv::ximgproc::SuperpixelSEEDS* seeds);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelSEEDSGetNumberOfSuperpixels", "ptr", $seeds), "cveSuperpixelSEEDSGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetNumberOfSuperpixels

Func _cveSuperpixelSEEDSGetLabels(ByRef $seeds, ByRef $labelsOut)
    ; CVAPI(void) cveSuperpixelSEEDSGetLabels(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_OutputArray* labelsOut);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSGetLabels", "ptr", $seeds, "ptr", $labelsOut), "cveSuperpixelSEEDSGetLabels", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabels

Func _cveSuperpixelSEEDSGetLabelsMat(ByRef $seeds, ByRef $matLabelsOut)
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

Func _cveSuperpixelSEEDSGetLabelContourMask(ByRef $seeds, ByRef $image, $thickLine)
    ; CVAPI(void) cveSuperpixelSEEDSGetLabelContourMask(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_OutputArray* image, bool thickLine);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSGetLabelContourMask", "ptr", $seeds, "ptr", $image, "boolean", $thickLine), "cveSuperpixelSEEDSGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelContourMask

Func _cveSuperpixelSEEDSGetLabelContourMaskMat(ByRef $seeds, ByRef $matImage, $thickLine)
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

Func _cveSuperpixelSEEDSIterate(ByRef $seeds, ByRef $img, $numIterations)
    ; CVAPI(void) cveSuperpixelSEEDSIterate(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_InputArray* img, int numIterations);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSIterate", "ptr", $seeds, "ptr", $img, "int", $numIterations), "cveSuperpixelSEEDSIterate", @error)
EndFunc   ;==>_cveSuperpixelSEEDSIterate

Func _cveSuperpixelSEEDSIterateMat(ByRef $seeds, ByRef $matImg, $numIterations)
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

Func _cveSuperpixelSEEDSRelease(ByRef $seeds, ByRef $sharedPtr)
    ; CVAPI(void) cveSuperpixelSEEDSRelease(cv::ximgproc::SuperpixelSEEDS** seeds, cv::Ptr<cv::ximgproc::SuperpixelSEEDS>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSRelease", "ptr*", $seeds, "ptr*", $sharedPtr), "cveSuperpixelSEEDSRelease", @error)
EndFunc   ;==>_cveSuperpixelSEEDSRelease

Func _cveSuperpixelLSCCreate(ByRef $image, $regionSize, $ratio, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelLSC*) cveSuperpixelLSCCreate(cv::_InputArray* image, int regionSize, float ratio, cv::Ptr<cv::ximgproc::SuperpixelLSC>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelLSCCreate", "ptr", $image, "int", $regionSize, "float", $ratio, "ptr*", $sharedPtr), "cveSuperpixelLSCCreate", @error)
EndFunc   ;==>_cveSuperpixelLSCCreate

Func _cveSuperpixelLSCCreateMat(ByRef $matImage, $regionSize, $ratio, ByRef $sharedPtr)
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

Func _cveSuperpixelLSCGetNumberOfSuperpixels(ByRef $lsc)
    ; CVAPI(int) cveSuperpixelLSCGetNumberOfSuperpixels(cv::ximgproc::SuperpixelLSC* lsc);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelLSCGetNumberOfSuperpixels", "ptr", $lsc), "cveSuperpixelLSCGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelLSCGetNumberOfSuperpixels

Func _cveSuperpixelLSCIterate(ByRef $lsc, $numIterations)
    ; CVAPI(void) cveSuperpixelLSCIterate(cv::ximgproc::SuperpixelLSC* lsc, int numIterations);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCIterate", "ptr", $lsc, "int", $numIterations), "cveSuperpixelLSCIterate", @error)
EndFunc   ;==>_cveSuperpixelLSCIterate

Func _cveSuperpixelLSCGetLabels(ByRef $lsc, ByRef $labelsOut)
    ; CVAPI(void) cveSuperpixelLSCGetLabels(cv::ximgproc::SuperpixelLSC* lsc, cv::_OutputArray* labelsOut);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCGetLabels", "ptr", $lsc, "ptr", $labelsOut), "cveSuperpixelLSCGetLabels", @error)
EndFunc   ;==>_cveSuperpixelLSCGetLabels

Func _cveSuperpixelLSCGetLabelsMat(ByRef $lsc, ByRef $matLabelsOut)
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

Func _cveSuperpixelLSCGetLabelContourMask(ByRef $lsc, ByRef $image, $thickLine)
    ; CVAPI(void) cveSuperpixelLSCGetLabelContourMask(cv::ximgproc::SuperpixelLSC* lsc, cv::_OutputArray* image, bool thickLine);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCGetLabelContourMask", "ptr", $lsc, "ptr", $image, "boolean", $thickLine), "cveSuperpixelLSCGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelLSCGetLabelContourMask

Func _cveSuperpixelLSCGetLabelContourMaskMat(ByRef $lsc, ByRef $matImage, $thickLine)
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

Func _cveSuperpixelLSCEnforceLabelConnectivity(ByRef $lsc, $minElementSize)
    ; CVAPI(void) cveSuperpixelLSCEnforceLabelConnectivity(cv::ximgproc::SuperpixelLSC* lsc, int minElementSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCEnforceLabelConnectivity", "ptr", $lsc, "int", $minElementSize), "cveSuperpixelLSCEnforceLabelConnectivity", @error)
EndFunc   ;==>_cveSuperpixelLSCEnforceLabelConnectivity

Func _cveSuperpixelLSCRelease(ByRef $lsc, ByRef $sharedPtr)
    ; CVAPI(void) cveSuperpixelLSCRelease(cv::ximgproc::SuperpixelLSC** lsc, cv::Ptr<cv::ximgproc::SuperpixelLSC>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCRelease", "ptr*", $lsc, "ptr*", $sharedPtr), "cveSuperpixelLSCRelease", @error)
EndFunc   ;==>_cveSuperpixelLSCRelease

Func _cveSuperpixelSLICCreate(ByRef $image, $algorithm, $regionSize, $ruler, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelSLIC*) cveSuperpixelSLICCreate(cv::_InputArray* image, int algorithm, int regionSize, float ruler, cv::Ptr<cv::ximgproc::SuperpixelSLIC>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelSLICCreate", "ptr", $image, "int", $algorithm, "int", $regionSize, "float", $ruler, "ptr*", $sharedPtr), "cveSuperpixelSLICCreate", @error)
EndFunc   ;==>_cveSuperpixelSLICCreate

Func _cveSuperpixelSLICCreateMat(ByRef $matImage, $algorithm, $regionSize, $ruler, ByRef $sharedPtr)
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

Func _cveSuperpixelSLICGetNumberOfSuperpixels(ByRef $slic)
    ; CVAPI(int) cveSuperpixelSLICGetNumberOfSuperpixels(cv::ximgproc::SuperpixelSLIC* slic);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelSLICGetNumberOfSuperpixels", "ptr", $slic), "cveSuperpixelSLICGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelSLICGetNumberOfSuperpixels

Func _cveSuperpixelSLICIterate(ByRef $slic, $numIterations)
    ; CVAPI(void) cveSuperpixelSLICIterate(cv::ximgproc::SuperpixelSLIC* slic, int numIterations);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICIterate", "ptr", $slic, "int", $numIterations), "cveSuperpixelSLICIterate", @error)
EndFunc   ;==>_cveSuperpixelSLICIterate

Func _cveSuperpixelSLICGetLabels(ByRef $slic, ByRef $labelsOut)
    ; CVAPI(void) cveSuperpixelSLICGetLabels(cv::ximgproc::SuperpixelSLIC* slic, cv::_OutputArray* labelsOut);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICGetLabels", "ptr", $slic, "ptr", $labelsOut), "cveSuperpixelSLICGetLabels", @error)
EndFunc   ;==>_cveSuperpixelSLICGetLabels

Func _cveSuperpixelSLICGetLabelsMat(ByRef $slic, ByRef $matLabelsOut)
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

Func _cveSuperpixelSLICGetLabelContourMask(ByRef $slic, ByRef $image, $thickLine)
    ; CVAPI(void) cveSuperpixelSLICGetLabelContourMask(cv::ximgproc::SuperpixelSLIC* slic, cv::_OutputArray* image, bool thickLine);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICGetLabelContourMask", "ptr", $slic, "ptr", $image, "boolean", $thickLine), "cveSuperpixelSLICGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelSLICGetLabelContourMask

Func _cveSuperpixelSLICGetLabelContourMaskMat(ByRef $slic, ByRef $matImage, $thickLine)
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

Func _cveSuperpixelSLICEnforceLabelConnectivity(ByRef $slic, $minElementSize)
    ; CVAPI(void) cveSuperpixelSLICEnforceLabelConnectivity(cv::ximgproc::SuperpixelSLIC* slic, int minElementSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICEnforceLabelConnectivity", "ptr", $slic, "int", $minElementSize), "cveSuperpixelSLICEnforceLabelConnectivity", @error)
EndFunc   ;==>_cveSuperpixelSLICEnforceLabelConnectivity

Func _cveSuperpixelSLICRelease(ByRef $slic, ByRef $sharedPtr)
    ; CVAPI(void) cveSuperpixelSLICRelease(cv::ximgproc::SuperpixelSLIC** slic, cv::Ptr<cv::ximgproc::SuperpixelSLIC>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICRelease", "ptr*", $slic, "ptr*", $sharedPtr), "cveSuperpixelSLICRelease", @error)
EndFunc   ;==>_cveSuperpixelSLICRelease

Func _cveGraphSegmentationCreate($sigma, $k, $minSize, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::segmentation::GraphSegmentation*) cveGraphSegmentationCreate(double sigma, float k, int minSize, cv::Ptr<cv::ximgproc::segmentation::GraphSegmentation>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGraphSegmentationCreate", "double", $sigma, "float", $k, "int", $minSize, "ptr*", $sharedPtr), "cveGraphSegmentationCreate", @error)
EndFunc   ;==>_cveGraphSegmentationCreate

Func _cveGraphSegmentationProcessImage(ByRef $segmentation, ByRef $src, ByRef $dst)
    ; CVAPI(void) cveGraphSegmentationProcessImage(cv::ximgproc::segmentation::GraphSegmentation* segmentation, cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphSegmentationProcessImage", "ptr", $segmentation, "ptr", $src, "ptr", $dst), "cveGraphSegmentationProcessImage", @error)
EndFunc   ;==>_cveGraphSegmentationProcessImage

Func _cveGraphSegmentationProcessImageMat(ByRef $segmentation, ByRef $matSrc, ByRef $matDst)
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

Func _cveGraphSegmentationRelease(ByRef $segmentation, ByRef $sharedPtr)
    ; CVAPI(void) cveGraphSegmentationRelease(cv::ximgproc::segmentation::GraphSegmentation** segmentation, cv::Ptr<cv::ximgproc::segmentation::GraphSegmentation>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphSegmentationRelease", "ptr*", $segmentation, "ptr*", $sharedPtr), "cveGraphSegmentationRelease", @error)
EndFunc   ;==>_cveGraphSegmentationRelease

Func _cveWeightedMedianFilter(ByRef $joint, ByRef $src, ByRef $dst, $r, $sigma, $weightType, ByRef $mask)
    ; CVAPI(void) cveWeightedMedianFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, int r, double sigma, cv::ximgproc::WMFWeightType weightType, cv::Mat* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeightedMedianFilter", "ptr", $joint, "ptr", $src, "ptr", $dst, "int", $r, "double", $sigma, "cv::ximgproc::WMFWeightType", $weightType, "ptr", $mask), "cveWeightedMedianFilter", @error)
EndFunc   ;==>_cveWeightedMedianFilter

Func _cveWeightedMedianFilterMat(ByRef $matJoint, ByRef $matSrc, ByRef $matDst, $r, $sigma, $weightType, ByRef $mask)
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

Func _cveSelectiveSearchSegmentationCreate(ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::segmentation::SelectiveSearchSegmentation*) cveSelectiveSearchSegmentationCreate(cv::Ptr<cv::ximgproc::segmentation::SelectiveSearchSegmentation>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSelectiveSearchSegmentationCreate", "ptr*", $sharedPtr), "cveSelectiveSearchSegmentationCreate", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationCreate

Func _cveSelectiveSearchSegmentationSetBaseImage(ByRef $segmentation, ByRef $image)
    ; CVAPI(void) cveSelectiveSearchSegmentationSetBaseImage(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, cv::_InputArray* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSetBaseImage", "ptr", $segmentation, "ptr", $image), "cveSelectiveSearchSegmentationSetBaseImage", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSetBaseImage

Func _cveSelectiveSearchSegmentationSetBaseImageMat(ByRef $segmentation, ByRef $matImage)
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

Func _cveSelectiveSearchSegmentationSwitchToSingleStrategy(ByRef $segmentation, $k, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSingleStrategy(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int k, float sigma);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSingleStrategy", "ptr", $segmentation, "int", $k, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSingleStrategy", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSingleStrategy

Func _cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast(ByRef $segmentation, $baseK, $incK, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int baseK, int incK, float sigma);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast", "ptr", $segmentation, "int", $baseK, "int", $incK, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast

Func _cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality(ByRef $segmentation, $baseK, $incK, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int baseK, int incK, float sigma);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality", "ptr", $segmentation, "int", $baseK, "int", $incK, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality

Func _cveSelectiveSearchSegmentationAddImage(ByRef $segmentation, ByRef $img)
    ; CVAPI(void) cveSelectiveSearchSegmentationAddImage(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, cv::_InputArray* img);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationAddImage", "ptr", $segmentation, "ptr", $img), "cveSelectiveSearchSegmentationAddImage", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationAddImage

Func _cveSelectiveSearchSegmentationAddImageMat(ByRef $segmentation, ByRef $matImg)
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

Func _cveSelectiveSearchSegmentationProcess(ByRef $segmentation, ByRef $rects)
    ; CVAPI(void) cveSelectiveSearchSegmentationProcess(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, std::vector<cv::Rect>* rects);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationProcess", "ptr", $segmentation, "ptr", $vecRects), "cveSelectiveSearchSegmentationProcess", @error)

    If $bRectsIsArray Then
        _VectorOfRectRelease($vecRects)
    EndIf
EndFunc   ;==>_cveSelectiveSearchSegmentationProcess

Func _cveSelectiveSearchSegmentationRelease(ByRef $segmentation, ByRef $sharedPtr)
    ; CVAPI(void) cveSelectiveSearchSegmentationRelease(cv::ximgproc::segmentation::SelectiveSearchSegmentation** segmentation, cv::Ptr<cv::ximgproc::segmentation::SelectiveSearchSegmentation>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationRelease", "ptr*", $segmentation, "ptr*", $sharedPtr), "cveSelectiveSearchSegmentationRelease", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationRelease

Func _cveGradientPaillouY(ByRef $op, ByRef $dst, $alpha, $omega)
    ; CVAPI(void) cveGradientPaillouY(cv::_InputArray* op, cv::_OutputArray* dst, double alpha, double omega);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientPaillouY", "ptr", $op, "ptr", $dst, "double", $alpha, "double", $omega), "cveGradientPaillouY", @error)
EndFunc   ;==>_cveGradientPaillouY

Func _cveGradientPaillouYMat(ByRef $matOp, ByRef $matDst, $alpha, $omega)
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

Func _cveGradientPaillouX(ByRef $op, ByRef $dst, $alpha, $omega)
    ; CVAPI(void) cveGradientPaillouX(cv::_InputArray* op, cv::_OutputArray* dst, double alpha, double omega);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientPaillouX", "ptr", $op, "ptr", $dst, "double", $alpha, "double", $omega), "cveGradientPaillouX", @error)
EndFunc   ;==>_cveGradientPaillouX

Func _cveGradientPaillouXMat(ByRef $matOp, ByRef $matDst, $alpha, $omega)
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

Func _cveGradientDericheY(ByRef $op, ByRef $dst, $alphaDerive, $alphaMean)
    ; CVAPI(void) cveGradientDericheY(cv::_InputArray* op, cv::_OutputArray* dst, double alphaDerive, double alphaMean);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientDericheY", "ptr", $op, "ptr", $dst, "double", $alphaDerive, "double", $alphaMean), "cveGradientDericheY", @error)
EndFunc   ;==>_cveGradientDericheY

Func _cveGradientDericheYMat(ByRef $matOp, ByRef $matDst, $alphaDerive, $alphaMean)
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

Func _cveGradientDericheX(ByRef $op, ByRef $dst, $alphaDerive, $alphaMean)
    ; CVAPI(void) cveGradientDericheX(cv::_InputArray* op, cv::_OutputArray* dst, double alphaDerive, double alphaMean);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientDericheX", "ptr", $op, "ptr", $dst, "double", $alphaDerive, "double", $alphaMean), "cveGradientDericheX", @error)
EndFunc   ;==>_cveGradientDericheX

Func _cveGradientDericheXMat(ByRef $matOp, ByRef $matDst, $alphaDerive, $alphaMean)
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

Func _cveThinning(ByRef $src, ByRef $dst, $thinningType)
    ; CVAPI(void) cveThinning(cv::_InputArray* src, cv::_OutputArray* dst, int thinningType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveThinning", "ptr", $src, "ptr", $dst, "int", $thinningType), "cveThinning", @error)
EndFunc   ;==>_cveThinning

Func _cveThinningMat(ByRef $matSrc, ByRef $matDst, $thinningType)
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

Func _cveAnisotropicDiffusion(ByRef $src, ByRef $dst, $alpha, $K, $niters)
    ; CVAPI(void) cveAnisotropicDiffusion(cv::_InputArray* src, cv::_OutputArray* dst, float alpha, float K, int niters);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAnisotropicDiffusion", "ptr", $src, "ptr", $dst, "float", $alpha, "float", $K, "int", $niters), "cveAnisotropicDiffusion", @error)
EndFunc   ;==>_cveAnisotropicDiffusion

Func _cveAnisotropicDiffusionMat(ByRef $matSrc, ByRef $matDst, $alpha, $K, $niters)
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

Func _cveFastLineDetectorCreate($length_threshold, $distance_threshold, $canny_th1, $canny_th2, $canny_aperture_size, $do_merge, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::FastLineDetector*) cveFastLineDetectorCreate(int length_threshold, float distance_threshold, double canny_th1, double canny_th2, int canny_aperture_size, bool do_merge, cv::Ptr<cv::ximgproc::FastLineDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFastLineDetectorCreate", "int", $length_threshold, "float", $distance_threshold, "double", $canny_th1, "double", $canny_th2, "int", $canny_aperture_size, "boolean", $do_merge, "ptr*", $sharedPtr), "cveFastLineDetectorCreate", @error)
EndFunc   ;==>_cveFastLineDetectorCreate

Func _cveFastLineDetectorDetect(ByRef $fld, ByRef $image, ByRef $lines)
    ; CVAPI(void) cveFastLineDetectorDetect(cv::ximgproc::FastLineDetector* fld, cv::_InputArray* image, cv::_OutputArray* lines);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorDetect", "ptr", $fld, "ptr", $image, "ptr", $lines), "cveFastLineDetectorDetect", @error)
EndFunc   ;==>_cveFastLineDetectorDetect

Func _cveFastLineDetectorDetectMat(ByRef $fld, ByRef $matImage, ByRef $matLines)
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

Func _cveFastLineDetectorDrawSegments(ByRef $fld, ByRef $image, ByRef $lines, $draw_arrow)
    ; CVAPI(void) cveFastLineDetectorDrawSegments(cv::ximgproc::FastLineDetector* fld, cv::_InputOutputArray* image, cv::_InputArray* lines, bool draw_arrow);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorDrawSegments", "ptr", $fld, "ptr", $image, "ptr", $lines, "boolean", $draw_arrow), "cveFastLineDetectorDrawSegments", @error)
EndFunc   ;==>_cveFastLineDetectorDrawSegments

Func _cveFastLineDetectorDrawSegmentsMat(ByRef $fld, ByRef $matImage, ByRef $matLines, $draw_arrow)
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

Func _cveFastLineDetectorRelease(ByRef $fld)
    ; CVAPI(void) cveFastLineDetectorRelease(cv::Ptr<cv::ximgproc::FastLineDetector>** fld);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorRelease", "ptr*", $fld), "cveFastLineDetectorRelease", @error)
EndFunc   ;==>_cveFastLineDetectorRelease

Func _cveBrightEdges(ByRef $original, ByRef $edgeview, $contrast, $shortrange, $longrange)
    ; CVAPI(void) cveBrightEdges(cv::Mat* original, cv::Mat* edgeview, int contrast, int shortrange, int longrange);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBrightEdges", "ptr", $original, "ptr", $edgeview, "int", $contrast, "int", $shortrange, "int", $longrange), "cveBrightEdges", @error)
EndFunc   ;==>_cveBrightEdges

Func _cveCreateDisparityWLSFilter(ByRef $matcherLeft, ByRef $disparityFilter, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::DisparityWLSFilter*) cveCreateDisparityWLSFilter(cv::StereoMatcher* matcherLeft, cv::ximgproc::DisparityFilter** disparityFilter, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateDisparityWLSFilter", "ptr", $matcherLeft, "ptr*", $disparityFilter, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveCreateDisparityWLSFilter", @error)
EndFunc   ;==>_cveCreateDisparityWLSFilter

Func _cveCreateRightMatcher(ByRef $matcherLeft, ByRef $sharedPtr)
    ; CVAPI(cv::StereoMatcher*) cveCreateRightMatcher(cv::StereoMatcher* matcherLeft, cv::Ptr<cv::StereoMatcher>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateRightMatcher", "ptr", $matcherLeft, "ptr*", $sharedPtr), "cveCreateRightMatcher", @error)
EndFunc   ;==>_cveCreateRightMatcher

Func _cveCreateDisparityWLSFilterGeneric($use_confidence, ByRef $disparityFilter, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::DisparityWLSFilter*) cveCreateDisparityWLSFilterGeneric(bool use_confidence, cv::ximgproc::DisparityFilter** disparityFilter, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateDisparityWLSFilterGeneric", "boolean", $use_confidence, "ptr*", $disparityFilter, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveCreateDisparityWLSFilterGeneric", @error)
EndFunc   ;==>_cveCreateDisparityWLSFilterGeneric

Func _cveDisparityWLSFilterRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveDisparityWLSFilterRelease(cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDisparityWLSFilterRelease", "ptr*", $sharedPtr), "cveDisparityWLSFilterRelease", @error)
EndFunc   ;==>_cveDisparityWLSFilterRelease

Func _cveDisparityFilterFilter(ByRef $disparityFilter, ByRef $disparity_map_left, ByRef $left_view, ByRef $filtered_disparity_map, ByRef $disparity_map_right, ByRef $ROI, ByRef $right_view)
    ; CVAPI(void) cveDisparityFilterFilter(cv::ximgproc::DisparityFilter* disparityFilter, cv::_InputArray* disparity_map_left, cv::_InputArray* left_view, cv::_OutputArray* filtered_disparity_map, cv::_InputArray* disparity_map_right, CvRect* ROI, cv::_InputArray* right_view);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDisparityFilterFilter", "ptr", $disparityFilter, "ptr", $disparity_map_left, "ptr", $left_view, "ptr", $filtered_disparity_map, "ptr", $disparity_map_right, "struct*", $ROI, "ptr", $right_view), "cveDisparityFilterFilter", @error)
EndFunc   ;==>_cveDisparityFilterFilter

Func _cveDisparityFilterFilterMat(ByRef $disparityFilter, ByRef $matDisparity_map_left, ByRef $matLeft_view, ByRef $matFiltered_disparity_map, ByRef $matDisparity_map_right, ByRef $ROI, ByRef $matRight_view)
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

Func _cveRidgeDetectionFilterCreate($ddepth, $dx, $dy, $ksize, $outDtype, $scale, $delta, $borderType, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::RidgeDetectionFilter*) cveRidgeDetectionFilterCreate(int ddepth, int dx, int dy, int ksize, int outDtype, double scale, double delta, int borderType, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::RidgeDetectionFilter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRidgeDetectionFilterCreate", "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "int", $outDtype, "double", $scale, "double", $delta, "int", $borderType, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveRidgeDetectionFilterCreate", @error)
EndFunc   ;==>_cveRidgeDetectionFilterCreate

Func _cveRidgeDetectionFilterRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveRidgeDetectionFilterRelease(cv::Ptr<cv::ximgproc::RidgeDetectionFilter>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRidgeDetectionFilterRelease", "ptr*", $sharedPtr), "cveRidgeDetectionFilterRelease", @error)
EndFunc   ;==>_cveRidgeDetectionFilterRelease

Func _cveRidgeDetectionFilterGetRidgeFilteredImage(ByRef $ridgeDetection, ByRef $img, ByRef $out)
    ; CVAPI(void) cveRidgeDetectionFilterGetRidgeFilteredImage(cv::ximgproc::RidgeDetectionFilter* ridgeDetection, cv::_InputArray* img, cv::_OutputArray* out);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRidgeDetectionFilterGetRidgeFilteredImage", "ptr", $ridgeDetection, "ptr", $img, "ptr", $out), "cveRidgeDetectionFilterGetRidgeFilteredImage", @error)
EndFunc   ;==>_cveRidgeDetectionFilterGetRidgeFilteredImage

Func _cveRidgeDetectionFilterGetRidgeFilteredImageMat(ByRef $ridgeDetection, ByRef $matImg, ByRef $matOut)
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

Func _cveEdgeBoxesCreate($alpha, $beta, $eta, $minScore, $maxBoxes, $edgeMinMag, $edgeMergeThr, $clusterMinMag, $maxAspectRatio, $minBoxArea, $gamma, $kappa, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::EdgeBoxes*) cveEdgeBoxesCreate(float alpha, float beta, float eta, float minScore, int maxBoxes, float edgeMinMag, float edgeMergeThr, float clusterMinMag, float maxAspectRatio, float minBoxArea, float gamma, float kappa, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::EdgeBoxes>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEdgeBoxesCreate", "float", $alpha, "float", $beta, "float", $eta, "float", $minScore, "int", $maxBoxes, "float", $edgeMinMag, "float", $edgeMergeThr, "float", $clusterMinMag, "float", $maxAspectRatio, "float", $minBoxArea, "float", $gamma, "float", $kappa, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveEdgeBoxesCreate", @error)
EndFunc   ;==>_cveEdgeBoxesCreate

Func _cveEdgeBoxesGetBoundingBoxes(ByRef $edgeBoxes, ByRef $edgeMap, ByRef $orientationMap, ByRef $boxes)
    ; CVAPI(void) cveEdgeBoxesGetBoundingBoxes(cv::ximgproc::EdgeBoxes* edgeBoxes, cv::_InputArray* edgeMap, cv::_InputArray* orientationMap, std::vector<cv::Rect>* boxes);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeBoxesGetBoundingBoxes", "ptr", $edgeBoxes, "ptr", $edgeMap, "ptr", $orientationMap, "ptr", $vecBoxes), "cveEdgeBoxesGetBoundingBoxes", @error)

    If $bBoxesIsArray Then
        _VectorOfRectRelease($vecBoxes)
    EndIf
EndFunc   ;==>_cveEdgeBoxesGetBoundingBoxes

Func _cveEdgeBoxesGetBoundingBoxesMat(ByRef $edgeBoxes, ByRef $matEdgeMap, ByRef $matOrientationMap, ByRef $boxes)
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

Func _cveEdgeBoxesRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveEdgeBoxesRelease(cv::Ptr<cv::ximgproc::EdgeBoxes>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeBoxesRelease", "ptr*", $sharedPtr), "cveEdgeBoxesRelease", @error)
EndFunc   ;==>_cveEdgeBoxesRelease

Func _cveEdgeDrawingCreate(ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::ximgproc::EdgeDrawing*) cveEdgeDrawingCreate(cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::EdgeDrawing>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEdgeDrawingCreate", "ptr*", $algorithm, "ptr*", $sharedPtr), "cveEdgeDrawingCreate", @error)
EndFunc   ;==>_cveEdgeDrawingCreate

Func _cveEdgeDrawingDetectEdges(ByRef $edgeDrawing, ByRef $src)
    ; CVAPI(void) cveEdgeDrawingDetectEdges(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_InputArray* src);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectEdges", "ptr", $edgeDrawing, "ptr", $src), "cveEdgeDrawingDetectEdges", @error)
EndFunc   ;==>_cveEdgeDrawingDetectEdges

Func _cveEdgeDrawingDetectEdgesMat(ByRef $edgeDrawing, ByRef $matSrc)
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

Func _cveEdgeDrawingGetEdgeImage(ByRef $edgeDrawing, ByRef $dst)
    ; CVAPI(void) cveEdgeDrawingGetEdgeImage(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingGetEdgeImage", "ptr", $edgeDrawing, "ptr", $dst), "cveEdgeDrawingGetEdgeImage", @error)
EndFunc   ;==>_cveEdgeDrawingGetEdgeImage

Func _cveEdgeDrawingGetEdgeImageMat(ByRef $edgeDrawing, ByRef $matDst)
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

Func _cveEdgeDrawingGetGradientImage(ByRef $edgeDrawing, ByRef $dst)
    ; CVAPI(void) cveEdgeDrawingGetGradientImage(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingGetGradientImage", "ptr", $edgeDrawing, "ptr", $dst), "cveEdgeDrawingGetGradientImage", @error)
EndFunc   ;==>_cveEdgeDrawingGetGradientImage

Func _cveEdgeDrawingGetGradientImageMat(ByRef $edgeDrawing, ByRef $matDst)
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

Func _cveEdgeDrawingDetectLines(ByRef $edgeDrawing, ByRef $lines)
    ; CVAPI(void) cveEdgeDrawingDetectLines(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* lines);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectLines", "ptr", $edgeDrawing, "ptr", $lines), "cveEdgeDrawingDetectLines", @error)
EndFunc   ;==>_cveEdgeDrawingDetectLines

Func _cveEdgeDrawingDetectLinesMat(ByRef $edgeDrawing, ByRef $matLines)
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

Func _cveEdgeDrawingDetectEllipses(ByRef $edgeDrawing, ByRef $ellipses)
    ; CVAPI(void) cveEdgeDrawingDetectEllipses(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* ellipses);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectEllipses", "ptr", $edgeDrawing, "ptr", $ellipses), "cveEdgeDrawingDetectEllipses", @error)
EndFunc   ;==>_cveEdgeDrawingDetectEllipses

Func _cveEdgeDrawingDetectEllipsesMat(ByRef $edgeDrawing, ByRef $matEllipses)
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

Func _cveEdgeDrawingRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveEdgeDrawingRelease(cv::Ptr<cv::ximgproc::EdgeDrawing>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingRelease", "ptr*", $sharedPtr), "cveEdgeDrawingRelease", @error)
EndFunc   ;==>_cveEdgeDrawingRelease