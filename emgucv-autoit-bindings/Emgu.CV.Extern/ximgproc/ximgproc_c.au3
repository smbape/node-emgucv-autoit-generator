#include-once
#include "..\..\CVEUtils.au3"

Func _cveDtFilter($guide, $src, $dst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
    ; CVAPI(void) cveDtFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, double sigmaSpatial, double sigmaColor, int mode, int numIters);

    Local $sGuideDllType
    If IsDllStruct($guide) Then
        $sGuideDllType = "struct*"
    Else
        $sGuideDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDtFilter", $sGuideDllType, $guide, $sSrcDllType, $src, $sDstDllType, $dst, "double", $sigmaSpatial, "double", $sigmaColor, "int", $mode, "int", $numIters), "cveDtFilter", @error)
EndFunc   ;==>_cveDtFilter

Func _cveDtFilterTyped($typeOfGuide, $guide, $typeOfSrc, $src, $typeOfDst, $dst, $sigmaSpatial, $sigmaColor, $mode, $numIters)

    Local $iArrGuide, $vectorGuide, $iArrGuideSize
    Local $bGuideIsArray = IsArray($guide)
    Local $bGuideCreate = IsDllStruct($guide) And $typeOfGuide == "Scalar"

    If $typeOfGuide == Default Then
        $iArrGuide = $guide
    ElseIf $bGuideIsArray Then
        $vectorGuide = Call("_VectorOf" & $typeOfGuide & "Create")

        $iArrGuideSize = UBound($guide)
        For $i = 0 To $iArrGuideSize - 1
            Call("_VectorOf" & $typeOfGuide & "Push", $vectorGuide, $guide[$i])
        Next

        $iArrGuide = Call("_cveInputArrayFromVectorOf" & $typeOfGuide, $vectorGuide)
    Else
        If $bGuideCreate Then
            $guide = Call("_cve" & $typeOfGuide & "Create", $guide)
        EndIf
        $iArrGuide = Call("_cveInputArrayFrom" & $typeOfGuide, $guide)
    EndIf

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveDtFilter($iArrGuide, $iArrSrc, $oArrDst, $sigmaSpatial, $sigmaColor, $mode, $numIters)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    If $bGuideIsArray Then
        Call("_VectorOf" & $typeOfGuide & "Release", $vectorGuide)
    EndIf

    If $typeOfGuide <> Default Then
        _cveInputArrayRelease($iArrGuide)
        If $bGuideCreate Then
            Call("_cve" & $typeOfGuide & "Release", $guide)
        EndIf
    EndIf
EndFunc   ;==>_cveDtFilterTyped

Func _cveDtFilterMat($guide, $src, $dst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
    ; cveDtFilter using cv::Mat instead of _*Array
    _cveDtFilterTyped("Mat", $guide, "Mat", $src, "Mat", $dst, $sigmaSpatial, $sigmaColor, $mode, $numIters)
EndFunc   ;==>_cveDtFilterMat

Func _cveGuidedFilter($guide, $src, $dst, $radius, $eps, $dDepth = -1)
    ; CVAPI(void) cveGuidedFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, int radius, double eps, int dDepth);

    Local $sGuideDllType
    If IsDllStruct($guide) Then
        $sGuideDllType = "struct*"
    Else
        $sGuideDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGuidedFilter", $sGuideDllType, $guide, $sSrcDllType, $src, $sDstDllType, $dst, "int", $radius, "double", $eps, "int", $dDepth), "cveGuidedFilter", @error)
EndFunc   ;==>_cveGuidedFilter

Func _cveGuidedFilterTyped($typeOfGuide, $guide, $typeOfSrc, $src, $typeOfDst, $dst, $radius, $eps, $dDepth = -1)

    Local $iArrGuide, $vectorGuide, $iArrGuideSize
    Local $bGuideIsArray = IsArray($guide)
    Local $bGuideCreate = IsDllStruct($guide) And $typeOfGuide == "Scalar"

    If $typeOfGuide == Default Then
        $iArrGuide = $guide
    ElseIf $bGuideIsArray Then
        $vectorGuide = Call("_VectorOf" & $typeOfGuide & "Create")

        $iArrGuideSize = UBound($guide)
        For $i = 0 To $iArrGuideSize - 1
            Call("_VectorOf" & $typeOfGuide & "Push", $vectorGuide, $guide[$i])
        Next

        $iArrGuide = Call("_cveInputArrayFromVectorOf" & $typeOfGuide, $vectorGuide)
    Else
        If $bGuideCreate Then
            $guide = Call("_cve" & $typeOfGuide & "Create", $guide)
        EndIf
        $iArrGuide = Call("_cveInputArrayFrom" & $typeOfGuide, $guide)
    EndIf

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveGuidedFilter($iArrGuide, $iArrSrc, $oArrDst, $radius, $eps, $dDepth)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    If $bGuideIsArray Then
        Call("_VectorOf" & $typeOfGuide & "Release", $vectorGuide)
    EndIf

    If $typeOfGuide <> Default Then
        _cveInputArrayRelease($iArrGuide)
        If $bGuideCreate Then
            Call("_cve" & $typeOfGuide & "Release", $guide)
        EndIf
    EndIf
EndFunc   ;==>_cveGuidedFilterTyped

Func _cveGuidedFilterMat($guide, $src, $dst, $radius, $eps, $dDepth = -1)
    ; cveGuidedFilter using cv::Mat instead of _*Array
    _cveGuidedFilterTyped("Mat", $guide, "Mat", $src, "Mat", $dst, $radius, $eps, $dDepth)
EndFunc   ;==>_cveGuidedFilterMat

Func _cveAmFilter($joint, $src, $dst, $sigmaS, $sigmaR, $adjustOutliers)
    ; CVAPI(void) cveAmFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, double sigmaS, double sigmaR, bool adjustOutliers);

    Local $sJointDllType
    If IsDllStruct($joint) Then
        $sJointDllType = "struct*"
    Else
        $sJointDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAmFilter", $sJointDllType, $joint, $sSrcDllType, $src, $sDstDllType, $dst, "double", $sigmaS, "double", $sigmaR, "boolean", $adjustOutliers), "cveAmFilter", @error)
EndFunc   ;==>_cveAmFilter

Func _cveAmFilterTyped($typeOfJoint, $joint, $typeOfSrc, $src, $typeOfDst, $dst, $sigmaS, $sigmaR, $adjustOutliers)

    Local $iArrJoint, $vectorJoint, $iArrJointSize
    Local $bJointIsArray = IsArray($joint)
    Local $bJointCreate = IsDllStruct($joint) And $typeOfJoint == "Scalar"

    If $typeOfJoint == Default Then
        $iArrJoint = $joint
    ElseIf $bJointIsArray Then
        $vectorJoint = Call("_VectorOf" & $typeOfJoint & "Create")

        $iArrJointSize = UBound($joint)
        For $i = 0 To $iArrJointSize - 1
            Call("_VectorOf" & $typeOfJoint & "Push", $vectorJoint, $joint[$i])
        Next

        $iArrJoint = Call("_cveInputArrayFromVectorOf" & $typeOfJoint, $vectorJoint)
    Else
        If $bJointCreate Then
            $joint = Call("_cve" & $typeOfJoint & "Create", $joint)
        EndIf
        $iArrJoint = Call("_cveInputArrayFrom" & $typeOfJoint, $joint)
    EndIf

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveAmFilter($iArrJoint, $iArrSrc, $oArrDst, $sigmaS, $sigmaR, $adjustOutliers)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    If $bJointIsArray Then
        Call("_VectorOf" & $typeOfJoint & "Release", $vectorJoint)
    EndIf

    If $typeOfJoint <> Default Then
        _cveInputArrayRelease($iArrJoint)
        If $bJointCreate Then
            Call("_cve" & $typeOfJoint & "Release", $joint)
        EndIf
    EndIf
EndFunc   ;==>_cveAmFilterTyped

Func _cveAmFilterMat($joint, $src, $dst, $sigmaS, $sigmaR, $adjustOutliers)
    ; cveAmFilter using cv::Mat instead of _*Array
    _cveAmFilterTyped("Mat", $joint, "Mat", $src, "Mat", $dst, $sigmaS, $sigmaR, $adjustOutliers)
EndFunc   ;==>_cveAmFilterMat

Func _cveJointBilateralFilter($joint, $src, $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(void) cveJointBilateralFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int borderType);

    Local $sJointDllType
    If IsDllStruct($joint) Then
        $sJointDllType = "struct*"
    Else
        $sJointDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveJointBilateralFilter", $sJointDllType, $joint, $sSrcDllType, $src, $sDstDllType, $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveJointBilateralFilter", @error)
EndFunc   ;==>_cveJointBilateralFilter

Func _cveJointBilateralFilterTyped($typeOfJoint, $joint, $typeOfSrc, $src, $typeOfDst, $dst, $d, $sigmaColor, $sigmaSpace, $borderType)

    Local $iArrJoint, $vectorJoint, $iArrJointSize
    Local $bJointIsArray = IsArray($joint)
    Local $bJointCreate = IsDllStruct($joint) And $typeOfJoint == "Scalar"

    If $typeOfJoint == Default Then
        $iArrJoint = $joint
    ElseIf $bJointIsArray Then
        $vectorJoint = Call("_VectorOf" & $typeOfJoint & "Create")

        $iArrJointSize = UBound($joint)
        For $i = 0 To $iArrJointSize - 1
            Call("_VectorOf" & $typeOfJoint & "Push", $vectorJoint, $joint[$i])
        Next

        $iArrJoint = Call("_cveInputArrayFromVectorOf" & $typeOfJoint, $vectorJoint)
    Else
        If $bJointCreate Then
            $joint = Call("_cve" & $typeOfJoint & "Create", $joint)
        EndIf
        $iArrJoint = Call("_cveInputArrayFrom" & $typeOfJoint, $joint)
    EndIf

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveJointBilateralFilter($iArrJoint, $iArrSrc, $oArrDst, $d, $sigmaColor, $sigmaSpace, $borderType)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    If $bJointIsArray Then
        Call("_VectorOf" & $typeOfJoint & "Release", $vectorJoint)
    EndIf

    If $typeOfJoint <> Default Then
        _cveInputArrayRelease($iArrJoint)
        If $bJointCreate Then
            Call("_cve" & $typeOfJoint & "Release", $joint)
        EndIf
    EndIf
EndFunc   ;==>_cveJointBilateralFilterTyped

Func _cveJointBilateralFilterMat($joint, $src, $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; cveJointBilateralFilter using cv::Mat instead of _*Array
    _cveJointBilateralFilterTyped("Mat", $joint, "Mat", $src, "Mat", $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
EndFunc   ;==>_cveJointBilateralFilterMat

Func _cveBilateralTextureFilter($src, $dst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
    ; CVAPI(void) cveBilateralTextureFilter(cv::_InputArray* src, cv::_OutputArray* dst, int fr, int numIter, double sigmaAlpha, double sigmaAvg);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBilateralTextureFilter", $sSrcDllType, $src, $sDstDllType, $dst, "int", $fr, "int", $numIter, "double", $sigmaAlpha, "double", $sigmaAvg), "cveBilateralTextureFilter", @error)
EndFunc   ;==>_cveBilateralTextureFilter

Func _cveBilateralTextureFilterTyped($typeOfSrc, $src, $typeOfDst, $dst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveBilateralTextureFilter($iArrSrc, $oArrDst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveBilateralTextureFilterTyped

Func _cveBilateralTextureFilterMat($src, $dst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
    ; cveBilateralTextureFilter using cv::Mat instead of _*Array
    _cveBilateralTextureFilterTyped("Mat", $src, "Mat", $dst, $fr, $numIter, $sigmaAlpha, $sigmaAvg)
EndFunc   ;==>_cveBilateralTextureFilterMat

Func _cveRollingGuidanceFilter($src, $dst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
    ; CVAPI(void) cveRollingGuidanceFilter(cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int numOfIter, int borderType);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRollingGuidanceFilter", $sSrcDllType, $src, $sDstDllType, $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $numOfIter, "int", $borderType), "cveRollingGuidanceFilter", @error)
EndFunc   ;==>_cveRollingGuidanceFilter

Func _cveRollingGuidanceFilterTyped($typeOfSrc, $src, $typeOfDst, $dst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveRollingGuidanceFilter($iArrSrc, $oArrDst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveRollingGuidanceFilterTyped

Func _cveRollingGuidanceFilterMat($src, $dst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
    ; cveRollingGuidanceFilter using cv::Mat instead of _*Array
    _cveRollingGuidanceFilterTyped("Mat", $src, "Mat", $dst, $d, $sigmaColor, $sigmaSpace, $numOfIter, $borderType)
EndFunc   ;==>_cveRollingGuidanceFilterMat

Func _cveFastGlobalSmootherFilter($guide, $src, $dst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
    ; CVAPI(void) cveFastGlobalSmootherFilter(cv::_InputArray* guide, cv::_InputArray* src, cv::_OutputArray* dst, double lambda, double sigmaColor, double lambdaAttenuation, int numIter);

    Local $sGuideDllType
    If IsDllStruct($guide) Then
        $sGuideDllType = "struct*"
    Else
        $sGuideDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastGlobalSmootherFilter", $sGuideDllType, $guide, $sSrcDllType, $src, $sDstDllType, $dst, "double", $lambda, "double", $sigmaColor, "double", $lambdaAttenuation, "int", $numIter), "cveFastGlobalSmootherFilter", @error)
EndFunc   ;==>_cveFastGlobalSmootherFilter

Func _cveFastGlobalSmootherFilterTyped($typeOfGuide, $guide, $typeOfSrc, $src, $typeOfDst, $dst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)

    Local $iArrGuide, $vectorGuide, $iArrGuideSize
    Local $bGuideIsArray = IsArray($guide)
    Local $bGuideCreate = IsDllStruct($guide) And $typeOfGuide == "Scalar"

    If $typeOfGuide == Default Then
        $iArrGuide = $guide
    ElseIf $bGuideIsArray Then
        $vectorGuide = Call("_VectorOf" & $typeOfGuide & "Create")

        $iArrGuideSize = UBound($guide)
        For $i = 0 To $iArrGuideSize - 1
            Call("_VectorOf" & $typeOfGuide & "Push", $vectorGuide, $guide[$i])
        Next

        $iArrGuide = Call("_cveInputArrayFromVectorOf" & $typeOfGuide, $vectorGuide)
    Else
        If $bGuideCreate Then
            $guide = Call("_cve" & $typeOfGuide & "Create", $guide)
        EndIf
        $iArrGuide = Call("_cveInputArrayFrom" & $typeOfGuide, $guide)
    EndIf

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveFastGlobalSmootherFilter($iArrGuide, $iArrSrc, $oArrDst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    If $bGuideIsArray Then
        Call("_VectorOf" & $typeOfGuide & "Release", $vectorGuide)
    EndIf

    If $typeOfGuide <> Default Then
        _cveInputArrayRelease($iArrGuide)
        If $bGuideCreate Then
            Call("_cve" & $typeOfGuide & "Release", $guide)
        EndIf
    EndIf
EndFunc   ;==>_cveFastGlobalSmootherFilterTyped

Func _cveFastGlobalSmootherFilterMat($guide, $src, $dst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
    ; cveFastGlobalSmootherFilter using cv::Mat instead of _*Array
    _cveFastGlobalSmootherFilterTyped("Mat", $guide, "Mat", $src, "Mat", $dst, $lambda, $sigmaColor, $lambdaAttenuation, $numIter)
EndFunc   ;==>_cveFastGlobalSmootherFilterMat

Func _cveL0Smooth($src, $dst, $lambda = 0.02, $kappa = 2.0)
    ; CVAPI(void) cveL0Smooth(cv::_InputArray* src, cv::_OutputArray* dst, double lambda, double kappa);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveL0Smooth", $sSrcDllType, $src, $sDstDllType, $dst, "double", $lambda, "double", $kappa), "cveL0Smooth", @error)
EndFunc   ;==>_cveL0Smooth

Func _cveL0SmoothTyped($typeOfSrc, $src, $typeOfDst, $dst, $lambda = 0.02, $kappa = 2.0)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveL0Smooth($iArrSrc, $oArrDst, $lambda, $kappa)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveL0SmoothTyped

Func _cveL0SmoothMat($src, $dst, $lambda = 0.02, $kappa = 2.0)
    ; cveL0Smooth using cv::Mat instead of _*Array
    _cveL0SmoothTyped("Mat", $src, "Mat", $dst, $lambda, $kappa)
EndFunc   ;==>_cveL0SmoothMat

Func _cveNiBlackThreshold($src, $dst, $maxValue, $type, $blockSize, $delta)
    ; CVAPI(void) cveNiBlackThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double maxValue, int type, int blockSize, double delta);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNiBlackThreshold", $sSrcDllType, $src, $sDstDllType, $dst, "double", $maxValue, "int", $type, "int", $blockSize, "double", $delta), "cveNiBlackThreshold", @error)
EndFunc   ;==>_cveNiBlackThreshold

Func _cveNiBlackThresholdTyped($typeOfSrc, $src, $typeOfDst, $dst, $maxValue, $type, $blockSize, $delta)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveNiBlackThreshold($iArrSrc, $oArrDst, $maxValue, $type, $blockSize, $delta)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveNiBlackThresholdTyped

Func _cveNiBlackThresholdMat($src, $dst, $maxValue, $type, $blockSize, $delta)
    ; cveNiBlackThreshold using cv::Mat instead of _*Array
    _cveNiBlackThresholdTyped("Mat", $src, "Mat", $dst, $maxValue, $type, $blockSize, $delta)
EndFunc   ;==>_cveNiBlackThresholdMat

Func _cveCovarianceEstimation($src, $dst, $windowRows, $windowCols)
    ; CVAPI(void) cveCovarianceEstimation(cv::_InputArray* src, cv::_OutputArray* dst, int windowRows, int windowCols);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCovarianceEstimation", $sSrcDllType, $src, $sDstDllType, $dst, "int", $windowRows, "int", $windowCols), "cveCovarianceEstimation", @error)
EndFunc   ;==>_cveCovarianceEstimation

Func _cveCovarianceEstimationTyped($typeOfSrc, $src, $typeOfDst, $dst, $windowRows, $windowCols)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveCovarianceEstimation($iArrSrc, $oArrDst, $windowRows, $windowCols)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveCovarianceEstimationTyped

Func _cveCovarianceEstimationMat($src, $dst, $windowRows, $windowCols)
    ; cveCovarianceEstimation using cv::Mat instead of _*Array
    _cveCovarianceEstimationTyped("Mat", $src, "Mat", $dst, $windowRows, $windowCols)
EndFunc   ;==>_cveCovarianceEstimationMat

Func _cveDTFilterCreate($guide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)
    ; CVAPI(cv::ximgproc::DTFilter*) cveDTFilterCreate(cv::_InputArray* guide, double sigmaSpatial, double sigmaColor, int mode, int numIters, cv::Ptr<cv::ximgproc::DTFilter>** sharedPtr);

    Local $sGuideDllType
    If IsDllStruct($guide) Then
        $sGuideDllType = "struct*"
    Else
        $sGuideDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDTFilterCreate", $sGuideDllType, $guide, "double", $sigmaSpatial, "double", $sigmaColor, "int", $mode, "int", $numIters, $sSharedPtrDllType, $sharedPtr), "cveDTFilterCreate", @error)
EndFunc   ;==>_cveDTFilterCreate

Func _cveDTFilterCreateTyped($typeOfGuide, $guide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)

    Local $iArrGuide, $vectorGuide, $iArrGuideSize
    Local $bGuideIsArray = IsArray($guide)
    Local $bGuideCreate = IsDllStruct($guide) And $typeOfGuide == "Scalar"

    If $typeOfGuide == Default Then
        $iArrGuide = $guide
    ElseIf $bGuideIsArray Then
        $vectorGuide = Call("_VectorOf" & $typeOfGuide & "Create")

        $iArrGuideSize = UBound($guide)
        For $i = 0 To $iArrGuideSize - 1
            Call("_VectorOf" & $typeOfGuide & "Push", $vectorGuide, $guide[$i])
        Next

        $iArrGuide = Call("_cveInputArrayFromVectorOf" & $typeOfGuide, $vectorGuide)
    Else
        If $bGuideCreate Then
            $guide = Call("_cve" & $typeOfGuide & "Create", $guide)
        EndIf
        $iArrGuide = Call("_cveInputArrayFrom" & $typeOfGuide, $guide)
    EndIf

    Local $retval = _cveDTFilterCreate($iArrGuide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)

    If $bGuideIsArray Then
        Call("_VectorOf" & $typeOfGuide & "Release", $vectorGuide)
    EndIf

    If $typeOfGuide <> Default Then
        _cveInputArrayRelease($iArrGuide)
        If $bGuideCreate Then
            Call("_cve" & $typeOfGuide & "Release", $guide)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveDTFilterCreateTyped

Func _cveDTFilterCreateMat($guide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)
    ; cveDTFilterCreate using cv::Mat instead of _*Array
    Local $retval = _cveDTFilterCreateTyped("Mat", $guide, $sigmaSpatial, $sigmaColor, $mode, $numIters, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveDTFilterCreateMat

Func _cveDTFilterFilter($filter, $src, $dst, $dDepth)
    ; CVAPI(void) cveDTFilterFilter(cv::ximgproc::DTFilter* filter, cv::_InputArray* src, cv::_OutputArray* dst, int dDepth);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    Else
        $sFilterDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTFilterFilter", $sFilterDllType, $filter, $sSrcDllType, $src, $sDstDllType, $dst, "int", $dDepth), "cveDTFilterFilter", @error)
EndFunc   ;==>_cveDTFilterFilter

Func _cveDTFilterFilterTyped($filter, $typeOfSrc, $src, $typeOfDst, $dst, $dDepth)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveDTFilterFilter($filter, $iArrSrc, $oArrDst, $dDepth)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveDTFilterFilterTyped

Func _cveDTFilterFilterMat($filter, $src, $dst, $dDepth)
    ; cveDTFilterFilter using cv::Mat instead of _*Array
    _cveDTFilterFilterTyped($filter, "Mat", $src, "Mat", $dst, $dDepth)
EndFunc   ;==>_cveDTFilterFilterMat

Func _cveDTFilterRelease($filter, $sharedPtr)
    ; CVAPI(void) cveDTFilterRelease(cv::ximgproc::DTFilter** filter, cv::Ptr<cv::ximgproc::DTFilter>** sharedPtr);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    ElseIf $filter == Null Then
        $sFilterDllType = "ptr"
    Else
        $sFilterDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTFilterRelease", $sFilterDllType, $filter, $sSharedPtrDllType, $sharedPtr), "cveDTFilterRelease", @error)
EndFunc   ;==>_cveDTFilterRelease

Func _cveRFFeatureGetterCreate($sharedPtr)
    ; CVAPI(cv::ximgproc::RFFeatureGetter*) cveRFFeatureGetterCreate(cv::Ptr<cv::ximgproc::RFFeatureGetter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRFFeatureGetterCreate", $sSharedPtrDllType, $sharedPtr), "cveRFFeatureGetterCreate", @error)
EndFunc   ;==>_cveRFFeatureGetterCreate

Func _cveRFFeatureGetterRelease($getter, $sharedPtr)
    ; CVAPI(void) cveRFFeatureGetterRelease(cv::ximgproc::RFFeatureGetter** getter, cv::Ptr<cv::ximgproc::RFFeatureGetter>** sharedPtr);

    Local $sGetterDllType
    If IsDllStruct($getter) Then
        $sGetterDllType = "struct*"
    ElseIf $getter == Null Then
        $sGetterDllType = "ptr"
    Else
        $sGetterDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRFFeatureGetterRelease", $sGetterDllType, $getter, $sSharedPtrDllType, $sharedPtr), "cveRFFeatureGetterRelease", @error)
EndFunc   ;==>_cveRFFeatureGetterRelease

Func _cveStructuredEdgeDetectionCreate($model, $howToGetFeatures, $sharedPtr)
    ; CVAPI(cv::ximgproc::StructuredEdgeDetection*) cveStructuredEdgeDetectionCreate(cv::String* model, cv::ximgproc::RFFeatureGetter* howToGetFeatures, cv::Ptr<cv::ximgproc::StructuredEdgeDetection>** sharedPtr);

    Local $bModelIsString = IsString($model)
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sHowToGetFeaturesDllType
    If IsDllStruct($howToGetFeatures) Then
        $sHowToGetFeaturesDllType = "struct*"
    Else
        $sHowToGetFeaturesDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStructuredEdgeDetectionCreate", $sModelDllType, $model, $sHowToGetFeaturesDllType, $howToGetFeatures, $sSharedPtrDllType, $sharedPtr), "cveStructuredEdgeDetectionCreate", @error)

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveStructuredEdgeDetectionCreate

Func _cveStructuredEdgeDetectionDetectEdges($detection, $src, $dst)
    ; CVAPI(void) cveStructuredEdgeDetectionDetectEdges(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sDetectionDllType
    If IsDllStruct($detection) Then
        $sDetectionDllType = "struct*"
    Else
        $sDetectionDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionDetectEdges", $sDetectionDllType, $detection, $sSrcDllType, $src, $sDstDllType, $dst), "cveStructuredEdgeDetectionDetectEdges", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionDetectEdges

Func _cveStructuredEdgeDetectionDetectEdgesTyped($detection, $typeOfSrc, $src, $typeOfDst, $dst)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveStructuredEdgeDetectionDetectEdges($detection, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveStructuredEdgeDetectionDetectEdgesTyped

Func _cveStructuredEdgeDetectionDetectEdgesMat($detection, $src, $dst)
    ; cveStructuredEdgeDetectionDetectEdges using cv::Mat instead of _*Array
    _cveStructuredEdgeDetectionDetectEdgesTyped($detection, "Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveStructuredEdgeDetectionDetectEdgesMat

Func _cveStructuredEdgeDetectionComputeOrientation($detection, $src, $dst)
    ; CVAPI(void) cveStructuredEdgeDetectionComputeOrientation(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sDetectionDllType
    If IsDllStruct($detection) Then
        $sDetectionDllType = "struct*"
    Else
        $sDetectionDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionComputeOrientation", $sDetectionDllType, $detection, $sSrcDllType, $src, $sDstDllType, $dst), "cveStructuredEdgeDetectionComputeOrientation", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionComputeOrientation

Func _cveStructuredEdgeDetectionComputeOrientationTyped($detection, $typeOfSrc, $src, $typeOfDst, $dst)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveStructuredEdgeDetectionComputeOrientation($detection, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveStructuredEdgeDetectionComputeOrientationTyped

Func _cveStructuredEdgeDetectionComputeOrientationMat($detection, $src, $dst)
    ; cveStructuredEdgeDetectionComputeOrientation using cv::Mat instead of _*Array
    _cveStructuredEdgeDetectionComputeOrientationTyped($detection, "Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveStructuredEdgeDetectionComputeOrientationMat

Func _cveStructuredEdgeDetectionEdgesNms($detection, $edgeImage, $orientationImage, $dst, $r, $s, $m, $isParallel)
    ; CVAPI(void) cveStructuredEdgeDetectionEdgesNms(cv::ximgproc::StructuredEdgeDetection* detection, cv::_InputArray* edgeImage, cv::_InputArray* orientationImage, cv::_OutputArray* dst, int r, int s, float m, bool isParallel);

    Local $sDetectionDllType
    If IsDllStruct($detection) Then
        $sDetectionDllType = "struct*"
    Else
        $sDetectionDllType = "ptr"
    EndIf

    Local $sEdgeImageDllType
    If IsDllStruct($edgeImage) Then
        $sEdgeImageDllType = "struct*"
    Else
        $sEdgeImageDllType = "ptr"
    EndIf

    Local $sOrientationImageDllType
    If IsDllStruct($orientationImage) Then
        $sOrientationImageDllType = "struct*"
    Else
        $sOrientationImageDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionEdgesNms", $sDetectionDllType, $detection, $sEdgeImageDllType, $edgeImage, $sOrientationImageDllType, $orientationImage, $sDstDllType, $dst, "int", $r, "int", $s, "float", $m, "boolean", $isParallel), "cveStructuredEdgeDetectionEdgesNms", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionEdgesNms

Func _cveStructuredEdgeDetectionEdgesNmsTyped($detection, $typeOfEdgeImage, $edgeImage, $typeOfOrientationImage, $orientationImage, $typeOfDst, $dst, $r, $s, $m, $isParallel)

    Local $iArrEdgeImage, $vectorEdgeImage, $iArrEdgeImageSize
    Local $bEdgeImageIsArray = IsArray($edgeImage)
    Local $bEdgeImageCreate = IsDllStruct($edgeImage) And $typeOfEdgeImage == "Scalar"

    If $typeOfEdgeImage == Default Then
        $iArrEdgeImage = $edgeImage
    ElseIf $bEdgeImageIsArray Then
        $vectorEdgeImage = Call("_VectorOf" & $typeOfEdgeImage & "Create")

        $iArrEdgeImageSize = UBound($edgeImage)
        For $i = 0 To $iArrEdgeImageSize - 1
            Call("_VectorOf" & $typeOfEdgeImage & "Push", $vectorEdgeImage, $edgeImage[$i])
        Next

        $iArrEdgeImage = Call("_cveInputArrayFromVectorOf" & $typeOfEdgeImage, $vectorEdgeImage)
    Else
        If $bEdgeImageCreate Then
            $edgeImage = Call("_cve" & $typeOfEdgeImage & "Create", $edgeImage)
        EndIf
        $iArrEdgeImage = Call("_cveInputArrayFrom" & $typeOfEdgeImage, $edgeImage)
    EndIf

    Local $iArrOrientationImage, $vectorOrientationImage, $iArrOrientationImageSize
    Local $bOrientationImageIsArray = IsArray($orientationImage)
    Local $bOrientationImageCreate = IsDllStruct($orientationImage) And $typeOfOrientationImage == "Scalar"

    If $typeOfOrientationImage == Default Then
        $iArrOrientationImage = $orientationImage
    ElseIf $bOrientationImageIsArray Then
        $vectorOrientationImage = Call("_VectorOf" & $typeOfOrientationImage & "Create")

        $iArrOrientationImageSize = UBound($orientationImage)
        For $i = 0 To $iArrOrientationImageSize - 1
            Call("_VectorOf" & $typeOfOrientationImage & "Push", $vectorOrientationImage, $orientationImage[$i])
        Next

        $iArrOrientationImage = Call("_cveInputArrayFromVectorOf" & $typeOfOrientationImage, $vectorOrientationImage)
    Else
        If $bOrientationImageCreate Then
            $orientationImage = Call("_cve" & $typeOfOrientationImage & "Create", $orientationImage)
        EndIf
        $iArrOrientationImage = Call("_cveInputArrayFrom" & $typeOfOrientationImage, $orientationImage)
    EndIf

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

    _cveStructuredEdgeDetectionEdgesNms($detection, $iArrEdgeImage, $iArrOrientationImage, $oArrDst, $r, $s, $m, $isParallel)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bOrientationImageIsArray Then
        Call("_VectorOf" & $typeOfOrientationImage & "Release", $vectorOrientationImage)
    EndIf

    If $typeOfOrientationImage <> Default Then
        _cveInputArrayRelease($iArrOrientationImage)
        If $bOrientationImageCreate Then
            Call("_cve" & $typeOfOrientationImage & "Release", $orientationImage)
        EndIf
    EndIf

    If $bEdgeImageIsArray Then
        Call("_VectorOf" & $typeOfEdgeImage & "Release", $vectorEdgeImage)
    EndIf

    If $typeOfEdgeImage <> Default Then
        _cveInputArrayRelease($iArrEdgeImage)
        If $bEdgeImageCreate Then
            Call("_cve" & $typeOfEdgeImage & "Release", $edgeImage)
        EndIf
    EndIf
EndFunc   ;==>_cveStructuredEdgeDetectionEdgesNmsTyped

Func _cveStructuredEdgeDetectionEdgesNmsMat($detection, $edgeImage, $orientationImage, $dst, $r, $s, $m, $isParallel)
    ; cveStructuredEdgeDetectionEdgesNms using cv::Mat instead of _*Array
    _cveStructuredEdgeDetectionEdgesNmsTyped($detection, "Mat", $edgeImage, "Mat", $orientationImage, "Mat", $dst, $r, $s, $m, $isParallel)
EndFunc   ;==>_cveStructuredEdgeDetectionEdgesNmsMat

Func _cveStructuredEdgeDetectionRelease($detection, $sharedPtr)
    ; CVAPI(void) cveStructuredEdgeDetectionRelease(cv::ximgproc::StructuredEdgeDetection** detection, cv::Ptr<cv::ximgproc::StructuredEdgeDetection>** sharedPtr);

    Local $sDetectionDllType
    If IsDllStruct($detection) Then
        $sDetectionDllType = "struct*"
    ElseIf $detection == Null Then
        $sDetectionDllType = "ptr"
    Else
        $sDetectionDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStructuredEdgeDetectionRelease", $sDetectionDllType, $detection, $sSharedPtrDllType, $sharedPtr), "cveStructuredEdgeDetectionRelease", @error)
EndFunc   ;==>_cveStructuredEdgeDetectionRelease

Func _cveSuperpixelSEEDSCreate($imageWidth, $imageHeight, $imageChannels, $numSuperpixels, $numLevels, $prior, $histogramBins, $doubleStep, $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelSEEDS*) cveSuperpixelSEEDSCreate(int imageWidth, int imageHeight, int imageChannels, int numSuperpixels, int numLevels, int prior, int histogramBins, bool doubleStep, cv::Ptr<cv::ximgproc::SuperpixelSEEDS>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelSEEDSCreate", "int", $imageWidth, "int", $imageHeight, "int", $imageChannels, "int", $numSuperpixels, "int", $numLevels, "int", $prior, "int", $histogramBins, "boolean", $doubleStep, $sSharedPtrDllType, $sharedPtr), "cveSuperpixelSEEDSCreate", @error)
EndFunc   ;==>_cveSuperpixelSEEDSCreate

Func _cveSuperpixelSEEDSGetNumberOfSuperpixels($seeds)
    ; CVAPI(int) cveSuperpixelSEEDSGetNumberOfSuperpixels(cv::ximgproc::SuperpixelSEEDS* seeds);

    Local $sSeedsDllType
    If IsDllStruct($seeds) Then
        $sSeedsDllType = "struct*"
    Else
        $sSeedsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelSEEDSGetNumberOfSuperpixels", $sSeedsDllType, $seeds), "cveSuperpixelSEEDSGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetNumberOfSuperpixels

Func _cveSuperpixelSEEDSGetLabels($seeds, $labelsOut)
    ; CVAPI(void) cveSuperpixelSEEDSGetLabels(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_OutputArray* labelsOut);

    Local $sSeedsDllType
    If IsDllStruct($seeds) Then
        $sSeedsDllType = "struct*"
    Else
        $sSeedsDllType = "ptr"
    EndIf

    Local $sLabelsOutDllType
    If IsDllStruct($labelsOut) Then
        $sLabelsOutDllType = "struct*"
    Else
        $sLabelsOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSGetLabels", $sSeedsDllType, $seeds, $sLabelsOutDllType, $labelsOut), "cveSuperpixelSEEDSGetLabels", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabels

Func _cveSuperpixelSEEDSGetLabelsTyped($seeds, $typeOfLabelsOut, $labelsOut)

    Local $oArrLabelsOut, $vectorLabelsOut, $iArrLabelsOutSize
    Local $bLabelsOutIsArray = IsArray($labelsOut)
    Local $bLabelsOutCreate = IsDllStruct($labelsOut) And $typeOfLabelsOut == "Scalar"

    If $typeOfLabelsOut == Default Then
        $oArrLabelsOut = $labelsOut
    ElseIf $bLabelsOutIsArray Then
        $vectorLabelsOut = Call("_VectorOf" & $typeOfLabelsOut & "Create")

        $iArrLabelsOutSize = UBound($labelsOut)
        For $i = 0 To $iArrLabelsOutSize - 1
            Call("_VectorOf" & $typeOfLabelsOut & "Push", $vectorLabelsOut, $labelsOut[$i])
        Next

        $oArrLabelsOut = Call("_cveOutputArrayFromVectorOf" & $typeOfLabelsOut, $vectorLabelsOut)
    Else
        If $bLabelsOutCreate Then
            $labelsOut = Call("_cve" & $typeOfLabelsOut & "Create", $labelsOut)
        EndIf
        $oArrLabelsOut = Call("_cveOutputArrayFrom" & $typeOfLabelsOut, $labelsOut)
    EndIf

    _cveSuperpixelSEEDSGetLabels($seeds, $oArrLabelsOut)

    If $bLabelsOutIsArray Then
        Call("_VectorOf" & $typeOfLabelsOut & "Release", $vectorLabelsOut)
    EndIf

    If $typeOfLabelsOut <> Default Then
        _cveOutputArrayRelease($oArrLabelsOut)
        If $bLabelsOutCreate Then
            Call("_cve" & $typeOfLabelsOut & "Release", $labelsOut)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelsTyped

Func _cveSuperpixelSEEDSGetLabelsMat($seeds, $labelsOut)
    ; cveSuperpixelSEEDSGetLabels using cv::Mat instead of _*Array
    _cveSuperpixelSEEDSGetLabelsTyped($seeds, "Mat", $labelsOut)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelsMat

Func _cveSuperpixelSEEDSGetLabelContourMask($seeds, $image, $thickLine)
    ; CVAPI(void) cveSuperpixelSEEDSGetLabelContourMask(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_OutputArray* image, bool thickLine);

    Local $sSeedsDllType
    If IsDllStruct($seeds) Then
        $sSeedsDllType = "struct*"
    Else
        $sSeedsDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSGetLabelContourMask", $sSeedsDllType, $seeds, $sImageDllType, $image, "boolean", $thickLine), "cveSuperpixelSEEDSGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelContourMask

Func _cveSuperpixelSEEDSGetLabelContourMaskTyped($seeds, $typeOfImage, $image, $thickLine)

    Local $oArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $oArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $oArrImage = Call("_cveOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $oArrImage = Call("_cveOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    _cveSuperpixelSEEDSGetLabelContourMask($seeds, $oArrImage, $thickLine)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveOutputArrayRelease($oArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelContourMaskTyped

Func _cveSuperpixelSEEDSGetLabelContourMaskMat($seeds, $image, $thickLine)
    ; cveSuperpixelSEEDSGetLabelContourMask using cv::Mat instead of _*Array
    _cveSuperpixelSEEDSGetLabelContourMaskTyped($seeds, "Mat", $image, $thickLine)
EndFunc   ;==>_cveSuperpixelSEEDSGetLabelContourMaskMat

Func _cveSuperpixelSEEDSIterate($seeds, $img, $numIterations)
    ; CVAPI(void) cveSuperpixelSEEDSIterate(cv::ximgproc::SuperpixelSEEDS* seeds, cv::_InputArray* img, int numIterations);

    Local $sSeedsDllType
    If IsDllStruct($seeds) Then
        $sSeedsDllType = "struct*"
    Else
        $sSeedsDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSIterate", $sSeedsDllType, $seeds, $sImgDllType, $img, "int", $numIterations), "cveSuperpixelSEEDSIterate", @error)
EndFunc   ;==>_cveSuperpixelSEEDSIterate

Func _cveSuperpixelSEEDSIterateTyped($seeds, $typeOfImg, $img, $numIterations)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveSuperpixelSEEDSIterate($seeds, $iArrImg, $numIterations)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelSEEDSIterateTyped

Func _cveSuperpixelSEEDSIterateMat($seeds, $img, $numIterations)
    ; cveSuperpixelSEEDSIterate using cv::Mat instead of _*Array
    _cveSuperpixelSEEDSIterateTyped($seeds, "Mat", $img, $numIterations)
EndFunc   ;==>_cveSuperpixelSEEDSIterateMat

Func _cveSuperpixelSEEDSRelease($seeds, $sharedPtr)
    ; CVAPI(void) cveSuperpixelSEEDSRelease(cv::ximgproc::SuperpixelSEEDS** seeds, cv::Ptr<cv::ximgproc::SuperpixelSEEDS>** sharedPtr);

    Local $sSeedsDllType
    If IsDllStruct($seeds) Then
        $sSeedsDllType = "struct*"
    ElseIf $seeds == Null Then
        $sSeedsDllType = "ptr"
    Else
        $sSeedsDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSEEDSRelease", $sSeedsDllType, $seeds, $sSharedPtrDllType, $sharedPtr), "cveSuperpixelSEEDSRelease", @error)
EndFunc   ;==>_cveSuperpixelSEEDSRelease

Func _cveSuperpixelLSCCreate($image, $regionSize, $ratio, $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelLSC*) cveSuperpixelLSCCreate(cv::_InputArray* image, int regionSize, float ratio, cv::Ptr<cv::ximgproc::SuperpixelLSC>** sharedPtr);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelLSCCreate", $sImageDllType, $image, "int", $regionSize, "float", $ratio, $sSharedPtrDllType, $sharedPtr), "cveSuperpixelLSCCreate", @error)
EndFunc   ;==>_cveSuperpixelLSCCreate

Func _cveSuperpixelLSCCreateTyped($typeOfImage, $image, $regionSize, $ratio, $sharedPtr)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $retval = _cveSuperpixelLSCCreate($iArrImage, $regionSize, $ratio, $sharedPtr)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSuperpixelLSCCreateTyped

Func _cveSuperpixelLSCCreateMat($image, $regionSize, $ratio, $sharedPtr)
    ; cveSuperpixelLSCCreate using cv::Mat instead of _*Array
    Local $retval = _cveSuperpixelLSCCreateTyped("Mat", $image, $regionSize, $ratio, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveSuperpixelLSCCreateMat

Func _cveSuperpixelLSCGetNumberOfSuperpixels($lsc)
    ; CVAPI(int) cveSuperpixelLSCGetNumberOfSuperpixels(cv::ximgproc::SuperpixelLSC* lsc);

    Local $sLscDllType
    If IsDllStruct($lsc) Then
        $sLscDllType = "struct*"
    Else
        $sLscDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelLSCGetNumberOfSuperpixels", $sLscDllType, $lsc), "cveSuperpixelLSCGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelLSCGetNumberOfSuperpixels

Func _cveSuperpixelLSCIterate($lsc, $numIterations)
    ; CVAPI(void) cveSuperpixelLSCIterate(cv::ximgproc::SuperpixelLSC* lsc, int numIterations);

    Local $sLscDllType
    If IsDllStruct($lsc) Then
        $sLscDllType = "struct*"
    Else
        $sLscDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCIterate", $sLscDllType, $lsc, "int", $numIterations), "cveSuperpixelLSCIterate", @error)
EndFunc   ;==>_cveSuperpixelLSCIterate

Func _cveSuperpixelLSCGetLabels($lsc, $labelsOut)
    ; CVAPI(void) cveSuperpixelLSCGetLabels(cv::ximgproc::SuperpixelLSC* lsc, cv::_OutputArray* labelsOut);

    Local $sLscDllType
    If IsDllStruct($lsc) Then
        $sLscDllType = "struct*"
    Else
        $sLscDllType = "ptr"
    EndIf

    Local $sLabelsOutDllType
    If IsDllStruct($labelsOut) Then
        $sLabelsOutDllType = "struct*"
    Else
        $sLabelsOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCGetLabels", $sLscDllType, $lsc, $sLabelsOutDllType, $labelsOut), "cveSuperpixelLSCGetLabels", @error)
EndFunc   ;==>_cveSuperpixelLSCGetLabels

Func _cveSuperpixelLSCGetLabelsTyped($lsc, $typeOfLabelsOut, $labelsOut)

    Local $oArrLabelsOut, $vectorLabelsOut, $iArrLabelsOutSize
    Local $bLabelsOutIsArray = IsArray($labelsOut)
    Local $bLabelsOutCreate = IsDllStruct($labelsOut) And $typeOfLabelsOut == "Scalar"

    If $typeOfLabelsOut == Default Then
        $oArrLabelsOut = $labelsOut
    ElseIf $bLabelsOutIsArray Then
        $vectorLabelsOut = Call("_VectorOf" & $typeOfLabelsOut & "Create")

        $iArrLabelsOutSize = UBound($labelsOut)
        For $i = 0 To $iArrLabelsOutSize - 1
            Call("_VectorOf" & $typeOfLabelsOut & "Push", $vectorLabelsOut, $labelsOut[$i])
        Next

        $oArrLabelsOut = Call("_cveOutputArrayFromVectorOf" & $typeOfLabelsOut, $vectorLabelsOut)
    Else
        If $bLabelsOutCreate Then
            $labelsOut = Call("_cve" & $typeOfLabelsOut & "Create", $labelsOut)
        EndIf
        $oArrLabelsOut = Call("_cveOutputArrayFrom" & $typeOfLabelsOut, $labelsOut)
    EndIf

    _cveSuperpixelLSCGetLabels($lsc, $oArrLabelsOut)

    If $bLabelsOutIsArray Then
        Call("_VectorOf" & $typeOfLabelsOut & "Release", $vectorLabelsOut)
    EndIf

    If $typeOfLabelsOut <> Default Then
        _cveOutputArrayRelease($oArrLabelsOut)
        If $bLabelsOutCreate Then
            Call("_cve" & $typeOfLabelsOut & "Release", $labelsOut)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelLSCGetLabelsTyped

Func _cveSuperpixelLSCGetLabelsMat($lsc, $labelsOut)
    ; cveSuperpixelLSCGetLabels using cv::Mat instead of _*Array
    _cveSuperpixelLSCGetLabelsTyped($lsc, "Mat", $labelsOut)
EndFunc   ;==>_cveSuperpixelLSCGetLabelsMat

Func _cveSuperpixelLSCGetLabelContourMask($lsc, $image, $thickLine)
    ; CVAPI(void) cveSuperpixelLSCGetLabelContourMask(cv::ximgproc::SuperpixelLSC* lsc, cv::_OutputArray* image, bool thickLine);

    Local $sLscDllType
    If IsDllStruct($lsc) Then
        $sLscDllType = "struct*"
    Else
        $sLscDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCGetLabelContourMask", $sLscDllType, $lsc, $sImageDllType, $image, "boolean", $thickLine), "cveSuperpixelLSCGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelLSCGetLabelContourMask

Func _cveSuperpixelLSCGetLabelContourMaskTyped($lsc, $typeOfImage, $image, $thickLine)

    Local $oArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $oArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $oArrImage = Call("_cveOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $oArrImage = Call("_cveOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    _cveSuperpixelLSCGetLabelContourMask($lsc, $oArrImage, $thickLine)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveOutputArrayRelease($oArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelLSCGetLabelContourMaskTyped

Func _cveSuperpixelLSCGetLabelContourMaskMat($lsc, $image, $thickLine)
    ; cveSuperpixelLSCGetLabelContourMask using cv::Mat instead of _*Array
    _cveSuperpixelLSCGetLabelContourMaskTyped($lsc, "Mat", $image, $thickLine)
EndFunc   ;==>_cveSuperpixelLSCGetLabelContourMaskMat

Func _cveSuperpixelLSCEnforceLabelConnectivity($lsc, $minElementSize)
    ; CVAPI(void) cveSuperpixelLSCEnforceLabelConnectivity(cv::ximgproc::SuperpixelLSC* lsc, int minElementSize);

    Local $sLscDllType
    If IsDllStruct($lsc) Then
        $sLscDllType = "struct*"
    Else
        $sLscDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCEnforceLabelConnectivity", $sLscDllType, $lsc, "int", $minElementSize), "cveSuperpixelLSCEnforceLabelConnectivity", @error)
EndFunc   ;==>_cveSuperpixelLSCEnforceLabelConnectivity

Func _cveSuperpixelLSCRelease($lsc, $sharedPtr)
    ; CVAPI(void) cveSuperpixelLSCRelease(cv::ximgproc::SuperpixelLSC** lsc, cv::Ptr<cv::ximgproc::SuperpixelLSC>** sharedPtr);

    Local $sLscDllType
    If IsDllStruct($lsc) Then
        $sLscDllType = "struct*"
    ElseIf $lsc == Null Then
        $sLscDllType = "ptr"
    Else
        $sLscDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelLSCRelease", $sLscDllType, $lsc, $sSharedPtrDllType, $sharedPtr), "cveSuperpixelLSCRelease", @error)
EndFunc   ;==>_cveSuperpixelLSCRelease

Func _cveSuperpixelSLICCreate($image, $algorithm, $regionSize, $ruler, $sharedPtr)
    ; CVAPI(cv::ximgproc::SuperpixelSLIC*) cveSuperpixelSLICCreate(cv::_InputArray* image, int algorithm, int regionSize, float ruler, cv::Ptr<cv::ximgproc::SuperpixelSLIC>** sharedPtr);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSuperpixelSLICCreate", $sImageDllType, $image, "int", $algorithm, "int", $regionSize, "float", $ruler, $sSharedPtrDllType, $sharedPtr), "cveSuperpixelSLICCreate", @error)
EndFunc   ;==>_cveSuperpixelSLICCreate

Func _cveSuperpixelSLICCreateTyped($typeOfImage, $image, $algorithm, $regionSize, $ruler, $sharedPtr)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $retval = _cveSuperpixelSLICCreate($iArrImage, $algorithm, $regionSize, $ruler, $sharedPtr)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSuperpixelSLICCreateTyped

Func _cveSuperpixelSLICCreateMat($image, $algorithm, $regionSize, $ruler, $sharedPtr)
    ; cveSuperpixelSLICCreate using cv::Mat instead of _*Array
    Local $retval = _cveSuperpixelSLICCreateTyped("Mat", $image, $algorithm, $regionSize, $ruler, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveSuperpixelSLICCreateMat

Func _cveSuperpixelSLICGetNumberOfSuperpixels($slic)
    ; CVAPI(int) cveSuperpixelSLICGetNumberOfSuperpixels(cv::ximgproc::SuperpixelSLIC* slic);

    Local $sSlicDllType
    If IsDllStruct($slic) Then
        $sSlicDllType = "struct*"
    Else
        $sSlicDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSuperpixelSLICGetNumberOfSuperpixels", $sSlicDllType, $slic), "cveSuperpixelSLICGetNumberOfSuperpixels", @error)
EndFunc   ;==>_cveSuperpixelSLICGetNumberOfSuperpixels

Func _cveSuperpixelSLICIterate($slic, $numIterations)
    ; CVAPI(void) cveSuperpixelSLICIterate(cv::ximgproc::SuperpixelSLIC* slic, int numIterations);

    Local $sSlicDllType
    If IsDllStruct($slic) Then
        $sSlicDllType = "struct*"
    Else
        $sSlicDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICIterate", $sSlicDllType, $slic, "int", $numIterations), "cveSuperpixelSLICIterate", @error)
EndFunc   ;==>_cveSuperpixelSLICIterate

Func _cveSuperpixelSLICGetLabels($slic, $labelsOut)
    ; CVAPI(void) cveSuperpixelSLICGetLabels(cv::ximgproc::SuperpixelSLIC* slic, cv::_OutputArray* labelsOut);

    Local $sSlicDllType
    If IsDllStruct($slic) Then
        $sSlicDllType = "struct*"
    Else
        $sSlicDllType = "ptr"
    EndIf

    Local $sLabelsOutDllType
    If IsDllStruct($labelsOut) Then
        $sLabelsOutDllType = "struct*"
    Else
        $sLabelsOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICGetLabels", $sSlicDllType, $slic, $sLabelsOutDllType, $labelsOut), "cveSuperpixelSLICGetLabels", @error)
EndFunc   ;==>_cveSuperpixelSLICGetLabels

Func _cveSuperpixelSLICGetLabelsTyped($slic, $typeOfLabelsOut, $labelsOut)

    Local $oArrLabelsOut, $vectorLabelsOut, $iArrLabelsOutSize
    Local $bLabelsOutIsArray = IsArray($labelsOut)
    Local $bLabelsOutCreate = IsDllStruct($labelsOut) And $typeOfLabelsOut == "Scalar"

    If $typeOfLabelsOut == Default Then
        $oArrLabelsOut = $labelsOut
    ElseIf $bLabelsOutIsArray Then
        $vectorLabelsOut = Call("_VectorOf" & $typeOfLabelsOut & "Create")

        $iArrLabelsOutSize = UBound($labelsOut)
        For $i = 0 To $iArrLabelsOutSize - 1
            Call("_VectorOf" & $typeOfLabelsOut & "Push", $vectorLabelsOut, $labelsOut[$i])
        Next

        $oArrLabelsOut = Call("_cveOutputArrayFromVectorOf" & $typeOfLabelsOut, $vectorLabelsOut)
    Else
        If $bLabelsOutCreate Then
            $labelsOut = Call("_cve" & $typeOfLabelsOut & "Create", $labelsOut)
        EndIf
        $oArrLabelsOut = Call("_cveOutputArrayFrom" & $typeOfLabelsOut, $labelsOut)
    EndIf

    _cveSuperpixelSLICGetLabels($slic, $oArrLabelsOut)

    If $bLabelsOutIsArray Then
        Call("_VectorOf" & $typeOfLabelsOut & "Release", $vectorLabelsOut)
    EndIf

    If $typeOfLabelsOut <> Default Then
        _cveOutputArrayRelease($oArrLabelsOut)
        If $bLabelsOutCreate Then
            Call("_cve" & $typeOfLabelsOut & "Release", $labelsOut)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelSLICGetLabelsTyped

Func _cveSuperpixelSLICGetLabelsMat($slic, $labelsOut)
    ; cveSuperpixelSLICGetLabels using cv::Mat instead of _*Array
    _cveSuperpixelSLICGetLabelsTyped($slic, "Mat", $labelsOut)
EndFunc   ;==>_cveSuperpixelSLICGetLabelsMat

Func _cveSuperpixelSLICGetLabelContourMask($slic, $image, $thickLine)
    ; CVAPI(void) cveSuperpixelSLICGetLabelContourMask(cv::ximgproc::SuperpixelSLIC* slic, cv::_OutputArray* image, bool thickLine);

    Local $sSlicDllType
    If IsDllStruct($slic) Then
        $sSlicDllType = "struct*"
    Else
        $sSlicDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICGetLabelContourMask", $sSlicDllType, $slic, $sImageDllType, $image, "boolean", $thickLine), "cveSuperpixelSLICGetLabelContourMask", @error)
EndFunc   ;==>_cveSuperpixelSLICGetLabelContourMask

Func _cveSuperpixelSLICGetLabelContourMaskTyped($slic, $typeOfImage, $image, $thickLine)

    Local $oArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $oArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $oArrImage = Call("_cveOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $oArrImage = Call("_cveOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    _cveSuperpixelSLICGetLabelContourMask($slic, $oArrImage, $thickLine)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveOutputArrayRelease($oArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveSuperpixelSLICGetLabelContourMaskTyped

Func _cveSuperpixelSLICGetLabelContourMaskMat($slic, $image, $thickLine)
    ; cveSuperpixelSLICGetLabelContourMask using cv::Mat instead of _*Array
    _cveSuperpixelSLICGetLabelContourMaskTyped($slic, "Mat", $image, $thickLine)
EndFunc   ;==>_cveSuperpixelSLICGetLabelContourMaskMat

Func _cveSuperpixelSLICEnforceLabelConnectivity($slic, $minElementSize)
    ; CVAPI(void) cveSuperpixelSLICEnforceLabelConnectivity(cv::ximgproc::SuperpixelSLIC* slic, int minElementSize);

    Local $sSlicDllType
    If IsDllStruct($slic) Then
        $sSlicDllType = "struct*"
    Else
        $sSlicDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICEnforceLabelConnectivity", $sSlicDllType, $slic, "int", $minElementSize), "cveSuperpixelSLICEnforceLabelConnectivity", @error)
EndFunc   ;==>_cveSuperpixelSLICEnforceLabelConnectivity

Func _cveSuperpixelSLICRelease($slic, $sharedPtr)
    ; CVAPI(void) cveSuperpixelSLICRelease(cv::ximgproc::SuperpixelSLIC** slic, cv::Ptr<cv::ximgproc::SuperpixelSLIC>** sharedPtr);

    Local $sSlicDllType
    If IsDllStruct($slic) Then
        $sSlicDllType = "struct*"
    ElseIf $slic == Null Then
        $sSlicDllType = "ptr"
    Else
        $sSlicDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSuperpixelSLICRelease", $sSlicDllType, $slic, $sSharedPtrDllType, $sharedPtr), "cveSuperpixelSLICRelease", @error)
EndFunc   ;==>_cveSuperpixelSLICRelease

Func _cveGraphSegmentationCreate($sigma, $k, $minSize, $sharedPtr)
    ; CVAPI(cv::ximgproc::segmentation::GraphSegmentation*) cveGraphSegmentationCreate(double sigma, float k, int minSize, cv::Ptr<cv::ximgproc::segmentation::GraphSegmentation>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGraphSegmentationCreate", "double", $sigma, "float", $k, "int", $minSize, $sSharedPtrDllType, $sharedPtr), "cveGraphSegmentationCreate", @error)
EndFunc   ;==>_cveGraphSegmentationCreate

Func _cveGraphSegmentationProcessImage($segmentation, $src, $dst)
    ; CVAPI(void) cveGraphSegmentationProcessImage(cv::ximgproc::segmentation::GraphSegmentation* segmentation, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphSegmentationProcessImage", $sSegmentationDllType, $segmentation, $sSrcDllType, $src, $sDstDllType, $dst), "cveGraphSegmentationProcessImage", @error)
EndFunc   ;==>_cveGraphSegmentationProcessImage

Func _cveGraphSegmentationProcessImageTyped($segmentation, $typeOfSrc, $src, $typeOfDst, $dst)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveGraphSegmentationProcessImage($segmentation, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveGraphSegmentationProcessImageTyped

Func _cveGraphSegmentationProcessImageMat($segmentation, $src, $dst)
    ; cveGraphSegmentationProcessImage using cv::Mat instead of _*Array
    _cveGraphSegmentationProcessImageTyped($segmentation, "Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveGraphSegmentationProcessImageMat

Func _cveGraphSegmentationRelease($segmentation, $sharedPtr)
    ; CVAPI(void) cveGraphSegmentationRelease(cv::ximgproc::segmentation::GraphSegmentation** segmentation, cv::Ptr<cv::ximgproc::segmentation::GraphSegmentation>** sharedPtr);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    ElseIf $segmentation == Null Then
        $sSegmentationDllType = "ptr"
    Else
        $sSegmentationDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphSegmentationRelease", $sSegmentationDllType, $segmentation, $sSharedPtrDllType, $sharedPtr), "cveGraphSegmentationRelease", @error)
EndFunc   ;==>_cveGraphSegmentationRelease

Func _cveWeightedMedianFilter($joint, $src, $dst, $r, $sigma = 25.5, $weightType = $CV_WMF_EXP, $mask = _cveNoArray())
    ; CVAPI(void) cveWeightedMedianFilter(cv::_InputArray* joint, cv::_InputArray* src, cv::_OutputArray* dst, int r, double sigma, cv::ximgproc::WMFWeightType weightType, cv::Mat* mask);

    Local $sJointDllType
    If IsDllStruct($joint) Then
        $sJointDllType = "struct*"
    Else
        $sJointDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWeightedMedianFilter", $sJointDllType, $joint, $sSrcDllType, $src, $sDstDllType, $dst, "int", $r, "double", $sigma, "int", $weightType, $sMaskDllType, $mask), "cveWeightedMedianFilter", @error)
EndFunc   ;==>_cveWeightedMedianFilter

Func _cveWeightedMedianFilterTyped($typeOfJoint, $joint, $typeOfSrc, $src, $typeOfDst, $dst, $r, $sigma = 25.5, $weightType = $CV_WMF_EXP, $mask = _cveNoArray())

    Local $iArrJoint, $vectorJoint, $iArrJointSize
    Local $bJointIsArray = IsArray($joint)
    Local $bJointCreate = IsDllStruct($joint) And $typeOfJoint == "Scalar"

    If $typeOfJoint == Default Then
        $iArrJoint = $joint
    ElseIf $bJointIsArray Then
        $vectorJoint = Call("_VectorOf" & $typeOfJoint & "Create")

        $iArrJointSize = UBound($joint)
        For $i = 0 To $iArrJointSize - 1
            Call("_VectorOf" & $typeOfJoint & "Push", $vectorJoint, $joint[$i])
        Next

        $iArrJoint = Call("_cveInputArrayFromVectorOf" & $typeOfJoint, $vectorJoint)
    Else
        If $bJointCreate Then
            $joint = Call("_cve" & $typeOfJoint & "Create", $joint)
        EndIf
        $iArrJoint = Call("_cveInputArrayFrom" & $typeOfJoint, $joint)
    EndIf

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveWeightedMedianFilter($iArrJoint, $iArrSrc, $oArrDst, $r, $sigma, $weightType, $mask)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    If $bJointIsArray Then
        Call("_VectorOf" & $typeOfJoint & "Release", $vectorJoint)
    EndIf

    If $typeOfJoint <> Default Then
        _cveInputArrayRelease($iArrJoint)
        If $bJointCreate Then
            Call("_cve" & $typeOfJoint & "Release", $joint)
        EndIf
    EndIf
EndFunc   ;==>_cveWeightedMedianFilterTyped

Func _cveWeightedMedianFilterMat($joint, $src, $dst, $r, $sigma = 25.5, $weightType = $CV_WMF_EXP, $mask = _cveNoArrayMat())
    ; cveWeightedMedianFilter using cv::Mat instead of _*Array
    _cveWeightedMedianFilterTyped("Mat", $joint, "Mat", $src, "Mat", $dst, $r, $sigma, $weightType, $mask)
EndFunc   ;==>_cveWeightedMedianFilterMat

Func _cveSelectiveSearchSegmentationCreate($sharedPtr)
    ; CVAPI(cv::ximgproc::segmentation::SelectiveSearchSegmentation*) cveSelectiveSearchSegmentationCreate(cv::Ptr<cv::ximgproc::segmentation::SelectiveSearchSegmentation>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSelectiveSearchSegmentationCreate", $sSharedPtrDllType, $sharedPtr), "cveSelectiveSearchSegmentationCreate", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationCreate

Func _cveSelectiveSearchSegmentationSetBaseImage($segmentation, $image)
    ; CVAPI(void) cveSelectiveSearchSegmentationSetBaseImage(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, cv::_InputArray* image);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSetBaseImage", $sSegmentationDllType, $segmentation, $sImageDllType, $image), "cveSelectiveSearchSegmentationSetBaseImage", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSetBaseImage

Func _cveSelectiveSearchSegmentationSetBaseImageTyped($segmentation, $typeOfImage, $image)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    _cveSelectiveSearchSegmentationSetBaseImage($segmentation, $iArrImage)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveSelectiveSearchSegmentationSetBaseImageTyped

Func _cveSelectiveSearchSegmentationSetBaseImageMat($segmentation, $image)
    ; cveSelectiveSearchSegmentationSetBaseImage using cv::Mat instead of _*Array
    _cveSelectiveSearchSegmentationSetBaseImageTyped($segmentation, "Mat", $image)
EndFunc   ;==>_cveSelectiveSearchSegmentationSetBaseImageMat

Func _cveSelectiveSearchSegmentationSwitchToSingleStrategy($segmentation, $k, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSingleStrategy(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int k, float sigma);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSingleStrategy", $sSegmentationDllType, $segmentation, "int", $k, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSingleStrategy", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSingleStrategy

Func _cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast($segmentation, $baseK, $incK, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int baseK, int incK, float sigma);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast", $sSegmentationDllType, $segmentation, "int", $baseK, "int", $incK, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSelectiveSearchFast

Func _cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality($segmentation, $baseK, $incK, $sigma)
    ; CVAPI(void) cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, int baseK, int incK, float sigma);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality", $sSegmentationDllType, $segmentation, "int", $baseK, "int", $incK, "float", $sigma), "cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationSwitchToSelectiveSearchQuality

Func _cveSelectiveSearchSegmentationAddImage($segmentation, $img)
    ; CVAPI(void) cveSelectiveSearchSegmentationAddImage(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, cv::_InputArray* img);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationAddImage", $sSegmentationDllType, $segmentation, $sImgDllType, $img), "cveSelectiveSearchSegmentationAddImage", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationAddImage

Func _cveSelectiveSearchSegmentationAddImageTyped($segmentation, $typeOfImg, $img)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveSelectiveSearchSegmentationAddImage($segmentation, $iArrImg)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveSelectiveSearchSegmentationAddImageTyped

Func _cveSelectiveSearchSegmentationAddImageMat($segmentation, $img)
    ; cveSelectiveSearchSegmentationAddImage using cv::Mat instead of _*Array
    _cveSelectiveSearchSegmentationAddImageTyped($segmentation, "Mat", $img)
EndFunc   ;==>_cveSelectiveSearchSegmentationAddImageMat

Func _cveSelectiveSearchSegmentationProcess($segmentation, $rects)
    ; CVAPI(void) cveSelectiveSearchSegmentationProcess(cv::ximgproc::segmentation::SelectiveSearchSegmentation* segmentation, std::vector<cv::Rect>* rects);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    Else
        $sSegmentationDllType = "ptr"
    EndIf

    Local $vecRects, $iArrRectsSize
    Local $bRectsIsArray = IsArray($rects)

    If $bRectsIsArray Then
        $vecRects = _VectorOfRectCreate()

        $iArrRectsSize = UBound($rects)
        For $i = 0 To $iArrRectsSize - 1
            _VectorOfRectPush($vecRects, $rects[$i])
        Next
    Else
        $vecRects = $rects
    EndIf

    Local $sRectsDllType
    If IsDllStruct($rects) Then
        $sRectsDllType = "struct*"
    Else
        $sRectsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationProcess", $sSegmentationDllType, $segmentation, $sRectsDllType, $vecRects), "cveSelectiveSearchSegmentationProcess", @error)

    If $bRectsIsArray Then
        _VectorOfRectRelease($vecRects)
    EndIf
EndFunc   ;==>_cveSelectiveSearchSegmentationProcess

Func _cveSelectiveSearchSegmentationRelease($segmentation, $sharedPtr)
    ; CVAPI(void) cveSelectiveSearchSegmentationRelease(cv::ximgproc::segmentation::SelectiveSearchSegmentation** segmentation, cv::Ptr<cv::ximgproc::segmentation::SelectiveSearchSegmentation>** sharedPtr);

    Local $sSegmentationDllType
    If IsDllStruct($segmentation) Then
        $sSegmentationDllType = "struct*"
    ElseIf $segmentation == Null Then
        $sSegmentationDllType = "ptr"
    Else
        $sSegmentationDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectiveSearchSegmentationRelease", $sSegmentationDllType, $segmentation, $sSharedPtrDllType, $sharedPtr), "cveSelectiveSearchSegmentationRelease", @error)
EndFunc   ;==>_cveSelectiveSearchSegmentationRelease

Func _cveGradientPaillouY($op, $dst, $alpha, $omega)
    ; CVAPI(void) cveGradientPaillouY(cv::_InputArray* op, cv::_OutputArray* dst, double alpha, double omega);

    Local $sOpDllType
    If IsDllStruct($op) Then
        $sOpDllType = "struct*"
    Else
        $sOpDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientPaillouY", $sOpDllType, $op, $sDstDllType, $dst, "double", $alpha, "double", $omega), "cveGradientPaillouY", @error)
EndFunc   ;==>_cveGradientPaillouY

Func _cveGradientPaillouYTyped($typeOfOp, $op, $typeOfDst, $dst, $alpha, $omega)

    Local $iArrOp, $vectorOp, $iArrOpSize
    Local $bOpIsArray = IsArray($op)
    Local $bOpCreate = IsDllStruct($op) And $typeOfOp == "Scalar"

    If $typeOfOp == Default Then
        $iArrOp = $op
    ElseIf $bOpIsArray Then
        $vectorOp = Call("_VectorOf" & $typeOfOp & "Create")

        $iArrOpSize = UBound($op)
        For $i = 0 To $iArrOpSize - 1
            Call("_VectorOf" & $typeOfOp & "Push", $vectorOp, $op[$i])
        Next

        $iArrOp = Call("_cveInputArrayFromVectorOf" & $typeOfOp, $vectorOp)
    Else
        If $bOpCreate Then
            $op = Call("_cve" & $typeOfOp & "Create", $op)
        EndIf
        $iArrOp = Call("_cveInputArrayFrom" & $typeOfOp, $op)
    EndIf

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

    _cveGradientPaillouY($iArrOp, $oArrDst, $alpha, $omega)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bOpIsArray Then
        Call("_VectorOf" & $typeOfOp & "Release", $vectorOp)
    EndIf

    If $typeOfOp <> Default Then
        _cveInputArrayRelease($iArrOp)
        If $bOpCreate Then
            Call("_cve" & $typeOfOp & "Release", $op)
        EndIf
    EndIf
EndFunc   ;==>_cveGradientPaillouYTyped

Func _cveGradientPaillouYMat($op, $dst, $alpha, $omega)
    ; cveGradientPaillouY using cv::Mat instead of _*Array
    _cveGradientPaillouYTyped("Mat", $op, "Mat", $dst, $alpha, $omega)
EndFunc   ;==>_cveGradientPaillouYMat

Func _cveGradientPaillouX($op, $dst, $alpha, $omega)
    ; CVAPI(void) cveGradientPaillouX(cv::_InputArray* op, cv::_OutputArray* dst, double alpha, double omega);

    Local $sOpDllType
    If IsDllStruct($op) Then
        $sOpDllType = "struct*"
    Else
        $sOpDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientPaillouX", $sOpDllType, $op, $sDstDllType, $dst, "double", $alpha, "double", $omega), "cveGradientPaillouX", @error)
EndFunc   ;==>_cveGradientPaillouX

Func _cveGradientPaillouXTyped($typeOfOp, $op, $typeOfDst, $dst, $alpha, $omega)

    Local $iArrOp, $vectorOp, $iArrOpSize
    Local $bOpIsArray = IsArray($op)
    Local $bOpCreate = IsDllStruct($op) And $typeOfOp == "Scalar"

    If $typeOfOp == Default Then
        $iArrOp = $op
    ElseIf $bOpIsArray Then
        $vectorOp = Call("_VectorOf" & $typeOfOp & "Create")

        $iArrOpSize = UBound($op)
        For $i = 0 To $iArrOpSize - 1
            Call("_VectorOf" & $typeOfOp & "Push", $vectorOp, $op[$i])
        Next

        $iArrOp = Call("_cveInputArrayFromVectorOf" & $typeOfOp, $vectorOp)
    Else
        If $bOpCreate Then
            $op = Call("_cve" & $typeOfOp & "Create", $op)
        EndIf
        $iArrOp = Call("_cveInputArrayFrom" & $typeOfOp, $op)
    EndIf

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

    _cveGradientPaillouX($iArrOp, $oArrDst, $alpha, $omega)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bOpIsArray Then
        Call("_VectorOf" & $typeOfOp & "Release", $vectorOp)
    EndIf

    If $typeOfOp <> Default Then
        _cveInputArrayRelease($iArrOp)
        If $bOpCreate Then
            Call("_cve" & $typeOfOp & "Release", $op)
        EndIf
    EndIf
EndFunc   ;==>_cveGradientPaillouXTyped

Func _cveGradientPaillouXMat($op, $dst, $alpha, $omega)
    ; cveGradientPaillouX using cv::Mat instead of _*Array
    _cveGradientPaillouXTyped("Mat", $op, "Mat", $dst, $alpha, $omega)
EndFunc   ;==>_cveGradientPaillouXMat

Func _cveGradientDericheY($op, $dst, $alphaDerive, $alphaMean)
    ; CVAPI(void) cveGradientDericheY(cv::_InputArray* op, cv::_OutputArray* dst, double alphaDerive, double alphaMean);

    Local $sOpDllType
    If IsDllStruct($op) Then
        $sOpDllType = "struct*"
    Else
        $sOpDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientDericheY", $sOpDllType, $op, $sDstDllType, $dst, "double", $alphaDerive, "double", $alphaMean), "cveGradientDericheY", @error)
EndFunc   ;==>_cveGradientDericheY

Func _cveGradientDericheYTyped($typeOfOp, $op, $typeOfDst, $dst, $alphaDerive, $alphaMean)

    Local $iArrOp, $vectorOp, $iArrOpSize
    Local $bOpIsArray = IsArray($op)
    Local $bOpCreate = IsDllStruct($op) And $typeOfOp == "Scalar"

    If $typeOfOp == Default Then
        $iArrOp = $op
    ElseIf $bOpIsArray Then
        $vectorOp = Call("_VectorOf" & $typeOfOp & "Create")

        $iArrOpSize = UBound($op)
        For $i = 0 To $iArrOpSize - 1
            Call("_VectorOf" & $typeOfOp & "Push", $vectorOp, $op[$i])
        Next

        $iArrOp = Call("_cveInputArrayFromVectorOf" & $typeOfOp, $vectorOp)
    Else
        If $bOpCreate Then
            $op = Call("_cve" & $typeOfOp & "Create", $op)
        EndIf
        $iArrOp = Call("_cveInputArrayFrom" & $typeOfOp, $op)
    EndIf

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

    _cveGradientDericheY($iArrOp, $oArrDst, $alphaDerive, $alphaMean)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bOpIsArray Then
        Call("_VectorOf" & $typeOfOp & "Release", $vectorOp)
    EndIf

    If $typeOfOp <> Default Then
        _cveInputArrayRelease($iArrOp)
        If $bOpCreate Then
            Call("_cve" & $typeOfOp & "Release", $op)
        EndIf
    EndIf
EndFunc   ;==>_cveGradientDericheYTyped

Func _cveGradientDericheYMat($op, $dst, $alphaDerive, $alphaMean)
    ; cveGradientDericheY using cv::Mat instead of _*Array
    _cveGradientDericheYTyped("Mat", $op, "Mat", $dst, $alphaDerive, $alphaMean)
EndFunc   ;==>_cveGradientDericheYMat

Func _cveGradientDericheX($op, $dst, $alphaDerive, $alphaMean)
    ; CVAPI(void) cveGradientDericheX(cv::_InputArray* op, cv::_OutputArray* dst, double alphaDerive, double alphaMean);

    Local $sOpDllType
    If IsDllStruct($op) Then
        $sOpDllType = "struct*"
    Else
        $sOpDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGradientDericheX", $sOpDllType, $op, $sDstDllType, $dst, "double", $alphaDerive, "double", $alphaMean), "cveGradientDericheX", @error)
EndFunc   ;==>_cveGradientDericheX

Func _cveGradientDericheXTyped($typeOfOp, $op, $typeOfDst, $dst, $alphaDerive, $alphaMean)

    Local $iArrOp, $vectorOp, $iArrOpSize
    Local $bOpIsArray = IsArray($op)
    Local $bOpCreate = IsDllStruct($op) And $typeOfOp == "Scalar"

    If $typeOfOp == Default Then
        $iArrOp = $op
    ElseIf $bOpIsArray Then
        $vectorOp = Call("_VectorOf" & $typeOfOp & "Create")

        $iArrOpSize = UBound($op)
        For $i = 0 To $iArrOpSize - 1
            Call("_VectorOf" & $typeOfOp & "Push", $vectorOp, $op[$i])
        Next

        $iArrOp = Call("_cveInputArrayFromVectorOf" & $typeOfOp, $vectorOp)
    Else
        If $bOpCreate Then
            $op = Call("_cve" & $typeOfOp & "Create", $op)
        EndIf
        $iArrOp = Call("_cveInputArrayFrom" & $typeOfOp, $op)
    EndIf

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

    _cveGradientDericheX($iArrOp, $oArrDst, $alphaDerive, $alphaMean)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bOpIsArray Then
        Call("_VectorOf" & $typeOfOp & "Release", $vectorOp)
    EndIf

    If $typeOfOp <> Default Then
        _cveInputArrayRelease($iArrOp)
        If $bOpCreate Then
            Call("_cve" & $typeOfOp & "Release", $op)
        EndIf
    EndIf
EndFunc   ;==>_cveGradientDericheXTyped

Func _cveGradientDericheXMat($op, $dst, $alphaDerive, $alphaMean)
    ; cveGradientDericheX using cv::Mat instead of _*Array
    _cveGradientDericheXTyped("Mat", $op, "Mat", $dst, $alphaDerive, $alphaMean)
EndFunc   ;==>_cveGradientDericheXMat

Func _cveThinning($src, $dst, $thinningType = $CV_THINNING_ZHANGSUEN)
    ; CVAPI(void) cveThinning(cv::_InputArray* src, cv::_OutputArray* dst, int thinningType);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveThinning", $sSrcDllType, $src, $sDstDllType, $dst, "int", $thinningType), "cveThinning", @error)
EndFunc   ;==>_cveThinning

Func _cveThinningTyped($typeOfSrc, $src, $typeOfDst, $dst, $thinningType = $CV_THINNING_ZHANGSUEN)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveThinning($iArrSrc, $oArrDst, $thinningType)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveThinningTyped

Func _cveThinningMat($src, $dst, $thinningType = $CV_THINNING_ZHANGSUEN)
    ; cveThinning using cv::Mat instead of _*Array
    _cveThinningTyped("Mat", $src, "Mat", $dst, $thinningType)
EndFunc   ;==>_cveThinningMat

Func _cveAnisotropicDiffusion($src, $dst, $alpha, $K, $niters)
    ; CVAPI(void) cveAnisotropicDiffusion(cv::_InputArray* src, cv::_OutputArray* dst, float alpha, float K, int niters);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAnisotropicDiffusion", $sSrcDllType, $src, $sDstDllType, $dst, "float", $alpha, "float", $K, "int", $niters), "cveAnisotropicDiffusion", @error)
EndFunc   ;==>_cveAnisotropicDiffusion

Func _cveAnisotropicDiffusionTyped($typeOfSrc, $src, $typeOfDst, $dst, $alpha, $K, $niters)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

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

    _cveAnisotropicDiffusion($iArrSrc, $oArrDst, $alpha, $K, $niters)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveAnisotropicDiffusionTyped

Func _cveAnisotropicDiffusionMat($src, $dst, $alpha, $K, $niters)
    ; cveAnisotropicDiffusion using cv::Mat instead of _*Array
    _cveAnisotropicDiffusionTyped("Mat", $src, "Mat", $dst, $alpha, $K, $niters)
EndFunc   ;==>_cveAnisotropicDiffusionMat

Func _cveFastLineDetectorCreate($length_threshold, $distance_threshold, $canny_th1, $canny_th2, $canny_aperture_size, $do_merge, $sharedPtr)
    ; CVAPI(cv::ximgproc::FastLineDetector*) cveFastLineDetectorCreate(int length_threshold, float distance_threshold, double canny_th1, double canny_th2, int canny_aperture_size, bool do_merge, cv::Ptr<cv::ximgproc::FastLineDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFastLineDetectorCreate", "int", $length_threshold, "float", $distance_threshold, "double", $canny_th1, "double", $canny_th2, "int", $canny_aperture_size, "boolean", $do_merge, $sSharedPtrDllType, $sharedPtr), "cveFastLineDetectorCreate", @error)
EndFunc   ;==>_cveFastLineDetectorCreate

Func _cveFastLineDetectorDetect($fld, $image, $lines)
    ; CVAPI(void) cveFastLineDetectorDetect(cv::ximgproc::FastLineDetector* fld, cv::_InputArray* image, cv::_OutputArray* lines);

    Local $sFldDllType
    If IsDllStruct($fld) Then
        $sFldDllType = "struct*"
    Else
        $sFldDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorDetect", $sFldDllType, $fld, $sImageDllType, $image, $sLinesDllType, $lines), "cveFastLineDetectorDetect", @error)
EndFunc   ;==>_cveFastLineDetectorDetect

Func _cveFastLineDetectorDetectTyped($fld, $typeOfImage, $image, $typeOfLines, $lines)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $oArrLines, $vectorLines, $iArrLinesSize
    Local $bLinesIsArray = IsArray($lines)
    Local $bLinesCreate = IsDllStruct($lines) And $typeOfLines == "Scalar"

    If $typeOfLines == Default Then
        $oArrLines = $lines
    ElseIf $bLinesIsArray Then
        $vectorLines = Call("_VectorOf" & $typeOfLines & "Create")

        $iArrLinesSize = UBound($lines)
        For $i = 0 To $iArrLinesSize - 1
            Call("_VectorOf" & $typeOfLines & "Push", $vectorLines, $lines[$i])
        Next

        $oArrLines = Call("_cveOutputArrayFromVectorOf" & $typeOfLines, $vectorLines)
    Else
        If $bLinesCreate Then
            $lines = Call("_cve" & $typeOfLines & "Create", $lines)
        EndIf
        $oArrLines = Call("_cveOutputArrayFrom" & $typeOfLines, $lines)
    EndIf

    _cveFastLineDetectorDetect($fld, $iArrImage, $oArrLines)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveFastLineDetectorDetectTyped

Func _cveFastLineDetectorDetectMat($fld, $image, $lines)
    ; cveFastLineDetectorDetect using cv::Mat instead of _*Array
    _cveFastLineDetectorDetectTyped($fld, "Mat", $image, "Mat", $lines)
EndFunc   ;==>_cveFastLineDetectorDetectMat

Func _cveFastLineDetectorDrawSegments($fld, $image, $lines, $draw_arrow)
    ; CVAPI(void) cveFastLineDetectorDrawSegments(cv::ximgproc::FastLineDetector* fld, cv::_InputOutputArray* image, cv::_InputArray* lines, bool draw_arrow);

    Local $sFldDllType
    If IsDllStruct($fld) Then
        $sFldDllType = "struct*"
    Else
        $sFldDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorDrawSegments", $sFldDllType, $fld, $sImageDllType, $image, $sLinesDllType, $lines, "boolean", $draw_arrow), "cveFastLineDetectorDrawSegments", @error)
EndFunc   ;==>_cveFastLineDetectorDrawSegments

Func _cveFastLineDetectorDrawSegmentsTyped($fld, $typeOfImage, $image, $typeOfLines, $lines, $draw_arrow)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrLines, $vectorLines, $iArrLinesSize
    Local $bLinesIsArray = IsArray($lines)
    Local $bLinesCreate = IsDllStruct($lines) And $typeOfLines == "Scalar"

    If $typeOfLines == Default Then
        $iArrLines = $lines
    ElseIf $bLinesIsArray Then
        $vectorLines = Call("_VectorOf" & $typeOfLines & "Create")

        $iArrLinesSize = UBound($lines)
        For $i = 0 To $iArrLinesSize - 1
            Call("_VectorOf" & $typeOfLines & "Push", $vectorLines, $lines[$i])
        Next

        $iArrLines = Call("_cveInputArrayFromVectorOf" & $typeOfLines, $vectorLines)
    Else
        If $bLinesCreate Then
            $lines = Call("_cve" & $typeOfLines & "Create", $lines)
        EndIf
        $iArrLines = Call("_cveInputArrayFrom" & $typeOfLines, $lines)
    EndIf

    _cveFastLineDetectorDrawSegments($fld, $ioArrImage, $iArrLines, $draw_arrow)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveInputArrayRelease($iArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveFastLineDetectorDrawSegmentsTyped

Func _cveFastLineDetectorDrawSegmentsMat($fld, $image, $lines, $draw_arrow)
    ; cveFastLineDetectorDrawSegments using cv::Mat instead of _*Array
    _cveFastLineDetectorDrawSegmentsTyped($fld, "Mat", $image, "Mat", $lines, $draw_arrow)
EndFunc   ;==>_cveFastLineDetectorDrawSegmentsMat

Func _cveFastLineDetectorRelease($fld)
    ; CVAPI(void) cveFastLineDetectorRelease(cv::Ptr<cv::ximgproc::FastLineDetector>** fld);

    Local $sFldDllType
    If IsDllStruct($fld) Then
        $sFldDllType = "struct*"
    ElseIf $fld == Null Then
        $sFldDllType = "ptr"
    Else
        $sFldDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastLineDetectorRelease", $sFldDllType, $fld), "cveFastLineDetectorRelease", @error)
EndFunc   ;==>_cveFastLineDetectorRelease

Func _cveBrightEdges($original, $edgeview, $contrast, $shortrange, $longrange)
    ; CVAPI(void) cveBrightEdges(cv::Mat* original, cv::Mat* edgeview, int contrast, int shortrange, int longrange);

    Local $sOriginalDllType
    If IsDllStruct($original) Then
        $sOriginalDllType = "struct*"
    Else
        $sOriginalDllType = "ptr"
    EndIf

    Local $sEdgeviewDllType
    If IsDllStruct($edgeview) Then
        $sEdgeviewDllType = "struct*"
    Else
        $sEdgeviewDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBrightEdges", $sOriginalDllType, $original, $sEdgeviewDllType, $edgeview, "int", $contrast, "int", $shortrange, "int", $longrange), "cveBrightEdges", @error)
EndFunc   ;==>_cveBrightEdges

Func _cveCreateDisparityWLSFilter($matcherLeft, $disparityFilter, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::DisparityWLSFilter*) cveCreateDisparityWLSFilter(cv::StereoMatcher* matcherLeft, cv::ximgproc::DisparityFilter** disparityFilter, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);

    Local $sMatcherLeftDllType
    If IsDllStruct($matcherLeft) Then
        $sMatcherLeftDllType = "struct*"
    Else
        $sMatcherLeftDllType = "ptr"
    EndIf

    Local $sDisparityFilterDllType
    If IsDllStruct($disparityFilter) Then
        $sDisparityFilterDllType = "struct*"
    ElseIf $disparityFilter == Null Then
        $sDisparityFilterDllType = "ptr"
    Else
        $sDisparityFilterDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateDisparityWLSFilter", $sMatcherLeftDllType, $matcherLeft, $sDisparityFilterDllType, $disparityFilter, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveCreateDisparityWLSFilter", @error)
EndFunc   ;==>_cveCreateDisparityWLSFilter

Func _cveCreateRightMatcher($matcherLeft, $sharedPtr)
    ; CVAPI(cv::StereoMatcher*) cveCreateRightMatcher(cv::StereoMatcher* matcherLeft, cv::Ptr<cv::StereoMatcher>** sharedPtr);

    Local $sMatcherLeftDllType
    If IsDllStruct($matcherLeft) Then
        $sMatcherLeftDllType = "struct*"
    Else
        $sMatcherLeftDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateRightMatcher", $sMatcherLeftDllType, $matcherLeft, $sSharedPtrDllType, $sharedPtr), "cveCreateRightMatcher", @error)
EndFunc   ;==>_cveCreateRightMatcher

Func _cveCreateDisparityWLSFilterGeneric($use_confidence, $disparityFilter, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::DisparityWLSFilter*) cveCreateDisparityWLSFilterGeneric(bool use_confidence, cv::ximgproc::DisparityFilter** disparityFilter, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);

    Local $sDisparityFilterDllType
    If IsDllStruct($disparityFilter) Then
        $sDisparityFilterDllType = "struct*"
    ElseIf $disparityFilter == Null Then
        $sDisparityFilterDllType = "ptr"
    Else
        $sDisparityFilterDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCreateDisparityWLSFilterGeneric", "boolean", $use_confidence, $sDisparityFilterDllType, $disparityFilter, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveCreateDisparityWLSFilterGeneric", @error)
EndFunc   ;==>_cveCreateDisparityWLSFilterGeneric

Func _cveDisparityWLSFilterRelease($sharedPtr)
    ; CVAPI(void) cveDisparityWLSFilterRelease(cv::Ptr<cv::ximgproc::DisparityWLSFilter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDisparityWLSFilterRelease", $sSharedPtrDllType, $sharedPtr), "cveDisparityWLSFilterRelease", @error)
EndFunc   ;==>_cveDisparityWLSFilterRelease

Func _cveDisparityFilterFilter($disparityFilter, $disparity_map_left, $left_view, $filtered_disparity_map, $disparity_map_right, $ROI, $right_view)
    ; CVAPI(void) cveDisparityFilterFilter(cv::ximgproc::DisparityFilter* disparityFilter, cv::_InputArray* disparity_map_left, cv::_InputArray* left_view, cv::_OutputArray* filtered_disparity_map, cv::_InputArray* disparity_map_right, CvRect* ROI, cv::_InputArray* right_view);

    Local $sDisparityFilterDllType
    If IsDllStruct($disparityFilter) Then
        $sDisparityFilterDllType = "struct*"
    Else
        $sDisparityFilterDllType = "ptr"
    EndIf

    Local $sDisparity_map_leftDllType
    If IsDllStruct($disparity_map_left) Then
        $sDisparity_map_leftDllType = "struct*"
    Else
        $sDisparity_map_leftDllType = "ptr"
    EndIf

    Local $sLeft_viewDllType
    If IsDllStruct($left_view) Then
        $sLeft_viewDllType = "struct*"
    Else
        $sLeft_viewDllType = "ptr"
    EndIf

    Local $sFiltered_disparity_mapDllType
    If IsDllStruct($filtered_disparity_map) Then
        $sFiltered_disparity_mapDllType = "struct*"
    Else
        $sFiltered_disparity_mapDllType = "ptr"
    EndIf

    Local $sDisparity_map_rightDllType
    If IsDllStruct($disparity_map_right) Then
        $sDisparity_map_rightDllType = "struct*"
    Else
        $sDisparity_map_rightDllType = "ptr"
    EndIf

    Local $sROIDllType
    If IsDllStruct($ROI) Then
        $sROIDllType = "struct*"
    Else
        $sROIDllType = "ptr"
    EndIf

    Local $sRight_viewDllType
    If IsDllStruct($right_view) Then
        $sRight_viewDllType = "struct*"
    Else
        $sRight_viewDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDisparityFilterFilter", $sDisparityFilterDllType, $disparityFilter, $sDisparity_map_leftDllType, $disparity_map_left, $sLeft_viewDllType, $left_view, $sFiltered_disparity_mapDllType, $filtered_disparity_map, $sDisparity_map_rightDllType, $disparity_map_right, $sROIDllType, $ROI, $sRight_viewDllType, $right_view), "cveDisparityFilterFilter", @error)
EndFunc   ;==>_cveDisparityFilterFilter

Func _cveDisparityFilterFilterTyped($disparityFilter, $typeOfDisparity_map_left, $disparity_map_left, $typeOfLeft_view, $left_view, $typeOfFiltered_disparity_map, $filtered_disparity_map, $typeOfDisparity_map_right, $disparity_map_right, $ROI, $typeOfRight_view, $right_view)

    Local $iArrDisparity_map_left, $vectorDisparity_map_left, $iArrDisparity_map_leftSize
    Local $bDisparity_map_leftIsArray = IsArray($disparity_map_left)
    Local $bDisparity_map_leftCreate = IsDllStruct($disparity_map_left) And $typeOfDisparity_map_left == "Scalar"

    If $typeOfDisparity_map_left == Default Then
        $iArrDisparity_map_left = $disparity_map_left
    ElseIf $bDisparity_map_leftIsArray Then
        $vectorDisparity_map_left = Call("_VectorOf" & $typeOfDisparity_map_left & "Create")

        $iArrDisparity_map_leftSize = UBound($disparity_map_left)
        For $i = 0 To $iArrDisparity_map_leftSize - 1
            Call("_VectorOf" & $typeOfDisparity_map_left & "Push", $vectorDisparity_map_left, $disparity_map_left[$i])
        Next

        $iArrDisparity_map_left = Call("_cveInputArrayFromVectorOf" & $typeOfDisparity_map_left, $vectorDisparity_map_left)
    Else
        If $bDisparity_map_leftCreate Then
            $disparity_map_left = Call("_cve" & $typeOfDisparity_map_left & "Create", $disparity_map_left)
        EndIf
        $iArrDisparity_map_left = Call("_cveInputArrayFrom" & $typeOfDisparity_map_left, $disparity_map_left)
    EndIf

    Local $iArrLeft_view, $vectorLeft_view, $iArrLeft_viewSize
    Local $bLeft_viewIsArray = IsArray($left_view)
    Local $bLeft_viewCreate = IsDllStruct($left_view) And $typeOfLeft_view == "Scalar"

    If $typeOfLeft_view == Default Then
        $iArrLeft_view = $left_view
    ElseIf $bLeft_viewIsArray Then
        $vectorLeft_view = Call("_VectorOf" & $typeOfLeft_view & "Create")

        $iArrLeft_viewSize = UBound($left_view)
        For $i = 0 To $iArrLeft_viewSize - 1
            Call("_VectorOf" & $typeOfLeft_view & "Push", $vectorLeft_view, $left_view[$i])
        Next

        $iArrLeft_view = Call("_cveInputArrayFromVectorOf" & $typeOfLeft_view, $vectorLeft_view)
    Else
        If $bLeft_viewCreate Then
            $left_view = Call("_cve" & $typeOfLeft_view & "Create", $left_view)
        EndIf
        $iArrLeft_view = Call("_cveInputArrayFrom" & $typeOfLeft_view, $left_view)
    EndIf

    Local $oArrFiltered_disparity_map, $vectorFiltered_disparity_map, $iArrFiltered_disparity_mapSize
    Local $bFiltered_disparity_mapIsArray = IsArray($filtered_disparity_map)
    Local $bFiltered_disparity_mapCreate = IsDllStruct($filtered_disparity_map) And $typeOfFiltered_disparity_map == "Scalar"

    If $typeOfFiltered_disparity_map == Default Then
        $oArrFiltered_disparity_map = $filtered_disparity_map
    ElseIf $bFiltered_disparity_mapIsArray Then
        $vectorFiltered_disparity_map = Call("_VectorOf" & $typeOfFiltered_disparity_map & "Create")

        $iArrFiltered_disparity_mapSize = UBound($filtered_disparity_map)
        For $i = 0 To $iArrFiltered_disparity_mapSize - 1
            Call("_VectorOf" & $typeOfFiltered_disparity_map & "Push", $vectorFiltered_disparity_map, $filtered_disparity_map[$i])
        Next

        $oArrFiltered_disparity_map = Call("_cveOutputArrayFromVectorOf" & $typeOfFiltered_disparity_map, $vectorFiltered_disparity_map)
    Else
        If $bFiltered_disparity_mapCreate Then
            $filtered_disparity_map = Call("_cve" & $typeOfFiltered_disparity_map & "Create", $filtered_disparity_map)
        EndIf
        $oArrFiltered_disparity_map = Call("_cveOutputArrayFrom" & $typeOfFiltered_disparity_map, $filtered_disparity_map)
    EndIf

    Local $iArrDisparity_map_right, $vectorDisparity_map_right, $iArrDisparity_map_rightSize
    Local $bDisparity_map_rightIsArray = IsArray($disparity_map_right)
    Local $bDisparity_map_rightCreate = IsDllStruct($disparity_map_right) And $typeOfDisparity_map_right == "Scalar"

    If $typeOfDisparity_map_right == Default Then
        $iArrDisparity_map_right = $disparity_map_right
    ElseIf $bDisparity_map_rightIsArray Then
        $vectorDisparity_map_right = Call("_VectorOf" & $typeOfDisparity_map_right & "Create")

        $iArrDisparity_map_rightSize = UBound($disparity_map_right)
        For $i = 0 To $iArrDisparity_map_rightSize - 1
            Call("_VectorOf" & $typeOfDisparity_map_right & "Push", $vectorDisparity_map_right, $disparity_map_right[$i])
        Next

        $iArrDisparity_map_right = Call("_cveInputArrayFromVectorOf" & $typeOfDisparity_map_right, $vectorDisparity_map_right)
    Else
        If $bDisparity_map_rightCreate Then
            $disparity_map_right = Call("_cve" & $typeOfDisparity_map_right & "Create", $disparity_map_right)
        EndIf
        $iArrDisparity_map_right = Call("_cveInputArrayFrom" & $typeOfDisparity_map_right, $disparity_map_right)
    EndIf

    Local $iArrRight_view, $vectorRight_view, $iArrRight_viewSize
    Local $bRight_viewIsArray = IsArray($right_view)
    Local $bRight_viewCreate = IsDllStruct($right_view) And $typeOfRight_view == "Scalar"

    If $typeOfRight_view == Default Then
        $iArrRight_view = $right_view
    ElseIf $bRight_viewIsArray Then
        $vectorRight_view = Call("_VectorOf" & $typeOfRight_view & "Create")

        $iArrRight_viewSize = UBound($right_view)
        For $i = 0 To $iArrRight_viewSize - 1
            Call("_VectorOf" & $typeOfRight_view & "Push", $vectorRight_view, $right_view[$i])
        Next

        $iArrRight_view = Call("_cveInputArrayFromVectorOf" & $typeOfRight_view, $vectorRight_view)
    Else
        If $bRight_viewCreate Then
            $right_view = Call("_cve" & $typeOfRight_view & "Create", $right_view)
        EndIf
        $iArrRight_view = Call("_cveInputArrayFrom" & $typeOfRight_view, $right_view)
    EndIf

    _cveDisparityFilterFilter($disparityFilter, $iArrDisparity_map_left, $iArrLeft_view, $oArrFiltered_disparity_map, $iArrDisparity_map_right, $ROI, $iArrRight_view)

    If $bRight_viewIsArray Then
        Call("_VectorOf" & $typeOfRight_view & "Release", $vectorRight_view)
    EndIf

    If $typeOfRight_view <> Default Then
        _cveInputArrayRelease($iArrRight_view)
        If $bRight_viewCreate Then
            Call("_cve" & $typeOfRight_view & "Release", $right_view)
        EndIf
    EndIf

    If $bDisparity_map_rightIsArray Then
        Call("_VectorOf" & $typeOfDisparity_map_right & "Release", $vectorDisparity_map_right)
    EndIf

    If $typeOfDisparity_map_right <> Default Then
        _cveInputArrayRelease($iArrDisparity_map_right)
        If $bDisparity_map_rightCreate Then
            Call("_cve" & $typeOfDisparity_map_right & "Release", $disparity_map_right)
        EndIf
    EndIf

    If $bFiltered_disparity_mapIsArray Then
        Call("_VectorOf" & $typeOfFiltered_disparity_map & "Release", $vectorFiltered_disparity_map)
    EndIf

    If $typeOfFiltered_disparity_map <> Default Then
        _cveOutputArrayRelease($oArrFiltered_disparity_map)
        If $bFiltered_disparity_mapCreate Then
            Call("_cve" & $typeOfFiltered_disparity_map & "Release", $filtered_disparity_map)
        EndIf
    EndIf

    If $bLeft_viewIsArray Then
        Call("_VectorOf" & $typeOfLeft_view & "Release", $vectorLeft_view)
    EndIf

    If $typeOfLeft_view <> Default Then
        _cveInputArrayRelease($iArrLeft_view)
        If $bLeft_viewCreate Then
            Call("_cve" & $typeOfLeft_view & "Release", $left_view)
        EndIf
    EndIf

    If $bDisparity_map_leftIsArray Then
        Call("_VectorOf" & $typeOfDisparity_map_left & "Release", $vectorDisparity_map_left)
    EndIf

    If $typeOfDisparity_map_left <> Default Then
        _cveInputArrayRelease($iArrDisparity_map_left)
        If $bDisparity_map_leftCreate Then
            Call("_cve" & $typeOfDisparity_map_left & "Release", $disparity_map_left)
        EndIf
    EndIf
EndFunc   ;==>_cveDisparityFilterFilterTyped

Func _cveDisparityFilterFilterMat($disparityFilter, $disparity_map_left, $left_view, $filtered_disparity_map, $disparity_map_right, $ROI, $right_view)
    ; cveDisparityFilterFilter using cv::Mat instead of _*Array
    _cveDisparityFilterFilterTyped($disparityFilter, "Mat", $disparity_map_left, "Mat", $left_view, "Mat", $filtered_disparity_map, "Mat", $disparity_map_right, $ROI, "Mat", $right_view)
EndFunc   ;==>_cveDisparityFilterFilterMat

Func _cveRidgeDetectionFilterCreate($ddepth, $dx, $dy, $ksize, $outDtype, $scale, $delta, $borderType, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::RidgeDetectionFilter*) cveRidgeDetectionFilterCreate(int ddepth, int dx, int dy, int ksize, int outDtype, double scale, double delta, int borderType, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::RidgeDetectionFilter>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRidgeDetectionFilterCreate", "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "int", $outDtype, "double", $scale, "double", $delta, "int", $borderType, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveRidgeDetectionFilterCreate", @error)
EndFunc   ;==>_cveRidgeDetectionFilterCreate

Func _cveRidgeDetectionFilterRelease($sharedPtr)
    ; CVAPI(void) cveRidgeDetectionFilterRelease(cv::Ptr<cv::ximgproc::RidgeDetectionFilter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRidgeDetectionFilterRelease", $sSharedPtrDllType, $sharedPtr), "cveRidgeDetectionFilterRelease", @error)
EndFunc   ;==>_cveRidgeDetectionFilterRelease

Func _cveRidgeDetectionFilterGetRidgeFilteredImage($ridgeDetection, $img, $out)
    ; CVAPI(void) cveRidgeDetectionFilterGetRidgeFilteredImage(cv::ximgproc::RidgeDetectionFilter* ridgeDetection, cv::_InputArray* img, cv::_OutputArray* out);

    Local $sRidgeDetectionDllType
    If IsDllStruct($ridgeDetection) Then
        $sRidgeDetectionDllType = "struct*"
    Else
        $sRidgeDetectionDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sOutDllType
    If IsDllStruct($out) Then
        $sOutDllType = "struct*"
    Else
        $sOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRidgeDetectionFilterGetRidgeFilteredImage", $sRidgeDetectionDllType, $ridgeDetection, $sImgDllType, $img, $sOutDllType, $out), "cveRidgeDetectionFilterGetRidgeFilteredImage", @error)
EndFunc   ;==>_cveRidgeDetectionFilterGetRidgeFilteredImage

Func _cveRidgeDetectionFilterGetRidgeFilteredImageTyped($ridgeDetection, $typeOfImg, $img, $typeOfOut, $out)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $oArrOut, $vectorOut, $iArrOutSize
    Local $bOutIsArray = IsArray($out)
    Local $bOutCreate = IsDllStruct($out) And $typeOfOut == "Scalar"

    If $typeOfOut == Default Then
        $oArrOut = $out
    ElseIf $bOutIsArray Then
        $vectorOut = Call("_VectorOf" & $typeOfOut & "Create")

        $iArrOutSize = UBound($out)
        For $i = 0 To $iArrOutSize - 1
            Call("_VectorOf" & $typeOfOut & "Push", $vectorOut, $out[$i])
        Next

        $oArrOut = Call("_cveOutputArrayFromVectorOf" & $typeOfOut, $vectorOut)
    Else
        If $bOutCreate Then
            $out = Call("_cve" & $typeOfOut & "Create", $out)
        EndIf
        $oArrOut = Call("_cveOutputArrayFrom" & $typeOfOut, $out)
    EndIf

    _cveRidgeDetectionFilterGetRidgeFilteredImage($ridgeDetection, $iArrImg, $oArrOut)

    If $bOutIsArray Then
        Call("_VectorOf" & $typeOfOut & "Release", $vectorOut)
    EndIf

    If $typeOfOut <> Default Then
        _cveOutputArrayRelease($oArrOut)
        If $bOutCreate Then
            Call("_cve" & $typeOfOut & "Release", $out)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveRidgeDetectionFilterGetRidgeFilteredImageTyped

Func _cveRidgeDetectionFilterGetRidgeFilteredImageMat($ridgeDetection, $img, $out)
    ; cveRidgeDetectionFilterGetRidgeFilteredImage using cv::Mat instead of _*Array
    _cveRidgeDetectionFilterGetRidgeFilteredImageTyped($ridgeDetection, "Mat", $img, "Mat", $out)
EndFunc   ;==>_cveRidgeDetectionFilterGetRidgeFilteredImageMat

Func _cveEdgeBoxesCreate($alpha, $beta, $eta, $minScore, $maxBoxes, $edgeMinMag, $edgeMergeThr, $clusterMinMag, $maxAspectRatio, $minBoxArea, $gamma, $kappa, $algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::EdgeBoxes*) cveEdgeBoxesCreate(float alpha, float beta, float eta, float minScore, int maxBoxes, float edgeMinMag, float edgeMergeThr, float clusterMinMag, float maxAspectRatio, float minBoxArea, float gamma, float kappa, cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::EdgeBoxes>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEdgeBoxesCreate", "float", $alpha, "float", $beta, "float", $eta, "float", $minScore, "int", $maxBoxes, "float", $edgeMinMag, "float", $edgeMergeThr, "float", $clusterMinMag, "float", $maxAspectRatio, "float", $minBoxArea, "float", $gamma, "float", $kappa, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveEdgeBoxesCreate", @error)
EndFunc   ;==>_cveEdgeBoxesCreate

Func _cveEdgeBoxesGetBoundingBoxes($edgeBoxes, $edgeMap, $orientationMap, $boxes)
    ; CVAPI(void) cveEdgeBoxesGetBoundingBoxes(cv::ximgproc::EdgeBoxes* edgeBoxes, cv::_InputArray* edgeMap, cv::_InputArray* orientationMap, std::vector<cv::Rect>* boxes);

    Local $sEdgeBoxesDllType
    If IsDllStruct($edgeBoxes) Then
        $sEdgeBoxesDllType = "struct*"
    Else
        $sEdgeBoxesDllType = "ptr"
    EndIf

    Local $sEdgeMapDllType
    If IsDllStruct($edgeMap) Then
        $sEdgeMapDllType = "struct*"
    Else
        $sEdgeMapDllType = "ptr"
    EndIf

    Local $sOrientationMapDllType
    If IsDllStruct($orientationMap) Then
        $sOrientationMapDllType = "struct*"
    Else
        $sOrientationMapDllType = "ptr"
    EndIf

    Local $vecBoxes, $iArrBoxesSize
    Local $bBoxesIsArray = IsArray($boxes)

    If $bBoxesIsArray Then
        $vecBoxes = _VectorOfRectCreate()

        $iArrBoxesSize = UBound($boxes)
        For $i = 0 To $iArrBoxesSize - 1
            _VectorOfRectPush($vecBoxes, $boxes[$i])
        Next
    Else
        $vecBoxes = $boxes
    EndIf

    Local $sBoxesDllType
    If IsDllStruct($boxes) Then
        $sBoxesDllType = "struct*"
    Else
        $sBoxesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeBoxesGetBoundingBoxes", $sEdgeBoxesDllType, $edgeBoxes, $sEdgeMapDllType, $edgeMap, $sOrientationMapDllType, $orientationMap, $sBoxesDllType, $vecBoxes), "cveEdgeBoxesGetBoundingBoxes", @error)

    If $bBoxesIsArray Then
        _VectorOfRectRelease($vecBoxes)
    EndIf
EndFunc   ;==>_cveEdgeBoxesGetBoundingBoxes

Func _cveEdgeBoxesGetBoundingBoxesTyped($edgeBoxes, $typeOfEdgeMap, $edgeMap, $typeOfOrientationMap, $orientationMap, $boxes)

    Local $iArrEdgeMap, $vectorEdgeMap, $iArrEdgeMapSize
    Local $bEdgeMapIsArray = IsArray($edgeMap)
    Local $bEdgeMapCreate = IsDllStruct($edgeMap) And $typeOfEdgeMap == "Scalar"

    If $typeOfEdgeMap == Default Then
        $iArrEdgeMap = $edgeMap
    ElseIf $bEdgeMapIsArray Then
        $vectorEdgeMap = Call("_VectorOf" & $typeOfEdgeMap & "Create")

        $iArrEdgeMapSize = UBound($edgeMap)
        For $i = 0 To $iArrEdgeMapSize - 1
            Call("_VectorOf" & $typeOfEdgeMap & "Push", $vectorEdgeMap, $edgeMap[$i])
        Next

        $iArrEdgeMap = Call("_cveInputArrayFromVectorOf" & $typeOfEdgeMap, $vectorEdgeMap)
    Else
        If $bEdgeMapCreate Then
            $edgeMap = Call("_cve" & $typeOfEdgeMap & "Create", $edgeMap)
        EndIf
        $iArrEdgeMap = Call("_cveInputArrayFrom" & $typeOfEdgeMap, $edgeMap)
    EndIf

    Local $iArrOrientationMap, $vectorOrientationMap, $iArrOrientationMapSize
    Local $bOrientationMapIsArray = IsArray($orientationMap)
    Local $bOrientationMapCreate = IsDllStruct($orientationMap) And $typeOfOrientationMap == "Scalar"

    If $typeOfOrientationMap == Default Then
        $iArrOrientationMap = $orientationMap
    ElseIf $bOrientationMapIsArray Then
        $vectorOrientationMap = Call("_VectorOf" & $typeOfOrientationMap & "Create")

        $iArrOrientationMapSize = UBound($orientationMap)
        For $i = 0 To $iArrOrientationMapSize - 1
            Call("_VectorOf" & $typeOfOrientationMap & "Push", $vectorOrientationMap, $orientationMap[$i])
        Next

        $iArrOrientationMap = Call("_cveInputArrayFromVectorOf" & $typeOfOrientationMap, $vectorOrientationMap)
    Else
        If $bOrientationMapCreate Then
            $orientationMap = Call("_cve" & $typeOfOrientationMap & "Create", $orientationMap)
        EndIf
        $iArrOrientationMap = Call("_cveInputArrayFrom" & $typeOfOrientationMap, $orientationMap)
    EndIf

    _cveEdgeBoxesGetBoundingBoxes($edgeBoxes, $iArrEdgeMap, $iArrOrientationMap, $boxes)

    If $bOrientationMapIsArray Then
        Call("_VectorOf" & $typeOfOrientationMap & "Release", $vectorOrientationMap)
    EndIf

    If $typeOfOrientationMap <> Default Then
        _cveInputArrayRelease($iArrOrientationMap)
        If $bOrientationMapCreate Then
            Call("_cve" & $typeOfOrientationMap & "Release", $orientationMap)
        EndIf
    EndIf

    If $bEdgeMapIsArray Then
        Call("_VectorOf" & $typeOfEdgeMap & "Release", $vectorEdgeMap)
    EndIf

    If $typeOfEdgeMap <> Default Then
        _cveInputArrayRelease($iArrEdgeMap)
        If $bEdgeMapCreate Then
            Call("_cve" & $typeOfEdgeMap & "Release", $edgeMap)
        EndIf
    EndIf
EndFunc   ;==>_cveEdgeBoxesGetBoundingBoxesTyped

Func _cveEdgeBoxesGetBoundingBoxesMat($edgeBoxes, $edgeMap, $orientationMap, $boxes)
    ; cveEdgeBoxesGetBoundingBoxes using cv::Mat instead of _*Array
    _cveEdgeBoxesGetBoundingBoxesTyped($edgeBoxes, "Mat", $edgeMap, "Mat", $orientationMap, $boxes)
EndFunc   ;==>_cveEdgeBoxesGetBoundingBoxesMat

Func _cveEdgeBoxesRelease($sharedPtr)
    ; CVAPI(void) cveEdgeBoxesRelease(cv::Ptr<cv::ximgproc::EdgeBoxes>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeBoxesRelease", $sSharedPtrDllType, $sharedPtr), "cveEdgeBoxesRelease", @error)
EndFunc   ;==>_cveEdgeBoxesRelease

Func _cveEdgeDrawingCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::ximgproc::EdgeDrawing*) cveEdgeDrawingCreate(cv::Algorithm** algorithm, cv::Ptr<cv::ximgproc::EdgeDrawing>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEdgeDrawingCreate", $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveEdgeDrawingCreate", @error)
EndFunc   ;==>_cveEdgeDrawingCreate

Func _cveEdgeDrawingDetectEdges($edgeDrawing, $src)
    ; CVAPI(void) cveEdgeDrawingDetectEdges(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_InputArray* src);

    Local $sEdgeDrawingDllType
    If IsDllStruct($edgeDrawing) Then
        $sEdgeDrawingDllType = "struct*"
    Else
        $sEdgeDrawingDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectEdges", $sEdgeDrawingDllType, $edgeDrawing, $sSrcDllType, $src), "cveEdgeDrawingDetectEdges", @error)
EndFunc   ;==>_cveEdgeDrawingDetectEdges

Func _cveEdgeDrawingDetectEdgesTyped($edgeDrawing, $typeOfSrc, $src)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    _cveEdgeDrawingDetectEdges($edgeDrawing, $iArrSrc)

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveEdgeDrawingDetectEdgesTyped

Func _cveEdgeDrawingDetectEdgesMat($edgeDrawing, $src)
    ; cveEdgeDrawingDetectEdges using cv::Mat instead of _*Array
    _cveEdgeDrawingDetectEdgesTyped($edgeDrawing, "Mat", $src)
EndFunc   ;==>_cveEdgeDrawingDetectEdgesMat

Func _cveEdgeDrawingGetEdgeImage($edgeDrawing, $dst)
    ; CVAPI(void) cveEdgeDrawingGetEdgeImage(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* dst);

    Local $sEdgeDrawingDllType
    If IsDllStruct($edgeDrawing) Then
        $sEdgeDrawingDllType = "struct*"
    Else
        $sEdgeDrawingDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingGetEdgeImage", $sEdgeDrawingDllType, $edgeDrawing, $sDstDllType, $dst), "cveEdgeDrawingGetEdgeImage", @error)
EndFunc   ;==>_cveEdgeDrawingGetEdgeImage

Func _cveEdgeDrawingGetEdgeImageTyped($edgeDrawing, $typeOfDst, $dst)

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

    _cveEdgeDrawingGetEdgeImage($edgeDrawing, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveEdgeDrawingGetEdgeImageTyped

Func _cveEdgeDrawingGetEdgeImageMat($edgeDrawing, $dst)
    ; cveEdgeDrawingGetEdgeImage using cv::Mat instead of _*Array
    _cveEdgeDrawingGetEdgeImageTyped($edgeDrawing, "Mat", $dst)
EndFunc   ;==>_cveEdgeDrawingGetEdgeImageMat

Func _cveEdgeDrawingGetGradientImage($edgeDrawing, $dst)
    ; CVAPI(void) cveEdgeDrawingGetGradientImage(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* dst);

    Local $sEdgeDrawingDllType
    If IsDllStruct($edgeDrawing) Then
        $sEdgeDrawingDllType = "struct*"
    Else
        $sEdgeDrawingDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingGetGradientImage", $sEdgeDrawingDllType, $edgeDrawing, $sDstDllType, $dst), "cveEdgeDrawingGetGradientImage", @error)
EndFunc   ;==>_cveEdgeDrawingGetGradientImage

Func _cveEdgeDrawingGetGradientImageTyped($edgeDrawing, $typeOfDst, $dst)

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

    _cveEdgeDrawingGetGradientImage($edgeDrawing, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveEdgeDrawingGetGradientImageTyped

Func _cveEdgeDrawingGetGradientImageMat($edgeDrawing, $dst)
    ; cveEdgeDrawingGetGradientImage using cv::Mat instead of _*Array
    _cveEdgeDrawingGetGradientImageTyped($edgeDrawing, "Mat", $dst)
EndFunc   ;==>_cveEdgeDrawingGetGradientImageMat

Func _cveEdgeDrawingDetectLines($edgeDrawing, $lines)
    ; CVAPI(void) cveEdgeDrawingDetectLines(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* lines);

    Local $sEdgeDrawingDllType
    If IsDllStruct($edgeDrawing) Then
        $sEdgeDrawingDllType = "struct*"
    Else
        $sEdgeDrawingDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectLines", $sEdgeDrawingDllType, $edgeDrawing, $sLinesDllType, $lines), "cveEdgeDrawingDetectLines", @error)
EndFunc   ;==>_cveEdgeDrawingDetectLines

Func _cveEdgeDrawingDetectLinesTyped($edgeDrawing, $typeOfLines, $lines)

    Local $oArrLines, $vectorLines, $iArrLinesSize
    Local $bLinesIsArray = IsArray($lines)
    Local $bLinesCreate = IsDllStruct($lines) And $typeOfLines == "Scalar"

    If $typeOfLines == Default Then
        $oArrLines = $lines
    ElseIf $bLinesIsArray Then
        $vectorLines = Call("_VectorOf" & $typeOfLines & "Create")

        $iArrLinesSize = UBound($lines)
        For $i = 0 To $iArrLinesSize - 1
            Call("_VectorOf" & $typeOfLines & "Push", $vectorLines, $lines[$i])
        Next

        $oArrLines = Call("_cveOutputArrayFromVectorOf" & $typeOfLines, $vectorLines)
    Else
        If $bLinesCreate Then
            $lines = Call("_cve" & $typeOfLines & "Create", $lines)
        EndIf
        $oArrLines = Call("_cveOutputArrayFrom" & $typeOfLines, $lines)
    EndIf

    _cveEdgeDrawingDetectLines($edgeDrawing, $oArrLines)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
        EndIf
    EndIf
EndFunc   ;==>_cveEdgeDrawingDetectLinesTyped

Func _cveEdgeDrawingDetectLinesMat($edgeDrawing, $lines)
    ; cveEdgeDrawingDetectLines using cv::Mat instead of _*Array
    _cveEdgeDrawingDetectLinesTyped($edgeDrawing, "Mat", $lines)
EndFunc   ;==>_cveEdgeDrawingDetectLinesMat

Func _cveEdgeDrawingDetectEllipses($edgeDrawing, $ellipses)
    ; CVAPI(void) cveEdgeDrawingDetectEllipses(cv::ximgproc::EdgeDrawing* edgeDrawing, cv::_OutputArray* ellipses);

    Local $sEdgeDrawingDllType
    If IsDllStruct($edgeDrawing) Then
        $sEdgeDrawingDllType = "struct*"
    Else
        $sEdgeDrawingDllType = "ptr"
    EndIf

    Local $sEllipsesDllType
    If IsDllStruct($ellipses) Then
        $sEllipsesDllType = "struct*"
    Else
        $sEllipsesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingDetectEllipses", $sEdgeDrawingDllType, $edgeDrawing, $sEllipsesDllType, $ellipses), "cveEdgeDrawingDetectEllipses", @error)
EndFunc   ;==>_cveEdgeDrawingDetectEllipses

Func _cveEdgeDrawingDetectEllipsesTyped($edgeDrawing, $typeOfEllipses, $ellipses)

    Local $oArrEllipses, $vectorEllipses, $iArrEllipsesSize
    Local $bEllipsesIsArray = IsArray($ellipses)
    Local $bEllipsesCreate = IsDllStruct($ellipses) And $typeOfEllipses == "Scalar"

    If $typeOfEllipses == Default Then
        $oArrEllipses = $ellipses
    ElseIf $bEllipsesIsArray Then
        $vectorEllipses = Call("_VectorOf" & $typeOfEllipses & "Create")

        $iArrEllipsesSize = UBound($ellipses)
        For $i = 0 To $iArrEllipsesSize - 1
            Call("_VectorOf" & $typeOfEllipses & "Push", $vectorEllipses, $ellipses[$i])
        Next

        $oArrEllipses = Call("_cveOutputArrayFromVectorOf" & $typeOfEllipses, $vectorEllipses)
    Else
        If $bEllipsesCreate Then
            $ellipses = Call("_cve" & $typeOfEllipses & "Create", $ellipses)
        EndIf
        $oArrEllipses = Call("_cveOutputArrayFrom" & $typeOfEllipses, $ellipses)
    EndIf

    _cveEdgeDrawingDetectEllipses($edgeDrawing, $oArrEllipses)

    If $bEllipsesIsArray Then
        Call("_VectorOf" & $typeOfEllipses & "Release", $vectorEllipses)
    EndIf

    If $typeOfEllipses <> Default Then
        _cveOutputArrayRelease($oArrEllipses)
        If $bEllipsesCreate Then
            Call("_cve" & $typeOfEllipses & "Release", $ellipses)
        EndIf
    EndIf
EndFunc   ;==>_cveEdgeDrawingDetectEllipsesTyped

Func _cveEdgeDrawingDetectEllipsesMat($edgeDrawing, $ellipses)
    ; cveEdgeDrawingDetectEllipses using cv::Mat instead of _*Array
    _cveEdgeDrawingDetectEllipsesTyped($edgeDrawing, "Mat", $ellipses)
EndFunc   ;==>_cveEdgeDrawingDetectEllipsesMat

Func _cveEdgeDrawingRelease($sharedPtr)
    ; CVAPI(void) cveEdgeDrawingRelease(cv::Ptr<cv::ximgproc::EdgeDrawing>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgeDrawingRelease", $sSharedPtrDllType, $sharedPtr), "cveEdgeDrawingRelease", @error)
EndFunc   ;==>_cveEdgeDrawingRelease