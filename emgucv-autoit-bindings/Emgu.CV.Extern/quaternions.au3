#include-once
#include "..\CVEUtils.au3"

Func _eulerToQuaternions($x, $y, $z, $quaternions)
    ; CVAPI(void) eulerToQuaternions(double x, double y, double z, Quaternions* quaternions);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "eulerToQuaternions", "double", $x, "double", $y, "double", $z, $bQuaternionsDllType, $quaternions), "eulerToQuaternions", @error)
EndFunc   ;==>_eulerToQuaternions

Func _quaternionsToEuler($quaternions, $x, $y, $z)
    ; CVAPI(void) quaternionsToEuler(const Quaternions* quaternions, double* x, double* y, double* z);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    Local $bXDllType
    If VarGetType($x) == "DLLStruct" Then
        $bXDllType = "struct*"
    Else
        $bXDllType = "double*"
    EndIf

    Local $bYDllType
    If VarGetType($y) == "DLLStruct" Then
        $bYDllType = "struct*"
    Else
        $bYDllType = "double*"
    EndIf

    Local $bZDllType
    If VarGetType($z) == "DLLStruct" Then
        $bZDllType = "struct*"
    Else
        $bZDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToEuler", $bQuaternionsDllType, $quaternions, $bXDllType, $x, $bYDllType, $y, $bZDllType, $z), "quaternionsToEuler", @error)
EndFunc   ;==>_quaternionsToEuler

Func _quaternionsToRotationMatrix($quaternions, $rotation)
    ; CVAPI(void) quaternionsToRotationMatrix(const Quaternions* quaternions, CvMat* rotation);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    Local $bRotationDllType
    If VarGetType($rotation) == "DLLStruct" Then
        $bRotationDllType = "struct*"
    Else
        $bRotationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToRotationMatrix", $bQuaternionsDllType, $quaternions, $bRotationDllType, $rotation), "quaternionsToRotationMatrix", @error)
EndFunc   ;==>_quaternionsToRotationMatrix

Func _quaternionsRotatePoint($quaternions, $point, $pointDst)
    ; CVAPI(void) quaternionsRotatePoint(const Quaternions* quaternions, const CvPoint3D64f* point, CvPoint3D64f* pointDst);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    Local $bPointDllType
    If VarGetType($point) == "DLLStruct" Then
        $bPointDllType = "struct*"
    Else
        $bPointDllType = "ptr"
    EndIf

    Local $bPointDstDllType
    If VarGetType($pointDst) == "DLLStruct" Then
        $bPointDstDllType = "struct*"
    Else
        $bPointDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRotatePoint", $bQuaternionsDllType, $quaternions, $bPointDllType, $point, $bPointDstDllType, $pointDst), "quaternionsRotatePoint", @error)
EndFunc   ;==>_quaternionsRotatePoint

Func _quaternionsRotatePoints($quaternions, $pointSrc, $pointDst)
    ; CVAPI(void) quaternionsRotatePoints(const Quaternions* quaternions, const CvMat* pointSrc, CvMat* pointDst);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    Local $bPointSrcDllType
    If VarGetType($pointSrc) == "DLLStruct" Then
        $bPointSrcDllType = "struct*"
    Else
        $bPointSrcDllType = "ptr"
    EndIf

    Local $bPointDstDllType
    If VarGetType($pointDst) == "DLLStruct" Then
        $bPointDstDllType = "struct*"
    Else
        $bPointDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRotatePoints", $bQuaternionsDllType, $quaternions, $bPointSrcDllType, $pointSrc, $bPointDstDllType, $pointDst), "quaternionsRotatePoints", @error)
EndFunc   ;==>_quaternionsRotatePoints

Func _quaternionsMultiply($quaternions1, $quaternions2, $quaternionsDst)
    ; CVAPI(void) quaternionsMultiply(const Quaternions* quaternions1, const Quaternions* quaternions2, Quaternions* quaternionsDst);

    Local $bQuaternions1DllType
    If VarGetType($quaternions1) == "DLLStruct" Then
        $bQuaternions1DllType = "struct*"
    Else
        $bQuaternions1DllType = "ptr"
    EndIf

    Local $bQuaternions2DllType
    If VarGetType($quaternions2) == "DLLStruct" Then
        $bQuaternions2DllType = "struct*"
    Else
        $bQuaternions2DllType = "ptr"
    EndIf

    Local $bQuaternionsDstDllType
    If VarGetType($quaternionsDst) == "DLLStruct" Then
        $bQuaternionsDstDllType = "struct*"
    Else
        $bQuaternionsDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsMultiply", $bQuaternions1DllType, $quaternions1, $bQuaternions2DllType, $quaternions2, $bQuaternionsDstDllType, $quaternionsDst), "quaternionsMultiply", @error)
EndFunc   ;==>_quaternionsMultiply

Func _axisAngleToQuaternions($axisAngle, $quaternions)
    ; CVAPI(void) axisAngleToQuaternions(const CvPoint3D64f* axisAngle, Quaternions* quaternions);

    Local $bAxisAngleDllType
    If VarGetType($axisAngle) == "DLLStruct" Then
        $bAxisAngleDllType = "struct*"
    Else
        $bAxisAngleDllType = "ptr"
    EndIf

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "axisAngleToQuaternions", $bAxisAngleDllType, $axisAngle, $bQuaternionsDllType, $quaternions), "axisAngleToQuaternions", @error)
EndFunc   ;==>_axisAngleToQuaternions

Func _quaternionsToAxisAngle($quaternions, $axisAngle)
    ; CVAPI(void) quaternionsToAxisAngle(const Quaternions* quaternions, CvPoint3D64f* axisAngle);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    Local $bAxisAngleDllType
    If VarGetType($axisAngle) == "DLLStruct" Then
        $bAxisAngleDllType = "struct*"
    Else
        $bAxisAngleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToAxisAngle", $bQuaternionsDllType, $quaternions, $bAxisAngleDllType, $axisAngle), "quaternionsToAxisAngle", @error)
EndFunc   ;==>_quaternionsToAxisAngle

Func _quaternionsRenorm($quaternions)
    ; CVAPI(void) quaternionsRenorm(Quaternions* quaternions);

    Local $bQuaternionsDllType
    If VarGetType($quaternions) == "DLLStruct" Then
        $bQuaternionsDllType = "struct*"
    Else
        $bQuaternionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRenorm", $bQuaternionsDllType, $quaternions), "quaternionsRenorm", @error)
EndFunc   ;==>_quaternionsRenorm

Func _quaternionsSlerp($qa, $qb, $t, $qm)
    ; CVAPI(void) quaternionsSlerp(const Quaternions* qa, const Quaternions* qb, double t, Quaternions* qm);

    Local $bQaDllType
    If VarGetType($qa) == "DLLStruct" Then
        $bQaDllType = "struct*"
    Else
        $bQaDllType = "ptr"
    EndIf

    Local $bQbDllType
    If VarGetType($qb) == "DLLStruct" Then
        $bQbDllType = "struct*"
    Else
        $bQbDllType = "ptr"
    EndIf

    Local $bQmDllType
    If VarGetType($qm) == "DLLStruct" Then
        $bQmDllType = "struct*"
    Else
        $bQmDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsSlerp", $bQaDllType, $qa, $bQbDllType, $qb, "double", $t, $bQmDllType, $qm), "quaternionsSlerp", @error)
EndFunc   ;==>_quaternionsSlerp