#include-once
#include "..\CVEUtils.au3"

Func _eulerToQuaternions($x, $y, $z, $quaternions)
    ; CVAPI(void) eulerToQuaternions(double x, double y, double z, Quaternions* quaternions);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "eulerToQuaternions", "double", $x, "double", $y, "double", $z, $sQuaternionsDllType, $quaternions), "eulerToQuaternions", @error)
EndFunc   ;==>_eulerToQuaternions

Func _quaternionsToEuler($quaternions, $x, $y, $z)
    ; CVAPI(void) quaternionsToEuler(const Quaternions* quaternions, double* x, double* y, double* z);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "double*"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "double*"
    EndIf

    Local $sZDllType
    If IsDllStruct($z) Then
        $sZDllType = "struct*"
    Else
        $sZDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToEuler", $sQuaternionsDllType, $quaternions, $sXDllType, $x, $sYDllType, $y, $sZDllType, $z), "quaternionsToEuler", @error)
EndFunc   ;==>_quaternionsToEuler

Func _quaternionsToRotationMatrix($quaternions, $rotation)
    ; CVAPI(void) quaternionsToRotationMatrix(const Quaternions* quaternions, CvMat* rotation);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    Local $sRotationDllType
    If IsDllStruct($rotation) Then
        $sRotationDllType = "struct*"
    Else
        $sRotationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToRotationMatrix", $sQuaternionsDllType, $quaternions, $sRotationDllType, $rotation), "quaternionsToRotationMatrix", @error)
EndFunc   ;==>_quaternionsToRotationMatrix

Func _quaternionsRotatePoint($quaternions, $point, $pointDst)
    ; CVAPI(void) quaternionsRotatePoint(const Quaternions* quaternions, const CvPoint3D64f* point, CvPoint3D64f* pointDst);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    Local $sPointDllType
    If IsDllStruct($point) Then
        $sPointDllType = "struct*"
    Else
        $sPointDllType = "ptr"
    EndIf

    Local $sPointDstDllType
    If IsDllStruct($pointDst) Then
        $sPointDstDllType = "struct*"
    Else
        $sPointDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRotatePoint", $sQuaternionsDllType, $quaternions, $sPointDllType, $point, $sPointDstDllType, $pointDst), "quaternionsRotatePoint", @error)
EndFunc   ;==>_quaternionsRotatePoint

Func _quaternionsRotatePoints($quaternions, $pointSrc, $pointDst)
    ; CVAPI(void) quaternionsRotatePoints(const Quaternions* quaternions, const CvMat* pointSrc, CvMat* pointDst);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    Local $sPointSrcDllType
    If IsDllStruct($pointSrc) Then
        $sPointSrcDllType = "struct*"
    Else
        $sPointSrcDllType = "ptr"
    EndIf

    Local $sPointDstDllType
    If IsDllStruct($pointDst) Then
        $sPointDstDllType = "struct*"
    Else
        $sPointDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRotatePoints", $sQuaternionsDllType, $quaternions, $sPointSrcDllType, $pointSrc, $sPointDstDllType, $pointDst), "quaternionsRotatePoints", @error)
EndFunc   ;==>_quaternionsRotatePoints

Func _quaternionsMultiply($quaternions1, $quaternions2, $quaternionsDst)
    ; CVAPI(void) quaternionsMultiply(const Quaternions* quaternions1, const Quaternions* quaternions2, Quaternions* quaternionsDst);

    Local $sQuaternions1DllType
    If IsDllStruct($quaternions1) Then
        $sQuaternions1DllType = "struct*"
    Else
        $sQuaternions1DllType = "ptr"
    EndIf

    Local $sQuaternions2DllType
    If IsDllStruct($quaternions2) Then
        $sQuaternions2DllType = "struct*"
    Else
        $sQuaternions2DllType = "ptr"
    EndIf

    Local $sQuaternionsDstDllType
    If IsDllStruct($quaternionsDst) Then
        $sQuaternionsDstDllType = "struct*"
    Else
        $sQuaternionsDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsMultiply", $sQuaternions1DllType, $quaternions1, $sQuaternions2DllType, $quaternions2, $sQuaternionsDstDllType, $quaternionsDst), "quaternionsMultiply", @error)
EndFunc   ;==>_quaternionsMultiply

Func _axisAngleToQuaternions($axisAngle, $quaternions)
    ; CVAPI(void) axisAngleToQuaternions(const CvPoint3D64f* axisAngle, Quaternions* quaternions);

    Local $sAxisAngleDllType
    If IsDllStruct($axisAngle) Then
        $sAxisAngleDllType = "struct*"
    Else
        $sAxisAngleDllType = "ptr"
    EndIf

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "axisAngleToQuaternions", $sAxisAngleDllType, $axisAngle, $sQuaternionsDllType, $quaternions), "axisAngleToQuaternions", @error)
EndFunc   ;==>_axisAngleToQuaternions

Func _quaternionsToAxisAngle($quaternions, $axisAngle)
    ; CVAPI(void) quaternionsToAxisAngle(const Quaternions* quaternions, CvPoint3D64f* axisAngle);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    Local $sAxisAngleDllType
    If IsDllStruct($axisAngle) Then
        $sAxisAngleDllType = "struct*"
    Else
        $sAxisAngleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToAxisAngle", $sQuaternionsDllType, $quaternions, $sAxisAngleDllType, $axisAngle), "quaternionsToAxisAngle", @error)
EndFunc   ;==>_quaternionsToAxisAngle

Func _quaternionsRenorm($quaternions)
    ; CVAPI(void) quaternionsRenorm(Quaternions* quaternions);

    Local $sQuaternionsDllType
    If IsDllStruct($quaternions) Then
        $sQuaternionsDllType = "struct*"
    Else
        $sQuaternionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRenorm", $sQuaternionsDllType, $quaternions), "quaternionsRenorm", @error)
EndFunc   ;==>_quaternionsRenorm

Func _quaternionsSlerp($qa, $qb, $t, $qm)
    ; CVAPI(void) quaternionsSlerp(const Quaternions* qa, const Quaternions* qb, double t, Quaternions* qm);

    Local $sQaDllType
    If IsDllStruct($qa) Then
        $sQaDllType = "struct*"
    Else
        $sQaDllType = "ptr"
    EndIf

    Local $sQbDllType
    If IsDllStruct($qb) Then
        $sQbDllType = "struct*"
    Else
        $sQbDllType = "ptr"
    EndIf

    Local $sQmDllType
    If IsDllStruct($qm) Then
        $sQmDllType = "struct*"
    Else
        $sQmDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsSlerp", $sQaDllType, $qa, $sQbDllType, $qb, "double", $t, $sQmDllType, $qm), "quaternionsSlerp", @error)
EndFunc   ;==>_quaternionsSlerp