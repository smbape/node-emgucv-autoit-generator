#include-once
#include "..\CVEUtils.au3"

Func _eulerToQuaternions($x, $y, $z, ByRef $quaternions)
    ; CVAPI(void) eulerToQuaternions(double x, double y, double z, Quaternions* quaternions);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "eulerToQuaternions", "double", $x, "double", $y, "double", $z, "struct*", $quaternions), "eulerToQuaternions", @error)
EndFunc   ;==>_eulerToQuaternions

Func _quaternionsToEuler($quaternions, ByRef $x, ByRef $y, ByRef $z)
    ; CVAPI(void) quaternionsToEuler(const Quaternions* quaternions, double* x, double* y, double* z);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToEuler", "ptr", $quaternions, "struct*", $x, "struct*", $y, "struct*", $z), "quaternionsToEuler", @error)
EndFunc   ;==>_quaternionsToEuler

Func _quaternionsToRotationMatrix($quaternions, ByRef $rotation)
    ; CVAPI(void) quaternionsToRotationMatrix(const Quaternions* quaternions, CvMat* rotation);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToRotationMatrix", "ptr", $quaternions, "struct*", $rotation), "quaternionsToRotationMatrix", @error)
EndFunc   ;==>_quaternionsToRotationMatrix

Func _quaternionsRotatePoint($quaternions, $point, ByRef $pointDst)
    ; CVAPI(void) quaternionsRotatePoint(const Quaternions* quaternions, const CvPoint3D64f* point, CvPoint3D64f* pointDst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRotatePoint", "ptr", $quaternions, "ptr", $point, "struct*", $pointDst), "quaternionsRotatePoint", @error)
EndFunc   ;==>_quaternionsRotatePoint

Func _quaternionsRotatePoints($quaternions, $pointSrc, ByRef $pointDst)
    ; CVAPI(void) quaternionsRotatePoints(const Quaternions* quaternions, const CvMat* pointSrc, CvMat* pointDst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRotatePoints", "ptr", $quaternions, "ptr", $pointSrc, "struct*", $pointDst), "quaternionsRotatePoints", @error)
EndFunc   ;==>_quaternionsRotatePoints

Func _quaternionsMultiply($quaternions1, $quaternions2, ByRef $quaternionsDst)
    ; CVAPI(void) quaternionsMultiply(const Quaternions* quaternions1, const Quaternions* quaternions2, Quaternions* quaternionsDst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsMultiply", "ptr", $quaternions1, "ptr", $quaternions2, "struct*", $quaternionsDst), "quaternionsMultiply", @error)
EndFunc   ;==>_quaternionsMultiply

Func _axisAngleToQuaternions($axisAngle, ByRef $quaternions)
    ; CVAPI(void) axisAngleToQuaternions(const CvPoint3D64f* axisAngle, Quaternions* quaternions);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "axisAngleToQuaternions", "ptr", $axisAngle, "struct*", $quaternions), "axisAngleToQuaternions", @error)
EndFunc   ;==>_axisAngleToQuaternions

Func _quaternionsToAxisAngle($quaternions, ByRef $axisAngle)
    ; CVAPI(void) quaternionsToAxisAngle(const Quaternions* quaternions, CvPoint3D64f* axisAngle);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsToAxisAngle", "ptr", $quaternions, "struct*", $axisAngle), "quaternionsToAxisAngle", @error)
EndFunc   ;==>_quaternionsToAxisAngle

Func _quaternionsRenorm(ByRef $quaternions)
    ; CVAPI(void) quaternionsRenorm(Quaternions* quaternions);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsRenorm", "struct*", $quaternions), "quaternionsRenorm", @error)
EndFunc   ;==>_quaternionsRenorm

Func _quaternionsSlerp($qa, $qb, $t, ByRef $qm)
    ; CVAPI(void) quaternionsSlerp(const Quaternions* qa, const Quaternions* qb, double t, Quaternions* qm);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "quaternionsSlerp", "ptr", $qa, "ptr", $qb, "double", $t, "struct*", $qm), "quaternionsSlerp", @error)
EndFunc   ;==>_quaternionsSlerp