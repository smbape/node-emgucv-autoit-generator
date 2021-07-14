#include-once
#include "..\..\CVEUtils.au3"

Func _cveICPCreate($iterations, $tolerence, $rejectionScale, $numLevels, $sampleType, $numMaxCorr)
    ; CVAPI(cv::ppf_match_3d::ICP*) cveICPCreate(int iterations, float tolerence, float rejectionScale, int numLevels, int sampleType, int numMaxCorr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveICPCreate", "int", $iterations, "float", $tolerence, "float", $rejectionScale, "int", $numLevels, "int", $sampleType, "int", $numMaxCorr), "cveICPCreate", @error)
EndFunc   ;==>_cveICPCreate

Func _cveICPRegisterModelToScene(ByRef $icp, ByRef $srcPC, ByRef $dstPC, ByRef $residual, ByRef $pose)
    ; CVAPI(int) cveICPRegisterModelToScene(cv::ppf_match_3d::ICP* icp, cv::Mat* srcPC, cv::Mat* dstPC, double* residual, cv::Mat* pose);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveICPRegisterModelToScene", "ptr", $icp, "ptr", $srcPC, "ptr", $dstPC, "struct*", $residual, "ptr", $pose), "cveICPRegisterModelToScene", @error)
EndFunc   ;==>_cveICPRegisterModelToScene

Func _cveICPRelease(ByRef $icp)
    ; CVAPI(void) cveICPRelease(cv::ppf_match_3d::ICP** icp);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveICPRelease", "ptr*", $icp), "cveICPRelease", @error)
EndFunc   ;==>_cveICPRelease