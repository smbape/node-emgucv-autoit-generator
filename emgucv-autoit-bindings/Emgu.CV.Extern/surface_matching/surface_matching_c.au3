#include-once
#include "..\..\CVEUtils.au3"

Func _cveICPCreate($iterations, $tolerence, $rejectionScale, $numLevels, $sampleType, $numMaxCorr)
    ; CVAPI(cv::ppf_match_3d::ICP*) cveICPCreate(int iterations, float tolerence, float rejectionScale, int numLevels, int sampleType, int numMaxCorr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveICPCreate", "int", $iterations, "float", $tolerence, "float", $rejectionScale, "int", $numLevels, "int", $sampleType, "int", $numMaxCorr), "cveICPCreate", @error)
EndFunc   ;==>_cveICPCreate

Func _cveICPRegisterModelToScene($icp, $srcPC, $dstPC, $residual, $pose)
    ; CVAPI(int) cveICPRegisterModelToScene(cv::ppf_match_3d::ICP* icp, cv::Mat* srcPC, cv::Mat* dstPC, double* residual, cv::Mat* pose);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveICPRegisterModelToScene", "ptr", $icp, "ptr", $srcPC, "ptr", $dstPC, "struct*", $residual, "ptr", $pose), "cveICPRegisterModelToScene", @error)
EndFunc   ;==>_cveICPRegisterModelToScene

Func _cveICPRelease($icp)
    ; CVAPI(void) cveICPRelease(cv::ppf_match_3d::ICP** icp);

    Local $bIcpDllType
    If VarGetType($icp) == "DLLStruct" Then
        $bIcpDllType = "struct*"
    Else
        $bIcpDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveICPRelease", $bIcpDllType, $icp), "cveICPRelease", @error)
EndFunc   ;==>_cveICPRelease