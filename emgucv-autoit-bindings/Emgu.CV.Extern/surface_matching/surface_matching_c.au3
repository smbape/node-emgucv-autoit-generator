#include-once
#include "..\..\CVEUtils.au3"

Func _cveICPCreate($iterations, $tolerence, $rejectionScale, $numLevels, $sampleType, $numMaxCorr)
    ; CVAPI(cv::ppf_match_3d::ICP*) cveICPCreate(int iterations, float tolerence, float rejectionScale, int numLevels, int sampleType, int numMaxCorr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveICPCreate", "int", $iterations, "float", $tolerence, "float", $rejectionScale, "int", $numLevels, "int", $sampleType, "int", $numMaxCorr), "cveICPCreate", @error)
EndFunc   ;==>_cveICPCreate

Func _cveICPRegisterModelToScene($icp, $srcPC, $dstPC, $residual, $pose)
    ; CVAPI(int) cveICPRegisterModelToScene(cv::ppf_match_3d::ICP* icp, cv::Mat* srcPC, cv::Mat* dstPC, double* residual, cv::Mat* pose);

    Local $bIcpDllType
    If VarGetType($icp) == "DLLStruct" Then
        $bIcpDllType = "struct*"
    Else
        $bIcpDllType = "ptr"
    EndIf

    Local $bSrcPCDllType
    If VarGetType($srcPC) == "DLLStruct" Then
        $bSrcPCDllType = "struct*"
    Else
        $bSrcPCDllType = "ptr"
    EndIf

    Local $bDstPCDllType
    If VarGetType($dstPC) == "DLLStruct" Then
        $bDstPCDllType = "struct*"
    Else
        $bDstPCDllType = "ptr"
    EndIf

    Local $bResidualDllType
    If VarGetType($residual) == "DLLStruct" Then
        $bResidualDllType = "struct*"
    Else
        $bResidualDllType = "double*"
    EndIf

    Local $bPoseDllType
    If VarGetType($pose) == "DLLStruct" Then
        $bPoseDllType = "struct*"
    Else
        $bPoseDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveICPRegisterModelToScene", $bIcpDllType, $icp, $bSrcPCDllType, $srcPC, $bDstPCDllType, $dstPC, $bResidualDllType, $residual, $bPoseDllType, $pose), "cveICPRegisterModelToScene", @error)
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