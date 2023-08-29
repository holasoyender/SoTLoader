; ---------------------------------------------------------------------------

RUNTIME_FUNCTION struc ; (sizeof=0xC, mappedto_1)
                                        ; XREF: .rdata:0000000140008528/r
                                        ; .rdata:0000000140008538/r ...
FunctionStart   dd ?                    ; offset rva
FunctionEnd     dd ?                    ; offset rva pastend
UnwindInfo      dd ?                    ; offset rva
RUNTIME_FUNCTION ends

; ---------------------------------------------------------------------------

UNWIND_INFO_HDR struc ; (sizeof=0x4, mappedto_2)
                                        ; XREF: .rdata:stru_140008398/r
                                        ; .rdata:stru_1400083A4/r ...
Ver3_Flags      db ?                    ; base 16
PrologSize      db ?                    ; base 16
CntUnwindCodes  db ?                    ; base 16
FrReg_FrRegOff  db ?                    ; base 16
UNWIND_INFO_HDR ends

; ---------------------------------------------------------------------------

UNWIND_CODE     struc ; (sizeof=0x2, mappedto_3)
                                        ; XREF: .rdata:000000014000839C/r
                                        ; .rdata:000000014000839E/r ...
PrologOff       db ?                    ; base 16
OpCode_OpInfo   db ?                    ; base 16
UNWIND_CODE     ends

; ---------------------------------------------------------------------------

_ThrowInfo      struc ; (sizeof=0x10, align=0x4, copyof_4)
                                        ; XREF: .rdata:stru_140008EB0/r
                                        ; .rdata:exceptionTypeInfo/r ...
attributes      dd ?
pmfnUnwind      dd ?
pForwardCompat  dd ?
pCatchableTypeArray dd ?
_ThrowInfo      ends

; ---------------------------------------------------------------------------

MODULEENTRY32   struc ; (sizeof=0x238, align=0x8, copyof_8)
                                        ; XREF: IsModuleInProcess/r
dwSize          dd ?                    ; XREF: IsModuleInProcess+39/w
th32ModuleID    dd ?                    ; XREF: IsModuleInProcess+47/o
th32ProcessID   dd ?
GlblcntUsage    dd ?
ProccntUsage    dd ?
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
modBaseAddr     dq ?                    ; offset
modBaseSize     dd ?
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
hModule         dq ?                    ; offset
szModule        db 256 dup(?)           ; XREF: IsModuleInProcess:loc_140003170/o
szExePath       db 260 dup(?)
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
MODULEENTRY32   ends

; ---------------------------------------------------------------------------

_EXPLICIT_ACCESS_W struc ; (sizeof=0x30, align=0x8, copyof_15)
                                        ; XREF: PerformRemoteExecution+D8/w
                                        ; PerformRemoteExecution/r
grfAccessPermissions dd ?               ; XREF: PerformRemoteExecution+DE/w
grfAccessMode   dd ?                    ; XREF: PerformRemoteExecution+E6/w ; enum ACCESS_MODE
grfInheritance  dd ?                    ; XREF: PerformRemoteExecution+EE/w
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
Trustee         TRUSTEE_W ?             ; XREF: PerformRemoteExecution+C1/w
                                        ; PerformRemoteExecution+CC/w ...
_EXPLICIT_ACCESS_W ends

; ---------------------------------------------------------------------------

TRUSTEE_W       struc ; (sizeof=0x20, align=0x8, copyof_18)
                                        ; XREF: _EXPLICIT_ACCESS_W/r
pMultipleTrustee dq ?                   ; offset
MultipleTrusteeOperation dd ?           ; enum MULTIPLE_TRUSTEE_OPERATION
TrusteeForm     dd ?                    ; XREF: PerformRemoteExecution+F6/w ; enum TRUSTEE_FORM
TrusteeType     dd ?                    ; XREF: PerformRemoteExecution+CC/w ; enum TRUSTEE_TYPE
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
ptstrName       dq ?                    ; XREF: PerformRemoteExecution+C1/w ; offset
TRUSTEE_W       ends

; ---------------------------------------------------------------------------

PROCESSENTRY32  struc ; (sizeof=0x130, align=0x8, copyof_29)
                                        ; XREF: main/r
dwSize          dd ?                    ; XREF: main+49/w
cntUsage        dd ?
th32ProcessID   dd ?                    ; XREF: main:loc_1400039E0/r
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
th32DefaultHeapID dq ?
th32ModuleID    dd ?
cntThreads      dd ?
th32ParentProcessID dd ?
pcPriClassBase  dd ?
dwFlags         dd ?
szExeFile       db 260 dup(?)           ; XREF: main+77/o
PROCESSENTRY32  ends

; ---------------------------------------------------------------------------

_onexit_table_t struc ; (sizeof=0x18, align=0x8, copyof_34)
                                        ; XREF: .data:Table/r
                                        ; .data:stru_14000A870/r
_first          dq ?                    ; XREF: __scrt_initialize_onexit_tables+53/w
                                        ; __scrt_initialize_onexit_tables+62/w ... ; offset
_last           dq ?                    ; offset
_end            dq ?                    ; XREF: __scrt_initialize_onexit_tables+5B/w
                                        ; __scrt_initialize_onexit_tables+6A/w ; offset
_onexit_table_t ends

; ---------------------------------------------------------------------------

_FILETIME       struc ; (sizeof=0x8, align=0x4, copyof_36)
                                        ; XREF: __security_init_cookie/r
dwLowDateTime   dd ?                    ; XREF: __security_init_cookie+23/w
                                        ; __security_init_cookie+32/r
dwHighDateTime  dd ?
_FILETIME       ends

; ---------------------------------------------------------------------------

LARGE_INTEGER   union ; (sizeof=0x8, align=0x8, copyof_37)
                                        ; XREF: __security_init_cookie+5C/r
                                        ; __security_init_cookie+67/r ...
anonymous_0     _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
u               _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
QuadPart        dq ?
LARGE_INTEGER   ends

; ---------------------------------------------------------------------------

_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E struc ; (sizeof=0x8, align=0x4, copyof_39)
                                        ; XREF: LARGE_INTEGER/r
                                        ; LARGE_INTEGER/r
LowPart         dd ?
HighPart        dd ?
_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ends

; ---------------------------------------------------------------------------

_CONTEXT        struc ; (sizeof=0x4D0, align=0x10, copyof_41)
                                        ; XREF: .data:ContextRecord/r
                                        ; __scrt_fastfail/r
P1Home          dq ?
P2Home          dq ?
P3Home          dq ?
P4Home          dq ?
P5Home          dq ?
P6Home          dq ?
ContextFlags    dd ?
_MxCsr          dd ?
SegCs           dw ?
SegDs           dw ?
SegEs           dw ?
SegFs           dw ?
SegGs           dw ?
SegSs           dw ?
EFlags          dd ?
Dr0             dq ?
Dr1             dq ?
Dr2             dq ?
Dr3             dq ?
Dr6             dq ?
Dr7             dq ?
_Rax            dq ?
_Rcx            dq ?                    ; XREF: __report_gsfailure+5A/w
_Rdx            dq ?
_Rbx            dq ?
_Rsp            dq ?                    ; XREF: __report_gsfailure+40/w
                                        ; __scrt_fastfail+D0/w
_Rbp            dq ?
_Rsi            dq ?
_Rdi            dq ?
_R8             dq ?
_R9             dq ?
_R10            dq ?
_R11            dq ?
_R12            dq ?
_R13            dq ?
_R14            dq ?
_R15            dq ?
_Rip            dq ?                    ; XREF: __report_gsfailure+30/w
                                        ; __report_gsfailure+47/r ...
anonymous_0     _CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB ?
VectorRegister  M128A 26 dup(?)
VectorControl   dq ?
DebugControl    dq ?
LastBranchToRip dq ?
LastBranchFromRip dq ?
LastExceptionToRip dq ?
LastExceptionFromRip dq ?
_CONTEXT        ends

; ---------------------------------------------------------------------------

_CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB union ; (sizeof=0x200, align=0x10, copyof_44)
                                        ; XREF: _CONTEXT/r
FltSave         XMM_SAVE_AREA32 ?
anonymous_0     _CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB::$897D11C01F73F7E79A06B0B9ED9B9414 ?
_CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB ends

; ---------------------------------------------------------------------------

XMM_SAVE_AREA32 struc ; (sizeof=0x200, align=0x10, copyof_45)
                                        ; XREF: _CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB/r
ControlWord     dw ?
StatusWord      dw ?
TagWord         db ?
Reserved1       db ?
ErrorOpcode     dw ?
ErrorOffset     dd ?
ErrorSelector   dw ?
Reserved2       dw ?
DataOffset      dd ?
DataSelector    dw ?
Reserved3       dw ?
_MxCsr          dd ?
MxCsr_Mask      dd ?
FloatRegisters  M128A 8 dup(?)
XmmRegisters    M128A 16 dup(?)
Reserved4       db 96 dup(?)
XMM_SAVE_AREA32 ends

; ---------------------------------------------------------------------------

M128A           struc ; (sizeof=0x10, align=0x10, copyof_48)
                                        ; XREF: XMM_SAVE_AREA32/r
                                        ; XMM_SAVE_AREA32/r ...
Low             dq ?
High            dq ?
M128A           ends

; ---------------------------------------------------------------------------

_CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB::$897D11C01F73F7E79A06B0B9ED9B9414 struc ; (sizeof=0x1A0, align=0x10, copyof_51)
                                        ; XREF: _CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB/r
Header          M128A 2 dup(?)
Legacy          M128A 8 dup(?)
_Xmm0           M128A ?
_Xmm1           M128A ?
_Xmm2           M128A ?
_Xmm3           M128A ?
_Xmm4           M128A ?
_Xmm5           M128A ?
_Xmm6           M128A ?
_Xmm7           M128A ?
_Xmm8           M128A ?
_Xmm9           M128A ?
_Xmm10          M128A ?
_Xmm11          M128A ?
_Xmm12          M128A ?
_Xmm13          M128A ?
_Xmm14          M128A ?
_Xmm15          M128A ?
_CONTEXT::$D2ECA93702C646ACAFACD524BE9E8FEB::$897D11C01F73F7E79A06B0B9ED9B9414 ends

; ---------------------------------------------------------------------------

_EXCEPTION_POINTERS struc ; (sizeof=0x10, align=0x8, copyof_52)
                                        ; XREF: .rdata:ExceptionInfo/r
                                        ; __scrt_fastfail/r
ExceptionRecord dq ?                    ; XREF: __scrt_fastfail+106/w ; offset
ContextRecord   dq ?                    ; XREF: __scrt_fastfail+112/w ; offset
_EXCEPTION_POINTERS ends

; ---------------------------------------------------------------------------

C_SCOPE_TABLE   struc ; (sizeof=0x10, mappedto_58)
                                        ; XREF: .rdata:0000000140008DF4/r
                                        ; .rdata:0000000140008E04/r ...
Begin           dd ?                    ; offset rva
End             dd ?                    ; offset rva pastend
Handler         dd ?                    ; offset rva
Target          dd ?                    ; offset rva
C_SCOPE_TABLE   ends

; ---------------------------------------------------------------------------

__m128i         union ; (sizeof=0x10, align=0x10, copyof_62)
m128i_i8        db 16 dup(?)
m128i_i16       dw 8 dup(?)
m128i_i32       dd 4 dup(?)
m128i_i64       dq 2 dup(?)
m128i_u8        db 16 dup(?)
m128i_u16       dw 8 dup(?)
m128i_u32       dd 4 dup(?)
m128i_u64       dq 2 dup(?)
__m128i         ends

; ---------------------------------------------------------------------------

_SLIST_HEADER   union ; (sizeof=0x10, align=0x10, copyof_63)
                                        ; XREF: .data:stru_14000A890/r
anonymous_0     _SLIST_HEADER::$2AAD3A9E0F86A5BF9BE50654CA710F62 ?
HeaderX64       _SLIST_HEADER::$F9F9EB832D628D73E611400623F67F2B ?
_SLIST_HEADER   ends

; ---------------------------------------------------------------------------

_SLIST_HEADER::$2AAD3A9E0F86A5BF9BE50654CA710F62 struc ; (sizeof=0x10, align=0x8, copyof_64)
                                        ; XREF: _SLIST_HEADER/r
Alignment       dq ?
Region          dq ?
_SLIST_HEADER::$2AAD3A9E0F86A5BF9BE50654CA710F62 ends

; ---------------------------------------------------------------------------

_SLIST_HEADER::$F9F9EB832D628D73E611400623F67F2B struc ; (sizeof=0x10, align=0x8, copyof_65)
                                        ; XREF: _SLIST_HEADER/r
_bf_0           dq ?
_bf_8           dq ?
_SLIST_HEADER::$F9F9EB832D628D73E611400623F67F2B ends

; ---------------------------------------------------------------------------

; enum ACCESS_MODE, copyof_16, width 4 bytes
NOT_USED_ACCESS  = 0
GRANT_ACCESS     = 1
SET_ACCESS       = 2
DENY_ACCESS      = 3
REVOKE_ACCESS    = 4
SET_AUDIT_SUCCESS  = 5
SET_AUDIT_FAILURE  = 6

; ---------------------------------------------------------------------------

; enum MULTIPLE_TRUSTEE_OPERATION, copyof_20, width 4 bytes
NO_MULTIPLE_TRUSTEE  = 0
TRUSTEE_IS_IMPERSONATE  = 1

; ---------------------------------------------------------------------------

; enum TRUSTEE_FORM, copyof_22, width 4 bytes
TRUSTEE_IS_SID   = 0
TRUSTEE_IS_NAME  = 1
TRUSTEE_BAD_FORM  = 2
TRUSTEE_IS_OBJECTS_AND_SID  = 3
TRUSTEE_IS_OBJECTS_AND_NAME  = 4

; ---------------------------------------------------------------------------

; enum TRUSTEE_TYPE, copyof_24, width 4 bytes
TRUSTEE_IS_UNKNOWN  = 0
TRUSTEE_IS_USER  = 1
TRUSTEE_IS_GROUP  = 2
TRUSTEE_IS_DOMAIN  = 3
TRUSTEE_IS_ALIAS  = 4
TRUSTEE_IS_WELL_KNOWN_GROUP  = 5
TRUSTEE_IS_DELETED  = 6
TRUSTEE_IS_INVALID  = 7
TRUSTEE_IS_COMPUTER  = 8

;
; +-------------------------------------------------------------------------+
; |      This file was generated by The Interactive Disassembler (IDA)      |
; |           Copyright (c) 2023 Hex-Rays, <support@hex-rays.com>           |
; |                            Freeware version                             |
; +-------------------------------------------------------------------------+
;
; Input SHA256 : F9A36F560D07852BA3436936739E1CECF1FEF300C4D33B50AB18269C21CF5497
; Input MD5    : D98AA1085F859D0E072E09175DFB5999
; Input CRC32  : 9EF5DEA9

; File Name   : C:\Users\javiw\Desktop\proyectos\SOT\Loader.exe
; Format      : Portable executable for AMD64 (PE)
; Imagebase   : 140000000
; Timestamp   : 6442CE23 (Fri Apr 21 17:55:47 2023)
; Section 1. (virtual address 00001000)
; Virtual size                  : 00005C9B (  23707.)
; Section size in file          : 00005E00 (  24064.)
; Offset to raw data for section: 00000400
; Flags 60000020: Text Executable Readable
; Alignment     : default
; OS type         :  MS Windows
; Application type:  Executable

                .686p
                .mmx
                .model flat

; ===========================================================================

; Segment type: Pure code
; Segment permissions: Read/Execute
_text           segment para public 'CODE' use64
                assume cs:_text
                ;org 140001000h
                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing

; =============== S U B R O U T I N E =======================================


; void *get_unknown_string()
get_unknown_string proc near            ; CODE XREF: PrintFormattedOutputToStdout+2D↓p
                                        ; __scrt_initialize_default_local_stdio_options+4↓p
                lea     rax, unk_14000A8B0
                retn
get_unknown_string endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; int PrintFormattedOutputToStdout(const char *input, ...)
PrintFormattedOutputToStdout proc near  ; CODE XREF: main+B7↓p
                                        ; main+E8↓p ...

ArgList         = qword ptr -28h
Format          = qword ptr  8
variableArgs    = byte ptr  10h
arg_10          = qword ptr  18h
arg_18          = qword ptr  20h

                mov     [rsp+Format], rcx
                mov     qword ptr [rsp+variableArgs], rdx
                mov     [rsp+arg_10], r8
                mov     [rsp+arg_18], r9
                push    rbx
                push    rdi
                sub     rsp, 38h
                mov     ecx, 1          ; Ix
                lea     rdi, [rsp+48h+variableArgs]
                call    cs:__acrt_iob_func
                mov     rbx, rax
                call    get_unknown_string
                mov     r8, [rsp+48h+Format] ; Format
                xor     r9d, r9d        ; Locale
                mov     rdx, rbx        ; Stream
                mov     [rsp+48h+ArgList], rdi ; ArgList
                mov     rcx, [rax]      ; Options
                call    cs:__stdio_common_vfprintf
                add     rsp, 38h
                pop     rdi
                pop     rbx
                retn
PrintFormattedOutputToStdout endp

; ---------------------------------------------------------------------------
algn_140001062:                         ; DATA XREF: .pdata:ExceptionDir↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_140001070   proc near               ; DATA XREF: .pdata:000000014000B00C↓o
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rax, rdx
                lea     rcx, off_1400074D8
                xorps   xmm0, xmm0
                lea     rdx, [rbx+8]
                mov     [rbx], rcx
                lea     rcx, [rax+8]
                movups  xmmword ptr [rdx], xmm0
                call    cs:__std_exception_copy
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
sub_140001070   endp

; ---------------------------------------------------------------------------
algn_1400010A3:                         ; DATA XREF: .pdata:000000014000B00C↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_1400010B0   proc near               ; DATA XREF: .rdata:00000001400074E0↓o
                                        ; .rdata:00000001400074F8↓o ...
                mov     rdx, [rcx+8]
                lea     rax, aUnknownExcepti ; "Unknown exception"
                test    rdx, rdx
                cmovnz  rax, rdx
                retn
sub_1400010B0   endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_1400010D0(void *Block)
sub_1400010D0   proc near               ; DATA XREF: .rdata:off_1400074D8↓o
                                        ; .rdata:off_1400074F0↓o ...

arg_0           = qword ptr  8

                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                lea     rax, off_1400074D8
                mov     rdi, rcx
                mov     [rcx], rax
                mov     ebx, edx
                add     rcx, 8
                call    cs:__std_exception_destroy
                test    bl, 1
                jz      short loc_140001105
                mov     edx, 18h
                mov     rcx, rdi        ; Block
                call    j_j_free

loc_140001105:                          ; CODE XREF: sub_1400010D0+26↑j
                mov     rbx, [rsp+28h+arg_0]
                mov     rax, rdi
                add     rsp, 20h
                pop     rdi
                retn
sub_1400010D0   endp

; ---------------------------------------------------------------------------
algn_140001113:                         ; DATA XREF: .pdata:000000014000B018↓o
                align 20h

loc_140001120:                          ; CODE XREF: .text:0000000140006A47↓j
                                        ; .text:0000000140006A77↓j ...
                lea     rax, off_1400074D8
                mov     [rcx], rax
                add     rcx, 8
                jmp     cs:__std_exception_destroy
; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall InitializeBadArrayLengthException(_QWORD *exceptionObject)
InitializeBadArrayLengthException proc near
                                        ; CODE XREF: ThrowBadArrayLengthException+9↓p
                lea     rax, aBadArrayNewLen ; "bad array new length"
                mov     qword ptr [rcx+10h], 0
                mov     [rcx+8], rax
                lea     rax, off_140007518
                mov     [rcx], rax
                mov     rax, rcx
                retn
InitializeBadArrayLengthException endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __noreturn ThrowBadArrayLengthException()
ThrowBadArrayLengthException proc near  ; CODE XREF: CopyAndResizeArray:loc_140003F61↓p
                                        ; sub_140004010:loc_1400040D8↓p ...

exceptionObject = byte ptr -28h

                sub     rsp, 48h
                lea     rcx, [rsp+48h+exceptionObject]
                call    InitializeBadArrayLengthException
                lea     rdx, pThrowInfo ; pThrowInfo
                lea     rcx, [rsp+48h+exceptionObject] ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                align 10h
ThrowBadArrayLengthException endp


; =============== S U B R O U T I N E =======================================


sub_140001190   proc near               ; DATA XREF: .pdata:000000014000B024↓o
                                        ; .pdata:000000014000B030↓o
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rax, rdx
                lea     rcx, off_1400074D8
                xorps   xmm0, xmm0
                lea     rdx, [rbx+8]
                mov     [rbx], rcx
                lea     rcx, [rax+8]
                movups  xmmword ptr [rdx], xmm0
                call    cs:__std_exception_copy
                lea     rax, off_140007518
                mov     [rbx], rax
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
sub_140001190   endp

; ---------------------------------------------------------------------------
algn_1400011CD:                         ; DATA XREF: .pdata:000000014000B030↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_1400011D0   proc near               ; DATA XREF: .pdata:000000014000B03C↓o
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rax, rdx
                lea     rcx, off_1400074D8
                xorps   xmm0, xmm0
                lea     rdx, [rbx+8]
                mov     [rbx], rcx
                lea     rcx, [rax+8]
                movups  xmmword ptr [rdx], xmm0
                call    cs:__std_exception_copy
                lea     rax, off_1400074F0
                mov     [rbx], rax
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
sub_1400011D0   endp

; ---------------------------------------------------------------------------
algn_14000120D:                         ; DATA XREF: .pdata:000000014000B03C↓o
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __noreturn ThrowStringLengthExceededException()
ThrowStringLengthExceededException proc near
                                        ; CODE XREF: ResizeAndCopyData:loc_140004237↓p
                                        ; ModifyAndCopyData:loc_140004729↓p ...
                sub     rsp, 28h
                lea     rcx, aStringTooLong ; "string too long"
                call    cs:?_Xlength_error@std@@YAXPEBD@Z ; std::_Xlength_error(char const *)
; ---------------------------------------------------------------------------
                db 0CCh
ThrowStringLengthExceededException endp

algn_140001222:                         ; DATA XREF: .pdata:000000014000B048↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_140001230   proc near               ; DATA XREF: .pdata:000000014000B054↓o
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rax, rdx
                lea     rcx, off_1400074D8
                xorps   xmm0, xmm0
                lea     rdx, [rbx+8]
                mov     [rbx], rcx
                lea     rcx, [rax+8]
                movups  xmmword ptr [rdx], xmm0
                call    cs:__std_exception_copy
                lea     rax, off_1400077B0
                mov     [rbx], rax
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
sub_140001230   endp

; ---------------------------------------------------------------------------
algn_14000126D:                         ; DATA XREF: .pdata:000000014000B054↓o
                align 10h
; [0000000B BYTES: COLLAPSED FUNCTION std::error_category::default_error_condition(int). PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h

; =============== S U B R O U T I N E =======================================


sub_140001280   proc near               ; DATA XREF: .rdata:0000000140007790↓o
                                        ; .rdata:0000000140007830↓o ...

var_18          = byte ptr -18h

                push    rbx
                sub     rsp, 30h
                mov     rax, [rcx]
                mov     rbx, r8
                mov     r8d, edx
                lea     rdx, [rsp+38h+var_18]
                call    qword ptr [rax+18h]
                mov     rcx, [rbx+8]
                mov     r9, [rax+8]
                mov     rdx, [rcx+8]
                cmp     [r9+8], rdx
                jnz     short loc_1400012B7
                mov     ecx, [rbx]
                cmp     [rax], ecx
                jnz     short loc_1400012B7
                mov     al, 1
                add     rsp, 30h
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_1400012B7:                          ; CODE XREF: sub_140001280+27↑j
                                        ; sub_140001280+2D↑j
                xor     al, al
                add     rsp, 30h
                pop     rbx
                retn
sub_140001280   endp

; ---------------------------------------------------------------------------
algn_1400012BF:                         ; DATA XREF: .pdata:000000014000B060↓o
                align 20h
; [00000019 BYTES: COLLAPSED FUNCTION std::error_category::equivalent(std::error_code const &,int). PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall InitializeMemoryBlock(__int64 memoryBlock)
InitializeMemoryBlock proc near         ; CODE XREF: ThrowException+9↓p
                lea     rax, staticMemoryLocation
                mov     dword ptr [rcx], 16h
                mov     [rcx+8], rax
                mov     rax, rcx
                retn
InitializeMemoryBlock endp

; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame fpd=57h

; __int64 __fastcall HandleExceptionAndCopyData(__int64 exceptionObj, _OWORD *dataToCopy, __int64 dataSize)
HandleExceptionAndCopyData proc near    ; CODE XREF: ProcessAndCopyData_0+58↓p
                                        ; HandleAndCopyExceptionData+1F↓p ...

var_A0          = qword ptr -0A0h
var_98          = qword ptr -98h
var_88          = xmmword ptr -88h
var_78          = byte ptr -78h
dataMemoryBlock = qword ptr -50h
var_40          = qword ptr -40h
var_38          = qword ptr -38h
var_30          = qword ptr -30h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __GSHandlerCheck_EH4
                push    rbp
                push    rbx
                push    rsi
                push    rdi
                push    r14
                lea     rbp, [rsp-37h]
                sub     rsp, 0A0h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+57h+var_30], rax
                mov     rsi, rdx
                mov     rbx, rcx
                mov     [rbp+57h+var_A0], rcx
                xor     r14d, r14d
                mov     rdx, r8
                lea     rcx, [rbp+57h+var_78]
                call    sub_140004010
                mov     rdi, rax
                mov     [rbp+57h+var_A0], rax
                movups  xmm0, xmmword ptr [rsi]
                movaps  xmmword ptr [rbp+57h+dataMemoryBlock], xmm0
                cmp     [rax+10h], r14
                jz      short loc_140001361
                lea     r8d, [r14+2]
                lea     rdx, asc_140007580 ; ": "
                mov     rcx, rax        ; Src
                call    CopyDataToMemoryBlock

loc_140001361:                          ; CODE XREF: HandleExceptionAndCopyData+4C↑j
                mov     rcx, [rbp+57h+dataMemoryBlock+8]
                mov     rax, [rcx]
                mov     r8d, dword ptr [rbp+57h+dataMemoryBlock]
                lea     rdx, [rbp+57h+dataMemoryBlock]
                call    qword ptr [rax+10h]
                nop
                lea     rdx, [rbp+57h+dataMemoryBlock]
                cmp     [rbp+57h+var_38], 10h
                cmovnb  rdx, [rbp+57h+dataMemoryBlock]
                mov     r8, [rbp+57h+var_40]
                mov     rcx, rdi        ; Src
                call    CopyDataToMemoryBlock
                nop
                mov     rdx, [rbp+57h+var_38]
                cmp     rdx, 10h
                jb      short loc_1400013CD
                inc     rdx
                mov     rcx, [rbp+57h+dataMemoryBlock] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_1400013C8
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_1400013C8
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400013C8:                          ; CODE XREF: HandleExceptionAndCopyData+AA↑j
                                        ; HandleExceptionAndCopyData+BF↑j
                call    j_j_free

loc_1400013CD:                          ; CODE XREF: HandleExceptionAndCopyData+97↑j
                mov     [rbp+57h+var_40], r14
                mov     [rbp+57h+var_38], 0Fh
                mov     byte ptr [rbp+57h+dataMemoryBlock], 0
                mov     [rbp+57h+var_98], r14
                mov     qword ptr [rbp+57h+var_88], r14
                mov     qword ptr [rbp+57h+var_88+8], r14
                movups  xmm0, xmmword ptr [rdi]
                movups  xmmword ptr [rbp+57h+var_98], xmm0
                movups  xmm1, xmmword ptr [rdi+10h]
                movups  [rbp+57h+var_88], xmm1
                mov     qword ptr [rdi+18h], 0Fh
                mov     byte ptr [rdi], 0
                mov     byte ptr [rdi], 0
                mov     [rdi+10h], r14
                mov     qword ptr [rdi+18h], 0Fh
                lea     rax, [rbp+57h+var_98]
                cmp     qword ptr [rbp+57h+var_88+8], 10h
                cmovnb  rax, [rbp+57h+var_98]
                lea     rcx, off_1400074D8
                mov     [rbx], rcx
                lea     rdx, [rbx+8]
                xorps   xmm0, xmm0
                movups  xmmword ptr [rdx], xmm0
                mov     [rbp+57h+dataMemoryBlock], rax
                mov     byte ptr [rbp+57h+dataMemoryBlock+8], 1
                lea     rcx, [rbp+57h+dataMemoryBlock]
                call    cs:__std_exception_copy
                lea     rax, off_1400077B0
                mov     [rbx], rax
                mov     rdx, qword ptr [rbp+57h+var_88+8]
                cmp     rdx, 10h
                jb      short loc_14000148E
                inc     rdx
                mov     rcx, [rbp+57h+var_98] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140001489
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140001489
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140001489:                          ; CODE XREF: HandleExceptionAndCopyData+16B↑j
                                        ; HandleExceptionAndCopyData+180↑j
                call    j_j_free

loc_14000148E:                          ; CODE XREF: HandleExceptionAndCopyData+158↑j
                lea     rax, off_1400077C8
                mov     [rbx], rax
                movups  xmm0, xmmword ptr [rsi]
                movups  xmmword ptr [rbx+18h], xmm0
                mov     rax, rbx
                mov     rcx, [rbp+57h+var_30]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                add     rsp, 0A0h
                pop     r14
                pop     rdi
                pop     rsi
                pop     rbx
                pop     rbp
                retn
; } // starts at 140001300
HandleExceptionAndCopyData endp

; ---------------------------------------------------------------------------
algn_1400014BC:                         ; DATA XREF: .pdata:000000014000B06C↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_1400014C0(void *Block)
sub_1400014C0   proc near               ; DATA XREF: .rdata:off_1400077C8↓o
                                        ; .rdata:staticDataMarker↓o ...

arg_0           = qword ptr  8

                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                lea     rax, off_1400074D8
                mov     rdi, rcx
                mov     [rcx], rax
                mov     ebx, edx
                add     rcx, 8
                call    cs:__std_exception_destroy
                test    bl, 1
                jz      short loc_1400014F5
                mov     edx, 28h ; '('
                mov     rcx, rdi        ; Block
                call    j_j_free

loc_1400014F5:                          ; CODE XREF: sub_1400014C0+26↑j
                mov     rbx, [rsp+28h+arg_0]
                mov     rax, rdi
                add     rsp, 20h
                pop     rdi
                retn
sub_1400014C0   endp

; ---------------------------------------------------------------------------
algn_140001503:                         ; DATA XREF: .pdata:000000014000B078↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall ProcessAndCopyData_0(_QWORD *outputPtr, __int128 *inputData)
ProcessAndCopyData_0 proc near          ; CODE XREF: ThrowException+20↓p
                                        ; ThrowErrorAndException+22↓p
                                        ; DATA XREF: ...

blockArray      = qword ptr -38h
var_28          = qword ptr -28h
dataSize        = qword ptr -20h
tempData        = xmmword ptr -18h
arg_10          = qword ptr  18h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_10], rbx
                push    rdi
                sub     rsp, 50h
                mov     rbx, rdx
                mov     rdi, rcx
                mov     qword ptr [rsp+58h+tempData], rcx
                xor     eax, eax
                mov     [rsp+58h+blockArray], rax
                mov     [rsp+58h+var_28], rax
                mov     [rsp+58h+dataSize], 0Fh
                mov     byte ptr [rsp+58h+blockArray], al
                xor     r8d, r8d        ; Size
                lea     rdx, staticData ; Src
                lea     rcx, [rsp+58h+blockArray] ; void *
                call    ResizeAndCopyData
                nop
                movups  xmm0, xmmword ptr [rbx]
                movaps  [rsp+58h+tempData], xmm0
                lea     r8, [rsp+58h+blockArray]
                lea     rdx, [rsp+58h+tempData]
                mov     rcx, rdi
                call    HandleExceptionAndCopyData
                nop
                mov     rdx, [rsp+58h+dataSize]
                cmp     rdx, 10h
                jb      short loc_1400015AE
                inc     rdx
                mov     rcx, [rsp+58h+blockArray] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_1400015A9
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_1400015A9
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400015A9:                          ; CODE XREF: ProcessAndCopyData_0+7B↑j
                                        ; ProcessAndCopyData_0+90↑j
                call    j_j_free

loc_1400015AE:                          ; CODE XREF: ProcessAndCopyData_0+67↑j
                lea     rax, staticDataMarker
                mov     [rdi], rax
                mov     rax, rdi
                mov     rbx, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                retn
; } // starts at 140001510
ProcessAndCopyData_0 endp

; ---------------------------------------------------------------------------
algn_1400015C6:                         ; DATA XREF: .pdata:000000014000B084↓o
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __noreturn ThrowException()
ThrowException  proc near               ; CODE XREF: ExtendAndCopyString_1:loc_140001A7E↓p
                                        ; sub_1400042E0:loc_140004408↓p ...

exceptionData   = xmmword ptr -58h
exceptionBuffer = byte ptr -48h
pExceptionObject= byte ptr -38h

                sub     rsp, 78h
                lea     rcx, [rsp+78h+exceptionBuffer]
                call    InitializeMemoryBlock
                lea     rdx, [rsp+78h+exceptionData]
                lea     rcx, [rsp+78h+pExceptionObject]
                movups  xmm0, xmmword ptr [rax]
                movaps  [rsp+78h+exceptionData], xmm0
                call    ProcessAndCopyData_0
                lea     rdx, exceptionTypeInfo ; pThrowInfo
                lea     rcx, [rsp+78h+pExceptionObject] ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                db 0CCh
ThrowException  endp

algn_140001607:                         ; DATA XREF: .pdata:000000014000B090↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_140001610   proc near               ; DATA XREF: .pdata:000000014000B09C↓o

arg_0           = qword ptr  8

                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                mov     rbx, rdx
                lea     rax, off_1400074D8
                mov     [rcx], rax
                lea     rdx, [rcx+8]
                mov     rdi, rcx
                xorps   xmm0, xmm0
                movups  xmmword ptr [rdx], xmm0
                lea     rcx, [rbx+8]
                call    cs:__std_exception_copy
                lea     rax, off_1400077C8
                mov     [rdi], rax
                lea     rax, staticDataMarker
                movups  xmm0, xmmword ptr [rbx+18h]
                mov     rbx, [rsp+28h+arg_0]
                mov     [rdi], rax
                mov     rax, rdi
                movups  xmmword ptr [rdi+18h], xmm0
                add     rsp, 20h
                pop     rdi
                retn
sub_140001610   endp

; ---------------------------------------------------------------------------
algn_140001668:                         ; DATA XREF: .pdata:000000014000B09C↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_140001670   proc near               ; DATA XREF: .pdata:000000014000B0A8↓o

arg_0           = qword ptr  8

                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                mov     rbx, rdx
                lea     rax, off_1400074D8
                mov     [rcx], rax
                lea     rdx, [rcx+8]
                mov     rdi, rcx
                xorps   xmm0, xmm0
                movups  xmmword ptr [rdx], xmm0
                lea     rcx, [rbx+8]
                call    cs:__std_exception_copy
                lea     rax, off_1400077C8
                mov     [rdi], rax
                mov     rax, rdi
                movups  xmm0, xmmword ptr [rbx+18h]
                mov     rbx, [rsp+28h+arg_0]
                movups  xmmword ptr [rdi+18h], xmm0
                add     rsp, 20h
                pop     rdi
                retn
sub_140001670   endp

; ---------------------------------------------------------------------------
algn_1400016BE:                         ; DATA XREF: .pdata:000000014000B0A8↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_1400016C0(_QWORD)
sub_1400016C0   proc near               ; CODE XREF: sub_140006A00+7↓j
                                        ; DATA XREF: .rdata:000000014000849B↓o
                mov     rcx, [rcx]
                jmp     LocalFree
sub_1400016C0   endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


sub_1400016D0   proc near               ; DATA XREF: .rdata:0000000140007770↓o
                lea     rax, aGeneric   ; "generic"
                retn
sub_1400016D0   endp

; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================


sub_1400016E0   proc near               ; DATA XREF: .rdata:0000000140007778↓o
                                        ; .pdata:000000014000B0B4↓o

var_10          = qword ptr -10h
arg_0           = qword ptr  8

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 30h
                mov     rbx, rdx
                mov     [rsp+38h+var_10], rdx
                xor     edi, edi
                test    r8d, r8d
                jnz     short loc_140001718
                mov     [rdx], rdi
                mov     [rdx+10h], rdi
                mov     qword ptr [rdx+18h], 0Fh
                mov     [rdx], r8b
                lea     r8d, [rdi+7]
                lea     rdx, aSuccess   ; "success"
                jmp     short loc_14000174D
; ---------------------------------------------------------------------------

loc_140001718:                          ; CODE XREF: sub_1400016E0+17↑j
                mov     ecx, r8d
                call    cs:?_Syserror_map@std@@YAPEBDH@Z ; std::_Syserror_map(int)
                mov     [rbx], rdi
                mov     [rbx+10h], rdi
                mov     qword ptr [rbx+18h], 0Fh
                mov     byte ptr [rbx], 0
                mov     r8, 0FFFFFFFFFFFFFFFFh
                nop     word ptr [rax+rax+00h]

loc_140001740:                          ; CODE XREF: sub_1400016E0+68↓j
                inc     r8              ; Size
                cmp     byte ptr [rax+r8], 0
                jnz     short loc_140001740
                mov     rdx, rax        ; Src

loc_14000174D:                          ; CODE XREF: sub_1400016E0+36↑j
                mov     rcx, rbx        ; void *
                call    ResizeAndCopyData
                mov     rax, rbx
                mov     rbx, [rsp+38h+arg_0]
                add     rsp, 30h
                pop     rdi
                retn
; } // starts at 1400016E0
sub_1400016E0   endp

; ---------------------------------------------------------------------------
algn_140001763:                         ; DATA XREF: .pdata:000000014000B0B4↓o
                align 10h
; [00000021 BYTES: COLLAPSED FUNCTION std::_Iostream_error_category2::`scalar deleting destructor'(uint). PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140001791:                         ; DATA XREF: .pdata:000000014000B0C0↓o
                align 20h

; =============== S U B R O U T I N E =======================================


sub_1400017A0   proc near               ; DATA XREF: .rdata:0000000140007810↓o
                lea     rax, aSystem    ; "system"
                retn
sub_1400017A0   endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


sub_1400017B0   proc near               ; DATA XREF: .rdata:0000000140007818↓o
                                        ; .pdata:000000014000B0CC↓o

hMem            = qword ptr -20h
var_18          = qword ptr -18h
var_10          = qword ptr -10h
arg_0           = qword ptr  8

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __GSHandlerCheck_EH4
                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 40h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rsp+48h+var_10], rax
                mov     rbx, rdx
                mov     [rsp+48h+hMem], rdx
                xor     edi, edi
                mov     [rsp+48h+hMem], rdi
                lea     rdx, [rsp+48h+hMem] ; lpBuffer
                mov     ecx, r8d        ; dwMessageId
                call    __std_system_error_allocate_message
                mov     [rsp+48h+var_18], rax
                mov     [rbx], rdi
                test    rax, rax
                jnz     short loc_14000180D
                mov     [rbx+10h], rdi
                mov     qword ptr [rbx+18h], 0Fh
                mov     [rbx], al
                lea     r8d, [rdi+0Dh]
                lea     rdx, aUnknownError ; "unknown error"
                jmp     short loc_140001824
; ---------------------------------------------------------------------------

loc_14000180D:                          ; CODE XREF: sub_1400017B0+40↑j
                mov     [rbx+10h], rdi
                mov     qword ptr [rbx+18h], 0Fh
                mov     byte ptr [rbx], 0
                mov     r8, rax         ; Size
                mov     rdx, [rsp+48h+hMem] ; Src

loc_140001824:                          ; CODE XREF: sub_1400017B0+5B↑j
                mov     rcx, rbx        ; void *
                call    ResizeAndCopyData
                nop
                mov     rcx, [rsp+48h+hMem] ; hMem
                call    LocalFree
                mov     rax, rbx
                mov     rcx, [rsp+48h+var_10]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                mov     rbx, [rsp+48h+arg_0]
                add     rsp, 40h
                pop     rdi
                retn
; } // starts at 1400017B0
sub_1400017B0   endp

; ---------------------------------------------------------------------------
algn_140001852:                         ; DATA XREF: .pdata:000000014000B0CC↓o
                align 20h

; =============== S U B R O U T I N E =======================================


sub_140001860   proc near               ; DATA XREF: .rdata:0000000140007820↓o
                                        ; .pdata:000000014000B0D8↓o

arg_0           = qword ptr  8

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                mov     edi, r8d
                mov     rbx, rdx
                test    r8d, r8d
                jnz     short loc_140001891
                mov     [rdx], r8d
                lea     rax, staticMemoryLocation
                mov     [rdx+8], rax
                mov     rax, rdx
                mov     rbx, [rsp+28h+arg_0]
                add     rsp, 20h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_140001891:                          ; CODE XREF: sub_140001860+13↑j
                mov     ecx, edi
                call    cs:?_Winerror_map@std@@YAHH@Z ; std::_Winerror_map(int)
                test    eax, eax
                jnz     short loc_1400018B8
                mov     [rbx], edi
                lea     rax, off_14000A048
                mov     [rbx+8], rax
                mov     rax, rbx
                mov     rbx, [rsp+28h+arg_0]
                add     rsp, 20h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_1400018B8:                          ; CODE XREF: sub_140001860+3B↑j
                mov     [rbx], eax
                lea     rax, staticMemoryLocation
                mov     [rbx+8], rax
                mov     rax, rbx
                mov     rbx, [rsp+28h+arg_0]
                add     rsp, 20h
                pop     rdi
                retn
; } // starts at 140001860
sub_140001860   endp

; ---------------------------------------------------------------------------
algn_1400018D3:                         ; DATA XREF: .pdata:000000014000B0D8↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; int __cdecl UserMathErrorFunction(struct _exception *)
UserMathErrorFunction proc near         ; CODE XREF: pre_c_initialization(void)+1C↓p
                                        ; pre_c_initialization(void)+7D↓p ...
                xor     eax, eax
                retn
UserMathErrorFunction endp

; ---------------------------------------------------------------------------
                align 10h
; [00000011 BYTES: COLLAPSED FUNCTION std::make_error_code(std::io_errc). PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __fastcall __noreturn ThrowErrorAndException(unsigned int errorCode, __int64 param1, __int64 param2, __int64 param3)
ThrowErrorAndException proc near        ; CODE XREF: ExtendAndCopyString_1+128↓p
                                        ; ExtendAndCopyString_1+136↓p ...

errorData       = xmmword ptr -58h
errorBuffer     = byte ptr -48h
pExceptionObject= qword ptr -38h

                sub     rsp, 78h
                mov     edx, ecx
                lea     rcx, [rsp+78h+errorBuffer]
                call    ?make_error_code@std@@YA?AVerror_code@1@W4io_errc@1@@Z ; std::make_error_code(std::io_errc)
                lea     rdx, [rsp+78h+errorData]
                lea     rcx, [rsp+78h+pExceptionObject]
                movups  xmm0, xmmword ptr [rax]
                movaps  [rsp+78h+errorData], xmm0
                call    ProcessAndCopyData_0
                lea     rdx, exceptionTypeInfo ; pThrowInfo
                lea     rcx, [rsp+78h+pExceptionObject] ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                db 0CCh
ThrowErrorAndException endp

algn_140001949:                         ; DATA XREF: .pdata:000000014000B0E4↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; const void **__fastcall ExtendAndCopyString_1(const void **Src, unsigned int codePage, _QWORD *sourceData)
ExtendAndCopyString_1 proc near         ; CODE XREF: ProcessDirectory+14F↓p
                                        ; DATA XREF: .pdata:000000014000B0F0↓o

var_58          = dword ptr -58h
var_48          = dword ptr -48h
var_40          = qword ptr -40h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006A10 SIZE 00000026 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                push    rbp
                push    rsi
                push    rdi
                push    r12
                push    r14
                push    r15
                sub     rsp, 40h
                mov     r15d, edx
                mov     rsi, rcx
                mov     [rsp+78h+var_40], rcx
                xor     r12d, r12d
                mov     [rsp+78h+var_48], r12d
                mov     [rcx], r12
                mov     [rcx+10h], r12
                mov     qword ptr [rcx+18h], 7
                mov     [rcx], r12w
                mov     [rsp+78h+var_48], 1
                mov     rbp, [r8+8]
                test    rbp, rbp
                jz      loc_140001A64
                cmp     rbp, 7FFFFFFFh
                ja      loc_140001A7E
                mov     r14, [r8]
                mov     [rsp+78h+var_58], r12d
                xor     r9d, r9d
                mov     r8d, ebp
                mov     rdx, r14
                mov     ecx, r15d
                call    __std_fs_convert_narrow_to_wide
                mov     rbx, rax
                shr     rax, 20h
                test    eax, eax
                jnz     loc_140001A84
                movsxd  rdx, ebx
                mov     rdi, [rsi+10h]
                cmp     rdx, rdi
                ja      short loc_1400019F3
                mov     rax, rsi
                cmp     qword ptr [rsi+18h], 8
                jb      short loc_1400019E8
                mov     rax, [rsi]

loc_1400019E8:                          ; CODE XREF: ExtendAndCopyString_1+93↑j
                mov     [rsi+10h], rdx
                mov     [rax+rdx*2], r12w
                jmp     short loc_140001A3D
; ---------------------------------------------------------------------------

loc_1400019F3:                          ; CODE XREF: ExtendAndCopyString_1+89↑j
                mov     rcx, rdx
                sub     rcx, rdi
                mov     r9, [rsi+18h]
                mov     rax, r9
                sub     rax, rdi
                cmp     rcx, rax
                ja      short loc_140001A2F
                mov     [rsi+10h], rdx
                mov     r8, rsi
                cmp     r9, 8
                jb      short loc_140001A18
                mov     r8, [rsi]

loc_140001A18:                          ; CODE XREF: ExtendAndCopyString_1+C3↑j
                lea     rdi, [r8+rdi*2]
                test    rcx, rcx
                jz      short loc_140001A28
                movzx   eax, r12w
                rep stosw

loc_140001A28:                          ; CODE XREF: ExtendAndCopyString_1+CF↑j
                mov     [r8+rdx*2], r12w
                jmp     short loc_140001A3D
; ---------------------------------------------------------------------------

loc_140001A2F:                          ; CODE XREF: ExtendAndCopyString_1+B6↑j
                mov     r9, rcx
                mov     rdx, rcx
                mov     rcx, rsi        ; Src
                call    ExtendAndCopyString_0

loc_140001A3D:                          ; CODE XREF: ExtendAndCopyString_1+A1↑j
                                        ; ExtendAndCopyString_1+DD↑j
                mov     r9, rsi
                cmp     qword ptr [rsi+18h], 8
                jb      short loc_140001A4A
                mov     r9, [rsi]

loc_140001A4A:                          ; CODE XREF: ExtendAndCopyString_1+F5↑j
                mov     [rsp+78h+var_58], ebx
                mov     r8d, ebp
                mov     rdx, r14
                mov     ecx, r15d
                call    __std_fs_convert_narrow_to_wide
                shr     rax, 20h
                test    eax, eax
                jnz     short loc_140001A76

loc_140001A64:                          ; CODE XREF: ExtendAndCopyString_1+44↑j
                mov     rax, rsi
                add     rsp, 40h
                pop     r15
                pop     r14
                pop     r12
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140001A76:                          ; CODE XREF: ExtendAndCopyString_1+112↑j
                mov     ecx, eax
                call    ThrowErrorAndException
; ---------------------------------------------------------------------------
                align 2

loc_140001A7E:                          ; CODE XREF: ExtendAndCopyString_1+51↑j
                call    ThrowException
; ---------------------------------------------------------------------------
                align 4

loc_140001A84:                          ; CODE XREF: ExtendAndCopyString_1+79↑j
                mov     ecx, eax
                call    ThrowErrorAndException
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 140001950
ExtendAndCopyString_1 endp

algn_140001A8C:                         ; DATA XREF: .pdata:000000014000B0F0↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; int *__fastcall ProcessPath(int *inputPath, char *endPointer)
ProcessPath     proc near               ; CODE XREF: ProcessAndCopyData+BA↓p
                                        ; ProcessAndCopyData+C8↓p ...
                mov     r8, rdx
                sub     r8, rcx
                sar     r8, 1
                cmp     r8, 2
                jl      loc_140001B79
                mov     r9d, [rcx]
                mov     eax, r9d
                and     eax, 0FFFFFFDFh
                sub     eax, 3A0041h
                cmp     eax, 1Ah
                jnb     short loc_140001ABB
                lea     rax, [rcx+4]
                retn
; ---------------------------------------------------------------------------

loc_140001ABB:                          ; CODE XREF: ProcessPath+24↑j
                cmp     r9w, 5Ch ; '\'
                jz      short loc_140001ACD
                cmp     r9w, 2Fh ; '/'
                jnz     loc_140001B79

loc_140001ACD:                          ; CODE XREF: ProcessPath+30↑j
                cmp     r8, 4
                jl      short loc_140001B2D
                movzx   eax, word ptr [rcx+6]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001AE3
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140001B33

loc_140001AE3:                          ; CODE XREF: ProcessPath+4B↑j
                cmp     r8, 4
                jz      short loc_140001AF9
                movzx   eax, word ptr [rcx+8]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001B33
                cmp     ax, 2Fh ; '/'
                jz      short loc_140001B33

loc_140001AF9:                          ; CODE XREF: ProcessPath+57↑j
                movzx   eax, word ptr [rcx+2]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001B09
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140001B1C

loc_140001B09:                          ; CODE XREF: ProcessPath+71↑j
                movzx   r8d, word ptr [rcx+4]
                cmp     r8w, 3Fh ; '?'
                jz      short loc_140001B28
                cmp     r8w, 2Eh ; '.'
                jz      short loc_140001B28

loc_140001B1C:                          ; CODE XREF: ProcessPath+77↑j
                cmp     ax, 3Fh ; '?'
                jnz     short loc_140001B33
                cmp     [rcx+4], ax
                jnz     short loc_140001B33

loc_140001B28:                          ; CODE XREF: ProcessPath+83↑j
                                        ; ProcessPath+8A↑j
                lea     rax, [rcx+6]
                retn
; ---------------------------------------------------------------------------

loc_140001B2D:                          ; CODE XREF: ProcessPath+41↑j
                cmp     r8, 3
                jl      short loc_140001B79

loc_140001B33:                          ; CODE XREF: ProcessPath+51↑j
                                        ; ProcessPath+61↑j ...
                movzx   eax, word ptr [rcx+2]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001B43
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140001B79

loc_140001B43:                          ; CODE XREF: ProcessPath+AB↑j
                movzx   eax, word ptr [rcx+4]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001B79
                cmp     ax, 2Fh ; '/'
                jz      short loc_140001B79
                lea     rax, [rcx+6]
                cmp     rax, rdx
                jz      short locret_140001B7C
                nop     dword ptr [rax+00h]

loc_140001B60:                          ; CODE XREF: ProcessPath+E6↓j
                movzx   ecx, word ptr [rax]
                cmp     cx, 5Ch ; '\'
                jz      short locret_140001B7C
                cmp     cx, 2Fh ; '/'
                jz      short locret_140001B7C
                add     rax, 2
                cmp     rax, rdx
                jnz     short loc_140001B60
                retn
; ---------------------------------------------------------------------------

loc_140001B79:                          ; CODE XREF: ProcessPath+D↑j
                                        ; ProcessPath+37↑j ...
                mov     rax, rcx

locret_140001B7C:                       ; CODE XREF: ProcessPath+CA↑j
                                        ; ProcessPath+D7↑j ...
                retn
ProcessPath     endp

; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================


; bool __fastcall CheckExtension(_WORD *filePath)
CheckExtension  proc near               ; CODE XREF: OpenAndIterateDirectory+F4↓p
                                        ; OpenAndIterateDirectory+112↓p
                cmp     word ptr [rcx+2Ch], 2Eh ; '.'
                jnz     short loc_140001BA2
                movzx   eax, word ptr [rcx+2Eh]
                test    ax, ax
                jnz     short loc_140001B93
                mov     al, 1
                retn
; ---------------------------------------------------------------------------

loc_140001B93:                          ; CODE XREF: CheckExtension+E↑j
                cmp     ax, 2Eh ; '.'
                jnz     short loc_140001BA2
                cmp     word ptr [rcx+30h], 0
                setz    al
                retn
; ---------------------------------------------------------------------------

loc_140001BA2:                          ; CODE XREF: CheckExtension+5↑j
                                        ; CheckExtension+17↑j
                xor     al, al
                retn
CheckExtension  endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


sub_140001BB0   proc near               ; CODE XREF: ProcessAndUpdate+3C07↓j
                                        ; ProcessFiles+2817↓j
                mov     rcx, [rcx]
                jmp     CloseFileHandleAndCheck
sub_140001BB0   endp

; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall ProcessAndCopyData(_QWORD *Dest, _QWORD *Source)
ProcessAndCopyData proc near            ; CODE XREF: OpenAndIterateDirectory+87↓p
                                        ; ProcessAndUpdateData+BE↓p
                                        ; DATA XREF: ...

var_58          = qword ptr -58h
var_48          = qword ptr -48h
var_40          = qword ptr -40h
var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h
var_20          = qword ptr -20h
arg_10          = qword ptr  18h

                push    rbx
                push    rsi
                push    rdi
                sub     rsp, 60h
                mov     rsi, [rdx+18h]
                mov     r11, rdx
                mov     rbx, rcx
                mov     r10, rdx
                cmp     rsi, 8
                jb      short loc_140001BDE
                mov     r10, [rdx]

loc_140001BDE:                          ; CODE XREF: ProcessAndCopyData+19↑j
                mov     rdi, [rdx+10h]
                add     rdi, rdi
                mov     rcx, rdi
                sar     rcx, 1
                lea     rdx, [rdi+r10]
                cmp     rcx, 2
                jl      loc_140001D06
                mov     eax, [r10]
                and     eax, 0FFFFFFDFh
                sub     eax, 3A0041h
                cmp     eax, 1Ah
                jnb     loc_140001D06
                cmp     rcx, 3
                jl      short loc_140001C2C
                movzx   eax, word ptr [r10+4]
                cmp     ax, 5Ch ; '\'
                jz      loc_140001D17
                cmp     ax, 2Fh ; '/'
                jz      loc_140001D17

loc_140001C2C:                          ; CODE XREF: ProcessAndCopyData+51↑j
                                        ; ProcessAndCopyData+151↓j
                                        ; DATA XREF: ...
                mov     [rsp+78h+arg_10], rbp
                mov     rbp, [rbx+18h]
                mov     [rsp+78h+var_20], r12
                mov     [rsp+78h+var_28], r13
                mov     [rsp+78h+var_30], r14
                mov     r14, rbx
                mov     [rsp+78h+var_38], r15
                cmp     rbp, 8
                jb      short loc_140001C58
                mov     r14, [rbx]

loc_140001C58:                          ; CODE XREF: ProcessAndCopyData+93↑j
                mov     r15, [rbx+10h]
                mov     r10, r11
                lea     r13, [r14+r15*2]
                mov     [rsp+78h+var_40], r13
                cmp     rsi, 8
                jb      short loc_140001C71
                mov     r10, [r11]

loc_140001C71:                          ; CODE XREF: ProcessAndCopyData+AC↑j
                mov     rdx, r13
                mov     rcx, r14
                add     rdi, r10
                call    ProcessPath
                mov     rcx, r10
                mov     rdx, rdi
                mov     rsi, rax
                call    ProcessPath
                mov     r8, rsi
                mov     r12, rax
                sub     r8, r14
                cmp     r10, rax
                jz      loc_140001D3A
                mov     r13, rax
                mov     rax, r8
                sar     rax, 1
                sub     r13, r10
                sar     r13, 1
                mov     rdx, rax
                cmp     r13, rax
                mov     [rsp+78h+var_48], rax
                cmovb   rdx, r13
                test    rdx, rdx
                jz      short loc_140001D2E
                movzx   eax, word ptr [r14]
                movzx   ecx, word ptr [r10]
                cmp     ax, cx
                jb      short loc_140001CF6
                mov     r9, r14
                sub     r9, r10
                cmp     ax, cx

loc_140001CD8:                          ; CODE XREF: ProcessAndCopyData+134↓j
                ja      short loc_140001CF6
                cmp     rdx, 1
                jz      short loc_140001D29
                movzx   eax, word ptr [r10+r9+2]
                add     r10, 2
                dec     rdx
                movzx   ecx, word ptr [r10]
                cmp     ax, cx
                jnb     short loc_140001CD8

loc_140001CF6:                          ; CODE XREF: ProcessAndCopyData+10D↑j
                                        ; ProcessAndCopyData:loc_140001CD8↑j ...
                mov     rdx, r11
                mov     rcx, rbx        ; void *
                call    CopyAndResizeString
                jmp     loc_140001E25
; ---------------------------------------------------------------------------

loc_140001D06:                          ; CODE XREF: ProcessAndCopyData+33↑j
                                        ; ProcessAndCopyData+47↑j
                                        ; DATA XREF: ...
                mov     rcx, r10
                call    ProcessPath
                cmp     r10, rax
                jz      loc_140001C2C

loc_140001D17:                          ; CODE XREF: ProcessAndCopyData+5C↑j
                                        ; ProcessAndCopyData+66↑j
                mov     rdx, r11
                mov     rcx, rbx        ; void *
                add     rsp, 60h
                pop     rdi
                pop     rsi
                pop     rbx
                jmp     CopyAndResizeString
; ---------------------------------------------------------------------------

loc_140001D29:                          ; CODE XREF: ProcessAndCopyData+11E↑j
                                        ; DATA XREF: .pdata:000000014000B114↓o ...
                mov     rax, [rsp+78h+var_48]

loc_140001D2E:                          ; CODE XREF: ProcessAndCopyData+100↑j
                cmp     rax, r13
                jb      short loc_140001CF6
                ja      short loc_140001CF6
                mov     r13, [rsp+78h+var_40]

loc_140001D3A:                          ; CODE XREF: ProcessAndCopyData+D9↑j
                xor     ecx, ecx
                cmp     r12, rdi
                jz      short loc_140001D77
                movzx   eax, word ptr [r12]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001D52
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140001D77

loc_140001D52:                          ; CODE XREF: ProcessAndCopyData+18A↑j
                sub     rsi, r14
                sar     rsi, 1
                cmp     r15, rsi
                jb      loc_140001E49
                mov     rax, rbx
                cmp     rbp, 8
                jb      short loc_140001D6D
                mov     rax, [rbx]

loc_140001D6D:                          ; CODE XREF: ProcessAndCopyData+1A8↑j
                mov     [rbx+10h], rsi
                mov     [rax+rsi*2], cx
                jmp     short loc_140001DCA
; ---------------------------------------------------------------------------

loc_140001D77:                          ; CODE XREF: ProcessAndCopyData+17F↑j
                                        ; ProcessAndCopyData+190↑j
                cmp     rsi, r13
                jnz     short loc_140001D88
                and     r8, 0FFFFFFFFFFFFFFFEh
                cmp     r8, 6
                jl      short loc_140001DCA
                jmp     short loc_140001D99
; ---------------------------------------------------------------------------

loc_140001D88:                          ; CODE XREF: ProcessAndCopyData+1BA↑j
                movzx   eax, word ptr [r13-2]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001DCA
                cmp     ax, 2Fh ; '/'
                jz      short loc_140001DCA

loc_140001D99:                          ; CODE XREF: ProcessAndCopyData+1C6↑j
                cmp     r15, rbp
                jnb     short loc_140001DBC
                lea     rax, [r15+1]
                mov     [rbx+10h], rax
                mov     rax, rbx
                cmp     rbp, 8
                jb      short loc_140001DB2
                mov     rax, [rbx]

loc_140001DB2:                          ; CODE XREF: ProcessAndCopyData+1ED↑j
                mov     dword ptr [rax+r15*2], 5Ch ; '\'
                jmp     short loc_140001DCA
; ---------------------------------------------------------------------------

loc_140001DBC:                          ; CODE XREF: ProcessAndCopyData+1DC↑j
                mov     r9d, 5Ch ; '\'
                mov     rcx, rbx        ; Src
                call    ModifyAndCopyData

loc_140001DCA:                          ; CODE XREF: ProcessAndCopyData+1B5↑j
                                        ; ProcessAndCopyData+1C4↑j ...
                mov     rdx, [rbx+18h]
                sub     rdi, r12
                mov     rcx, [rbx+10h]
                mov     rax, rdx
                sub     rax, rcx
                sar     rdi, 1
                cmp     rdi, rax
                ja      short loc_140001E0F
                lea     rbp, [rcx+rdi]
                mov     rsi, rbx
                mov     [rbx+10h], rbp
                cmp     rdx, 8
                jb      short loc_140001DF7
                mov     rsi, [rbx]

loc_140001DF7:                          ; CODE XREF: ProcessAndCopyData+232↑j
                lea     rcx, [rsi+rcx*2] ; void *
                mov     rdx, r12        ; Src
                lea     r8, [rdi+rdi]   ; Size
                call    memmove
                xor     eax, eax
                mov     [rsi+rbp*2], ax
                jmp     short loc_140001E22
; ---------------------------------------------------------------------------

loc_140001E0F:                          ; CODE XREF: ProcessAndCopyData+221↑j
                mov     r9, r12
                mov     [rsp+78h+var_58], rdi ; __int64
                mov     rdx, rdi
                mov     rcx, rbx        ; Src
                call    ModifyAndCopyData_0

loc_140001E22:                          ; CODE XREF: ProcessAndCopyData+24D↑j
                mov     rax, rbx

loc_140001E25:                          ; CODE XREF: ProcessAndCopyData+141↑j
                mov     r14, [rsp+78h+var_30]
                mov     r13, [rsp+78h+var_28]
                mov     r12, [rsp+78h+var_20]
                mov     rbp, [rsp+78h+arg_10]
                mov     r15, [rsp+78h+var_38]
                add     rsp, 60h
                pop     rdi
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140001E49:                          ; CODE XREF: ProcessAndCopyData+19B↑j
                                        ; DATA XREF: .pdata:000000014000B120↓o ...
                call    HandleInvalidStringPosition
; ---------------------------------------------------------------------------
                db 0CCh
ProcessAndCopyData endp

algn_140001E4F:                         ; DATA XREF: .pdata:000000014000B12C↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall ProcessContent(_QWORD *inputData)
ProcessContent  proc near               ; CODE XREF: ProcessAndUpdateData+B1↓p
                                        ; main+156↓p
                                        ; DATA XREF: ...
; __unwind { // __CxxFrameHandler4
                push    rdi
                sub     rsp, 20h
                mov     r10, rcx
                mov     r11, rcx
                cmp     qword ptr [rcx+18h], 8
                jb      short loc_140001E66
                mov     r11, [rcx]

loc_140001E66:                          ; CODE XREF: ProcessContent+11↑j
                mov     rdi, [rcx+10h]
                lea     rdx, [r11+rdi*2]
                mov     rcx, r11
                call    ProcessPath
                cmp     rax, rdx
                jz      short loc_140001EBC
                nop     dword ptr [rax+rax+00h]

loc_140001E80:                          ; CODE XREF: ProcessContent+46↓j
                movzx   ecx, word ptr [rax]
                cmp     cx, 5Ch ; '\'
                jz      short loc_140001E8F
                cmp     cx, 2Fh ; '/'
                jnz     short loc_140001E98

loc_140001E8F:                          ; CODE XREF: ProcessContent+37↑j
                add     rax, 2
                cmp     rax, rdx
                jnz     short loc_140001E80

loc_140001E98:                          ; CODE XREF: ProcessContent+3D↑j
                cmp     rax, rdx
                jz      short loc_140001EBC
                nop     dword ptr [rax]

loc_140001EA0:                          ; CODE XREF: ProcessContent+6A↓j
                lea     r8, [rdx-2]
                movzx   ecx, word ptr [r8]
                cmp     cx, 5Ch ; '\'
                jz      short loc_140001EBC
                cmp     cx, 2Fh ; '/'
                jz      short loc_140001EBC
                mov     rdx, r8
                cmp     rax, r8
                jnz     short loc_140001EA0

loc_140001EBC:                          ; CODE XREF: ProcessContent+29↑j
                                        ; ProcessContent+4B↑j ...
                sub     rdx, r11
                sar     rdx, 1
                cmp     rdi, rdx
                jb      short loc_140001EE7
                mov     rax, r10
                cmp     qword ptr [r10+18h], 8
                jb      short loc_140001ED4
                mov     rax, [r10]

loc_140001ED4:                          ; CODE XREF: ProcessContent+7F↑j
                mov     [r10+10h], rdx
                xor     ecx, ecx
                mov     [rax+rdx*2], cx
                mov     rax, r10
                add     rsp, 20h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_140001EE7:                          ; CODE XREF: ProcessContent+75↑j
                call    HandleInvalidStringPosition
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 140001E50
ProcessContent  endp

algn_140001EED:                         ; DATA XREF: .pdata:000000014000B138↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall ComparePaths(__int64)
ComparePaths    proc near               ; CODE XREF: ProcessDirectory+199↓p
                                        ; DATA XREF: .pdata:000000014000B144↓o

arg_10          = qword ptr  18h

                mov     [rsp+arg_10], rbx
                push    rbp
                push    rsi
                push    rdi
                sub     rsp, 20h
                cmp     qword ptr [rcx+18h], 8
                mov     r11, rdx
                mov     rdi, rcx
                jb      short loc_140001F0C
                mov     rdi, [rcx]

loc_140001F0C:                          ; CODE XREF: ComparePaths+17↑j
                mov     rax, [rcx+10h]
                mov     rcx, rdi
                lea     r10, [rdi+rax*2]
                mov     rdx, r10
                call    ProcessPath
                mov     rcx, [r11+8]
                mov     rsi, rax
                mov     rbx, [r11]
                lea     r11, [rbx+rcx*2]
                mov     rcx, rbx
                mov     rdx, r11
                call    ProcessPath
                mov     r8, rax
                mov     r9, rsi
                sub     r8, rbx
                sub     r9, rdi
                sar     r8, 1
                mov     rbp, rax
                sar     r9, 1
                cmp     r8, r9
                mov     rdx, r9
                cmovb   rdx, r8
                test    rdx, rdx
                jz      short loc_140001F9D
                movzx   eax, word ptr [rdi]
                movzx   ecx, word ptr [rbx]
                cmp     ax, cx
                jb      short loc_140001F89
                sub     rdi, rbx
                cmp     ax, cx

loc_140001F6D:                          ; CODE XREF: ComparePaths+97↓j
                ja      short loc_140001FA4
                cmp     rdx, 1
                jz      short loc_140001F9D
                movzx   eax, word ptr [rdi+rbx+2]
                add     rbx, 2
                dec     rdx
                movzx   ecx, word ptr [rbx]
                cmp     ax, cx
                jnb     short loc_140001F6D

loc_140001F89:                          ; CODE XREF: ComparePaths+75↑j
                                        ; ComparePaths+B0↓j
                mov     esi, 0FFFFFFFFh
                mov     eax, esi
                mov     rbx, [rsp+38h+arg_10]
                add     rsp, 20h
                pop     rdi
                pop     rsi
                pop     rbp
                retn
; ---------------------------------------------------------------------------

loc_140001F9D:                          ; CODE XREF: ComparePaths+6A↑j
                                        ; ComparePaths+83↑j
                cmp     r9, r8
                jb      short loc_140001F89
                jbe     short loc_140001FB8

loc_140001FA4:                          ; CODE XREF: ComparePaths:loc_140001F6D↑j
                mov     esi, 1
                mov     eax, esi
                mov     rbx, [rsp+38h+arg_10]
                add     rsp, 20h
                pop     rdi
                pop     rsi
                pop     rbp
                retn
; ---------------------------------------------------------------------------

loc_140001FB8:                          ; CODE XREF: ComparePaths+B2↑j
                mov     rcx, rsi
                cmp     rsi, r10
                jz      short loc_140001FD8

loc_140001FC0:                          ; CODE XREF: ComparePaths+E6↓j
                movzx   eax, word ptr [rcx]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001FCF
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140001FD8

loc_140001FCF:                          ; CODE XREF: ComparePaths+D7↑j
                add     rcx, 2
                cmp     rcx, r10
                jnz     short loc_140001FC0

loc_140001FD8:                          ; CODE XREF: ComparePaths+CE↑j
                                        ; ComparePaths+DD↑j
                mov     r8, rbp
                cmp     rbp, r11
                jz      short loc_140001FF9

loc_140001FE0:                          ; CODE XREF: ComparePaths+107↓j
                movzx   eax, word ptr [r8]
                cmp     ax, 5Ch ; '\'
                jz      short loc_140001FF0
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140001FF9

loc_140001FF0:                          ; CODE XREF: ComparePaths+F8↑j
                add     r8, 2
                cmp     r8, r11
                jnz     short loc_140001FE0

loc_140001FF9:                          ; CODE XREF: ComparePaths+EE↑j
                                        ; ComparePaths+FE↑j
                xor     edx, edx
                cmp     rbp, r8
                setnz   dl
                xor     eax, eax
                cmp     rsi, rcx
                setnz   al
                sub     eax, edx
                jnz     loc_1400020E7
                xor     edx, edx
                cmp     r8, r11
                setz    dl
                cmp     rcx, r10
                setz    al
                sub     edx, eax
                cmp     rcx, r10
                jz      loc_1400020E5
                mov     esi, 1
                nop

loc_140002030:                          ; CODE XREF: ComparePaths+1EF↓j
                test    edx, edx
                jnz     loc_1400020E5
                movzx   ebx, word ptr [rcx]
                cmp     ebx, 5Ch ; '\'
                jz      short loc_14000204A
                cmp     ebx, 2Fh ; '/'
                jz      short loc_14000204A
                xor     r9b, r9b
                jmp     short loc_14000204E
; ---------------------------------------------------------------------------

loc_14000204A:                          ; CODE XREF: ComparePaths+14E↑j
                                        ; ComparePaths+153↑j
                movzx   r9d, sil

loc_14000204E:                          ; CODE XREF: ComparePaths+158↑j
                movzx   edi, word ptr [r8]
                cmp     edi, 5Ch ; '\'
                jz      short loc_140002060
                cmp     edi, 2Fh ; '/'
                jz      short loc_140002060
                xor     edx, edx
                jmp     short loc_140002062
; ---------------------------------------------------------------------------

loc_140002060:                          ; CODE XREF: ComparePaths+165↑j
                                        ; ComparePaths+16A↑j
                mov     edx, esi

loc_140002062:                          ; CODE XREF: ComparePaths+16E↑j
                movzx   eax, r9b
                sub     edx, eax
                jnz     short loc_1400020E5
                test    r9b, r9b
                jz      short loc_1400020BC
                add     rcx, 2
                cmp     rcx, r10
                jz      short loc_140002098
                nop     dword ptr [rax+rax+00000000h]

loc_140002080:                          ; CODE XREF: ComparePaths+1A6↓j
                movzx   eax, word ptr [rcx]
                cmp     ax, 5Ch ; '\'
                jz      short loc_14000208F
                cmp     ax, 2Fh ; '/'
                jnz     short loc_140002098

loc_14000208F:                          ; CODE XREF: ComparePaths+197↑j
                add     rcx, 2
                cmp     rcx, r10
                jnz     short loc_140002080

loc_140002098:                          ; CODE XREF: ComparePaths+186↑j
                                        ; ComparePaths+19D↑j
                add     r8, 2
                cmp     r8, r11
                jz      short loc_1400020CA

loc_1400020A1:                          ; CODE XREF: ComparePaths+1C8↓j
                movzx   eax, word ptr [r8]
                cmp     ax, 5Ch ; '\'
                jz      short loc_1400020B1
                cmp     ax, 2Fh ; '/'
                jnz     short loc_1400020CA

loc_1400020B1:                          ; CODE XREF: ComparePaths+1B9↑j
                add     r8, 2
                cmp     r8, r11
                jnz     short loc_1400020A1
                jmp     short loc_1400020CA
; ---------------------------------------------------------------------------

loc_1400020BC:                          ; CODE XREF: ComparePaths+17D↑j
                mov     edx, ebx
                sub     edx, edi
                jnz     short loc_1400020E5
                add     rcx, 2
                add     r8, 2

loc_1400020CA:                          ; CODE XREF: ComparePaths+1AF↑j
                                        ; ComparePaths+1BF↑j ...
                xor     edx, edx
                cmp     r8, r11
                setz    dl
                xor     eax, eax
                cmp     rcx, r10
                setz    al
                sub     edx, eax
                cmp     rcx, r10
                jnz     loc_140002030

loc_1400020E5:                          ; CODE XREF: ComparePaths+134↑j
                                        ; ComparePaths+142↑j ...
                mov     eax, edx

loc_1400020E7:                          ; CODE XREF: ComparePaths+11B↑j
                mov     rbx, [rsp+38h+arg_10]
                add     rsp, 20h
                pop     rdi
                pop     rsi
                pop     rbp
                retn
ComparePaths    endp

; ---------------------------------------------------------------------------
algn_1400020F4:                         ; DATA XREF: .pdata:000000014000B144↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall CreatePathFromSegments(__int64 inputPath, _QWORD *outputPath)
CreatePathFromSegments proc near        ; CODE XREF: ProcessDirectory+15D↓p
                                        ; DATA XREF: .pdata:000000014000B150↓o

var_10          = qword ptr -10h
arg_0           = qword ptr  8
arg_10          = qword ptr  18h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_0], rbx
                mov     [rsp+arg_10], rsi
                push    rdi
                sub     rsp, 30h
                mov     rdi, rdx
                mov     [rsp+38h+var_10], rdx
                xor     esi, esi
                mov     r8, rcx
                cmp     qword ptr [rcx+18h], 8
                jb      short loc_140002126
                mov     r8, [rcx]

loc_140002126:                          ; CODE XREF: CreatePathFromSegments+21↑j
                mov     rax, [rcx+10h]
                lea     r11, [r8+rax*2]
                mov     r10, r11
                mov     rdx, r11
                mov     rcx, r8
                call    ProcessPath
                cmp     rax, r11
                jz      short loc_14000217B

loc_140002141:                          ; CODE XREF: CreatePathFromSegments+57↓j
                movzx   ecx, word ptr [rax]
                cmp     cx, 5Ch ; '\'
                jz      short loc_140002150
                cmp     cx, 2Fh ; '/'
                jnz     short loc_140002159

loc_140002150:                          ; CODE XREF: CreatePathFromSegments+48↑j
                add     rax, 2
                cmp     rax, r11
                jnz     short loc_140002141

loc_140002159:                          ; CODE XREF: CreatePathFromSegments+4E↑j
                cmp     rax, r11
                jz      short loc_14000217B
                xchg    ax, ax

loc_140002160:                          ; CODE XREF: CreatePathFromSegments+79↓j
                lea     rcx, [r10-2]
                movzx   edx, word ptr [rcx]
                cmp     dx, 5Ch ; '\'
                jz      short loc_14000217B
                cmp     dx, 2Fh ; '/'
                jz      short loc_14000217B
                mov     r10, rcx
                cmp     rax, rcx
                jnz     short loc_140002160

loc_14000217B:                          ; CODE XREF: CreatePathFromSegments+3F↑j
                                        ; CreatePathFromSegments+5C↑j ...
                mov     rdx, r10
                cmp     r10, r11
                jz      short loc_1400021D1

loc_140002183:                          ; CODE XREF: CreatePathFromSegments+90↓j
                cmp     word ptr [rdx], 3Ah ; ':'
                jz      short loc_140002192
                add     rdx, 2
                cmp     rdx, r11
                jnz     short loc_140002183

loc_140002192:                          ; CODE XREF: CreatePathFromSegments+87↑j
                cmp     r10, rdx
                jz      short loc_1400021D1
                lea     r9, [rdx-2]
                cmp     r10, r9
                jz      short loc_1400021D1
                cmp     word ptr [r9], 2Eh ; '.'
                jnz     short loc_1400021B8
                lea     rax, [r9-2]
                cmp     r10, rax
                jnz     short loc_1400021D4
                cmp     word ptr [rax], 2Eh ; '.'
                jnz     short loc_1400021D4
                jmp     short loc_1400021D1
; ---------------------------------------------------------------------------

loc_1400021B8:                          ; CODE XREF: CreatePathFromSegments+A5↑j
                sub     r9, 2
                cmp     r10, r9
                jz      short loc_1400021D1

loc_1400021C1:                          ; CODE XREF: CreatePathFromSegments+CF↓j
                cmp     word ptr [r9], 2Eh ; '.'
                jz      short loc_1400021D4
                sub     r9, 2
                cmp     r10, r9
                jnz     short loc_1400021C1

loc_1400021D1:                          ; CODE XREF: CreatePathFromSegments+81↑j
                                        ; CreatePathFromSegments+95↑j ...
                mov     r9, rdx

loc_1400021D4:                          ; CODE XREF: CreatePathFromSegments+AE↑j
                                        ; CreatePathFromSegments+B4↑j ...
                sub     rdx, r9
                sar     rdx, 1
                mov     [rdi], rsi
                mov     [rdi+10h], rsi
                mov     qword ptr [rdi+18h], 7
                mov     [rdi], si
                mov     rcx, rdi        ; void *
                cmp     rdx, 7
                ja      short loc_14000221F
                mov     [rdi+10h], rdx
                lea     rbx, [rdx+rdx]
                mov     r8, rbx         ; Size
                mov     rdx, r9         ; Src
                call    memmove
                mov     [rbx+rdi], si
                mov     rax, rdi
                mov     rbx, [rsp+38h+arg_0]
                mov     rsi, [rsp+38h+arg_10]
                add     rsp, 30h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_14000221F:                          ; CODE XREF: CreatePathFromSegments+F3↑j
                call    AllocateAndCopyStringToStruct
                mov     rax, rdi
                mov     rbx, [rsp+38h+arg_0]
                mov     rsi, [rsp+38h+arg_10]
                add     rsp, 30h
                pop     rdi
                retn
; } // starts at 140002100
CreatePathFromSegments endp

; ---------------------------------------------------------------------------
algn_140002237:                         ; DATA XREF: .pdata:000000014000B150↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; char *__fastcall CopyAndResizeString(char *destination, char *source, __int64 length)
CopyAndResizeString proc near           ; CODE XREF: ProcessAndCopyData+13C↑p
                                        ; ProcessAndCopyData+164↑j
                                        ; DATA XREF: ...

arg_0           = qword ptr  8
arg_8           = qword ptr  10h

                push    rdi
                sub     rsp, 20h
                mov     rdi, rcx
                cmp     rcx, rdx
                jz      short loc_1400022B5
                cmp     qword ptr [rdx+18h], 8
                mov     rax, [rdx+10h]
                jb      short loc_14000225C
                mov     rdx, [rdx]      ; Src

loc_14000225C:                          ; CODE XREF: CopyAndResizeString+17↑j
                mov     rcx, [rcx+18h]
                cmp     rax, rcx
                ja      short loc_1400022A7

loc_140002265:                          ; DATA XREF: .rdata:00000001400085D0↓o
                                        ; .rdata:00000001400085E0↓o ...
                mov     [rsp+28h+arg_0], rbx
                mov     [rsp+28h+arg_8], rsi
                mov     rsi, rdi
                cmp     rcx, 8
                jb      short loc_14000227B
                mov     rsi, [rdi]

loc_14000227B:                          ; CODE XREF: CopyAndResizeString+36↑j
                lea     rbx, [rax+rax]
                mov     [rdi+10h], rax
                mov     r8, rbx         ; Size
                mov     rcx, rsi        ; void *
                call    memmove
                xor     eax, eax
                mov     [rbx+rsi], ax
                mov     rax, rdi
                mov     rsi, [rsp+28h+arg_8]
                mov     rbx, [rsp+28h+arg_0]
                add     rsp, 20h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_1400022A7:                          ; CODE XREF: CopyAndResizeString+23↑j
                                        ; DATA XREF: .pdata:000000014000B168↓o ...
                mov     r9, rdx
                mov     rcx, rdi
                mov     rdx, rax
                call    AllocateAndCopyStringToStruct

loc_1400022B5:                          ; CODE XREF: CopyAndResizeString+C↑j
                mov     rax, rdi
                add     rsp, 20h
                pop     rdi
                retn
CopyAndResizeString endp

; ---------------------------------------------------------------------------
algn_1400022BE:                         ; DATA XREF: .pdata:000000014000B174↓o
                align 20h
; [00000062 BYTES: COLLAPSED FUNCTION unknown_libname_1. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140002322:                         ; DATA XREF: .pdata:000000014000B180↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall HandleAndCopyExceptionData(_QWORD *exceptionInfo, __int64 a2, __int128 *exceptionObject)
HandleAndCopyExceptionData proc near    ; CODE XREF: HandleAndThrowException+44↓p
                                        ; DATA XREF: .pdata:000000014000B18C↓o

var_28          = qword ptr -28h
var_18          = xmmword ptr -18h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006A4C SIZE 00000020 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                sub     rsp, 40h
                mov     rbx, rcx
                mov     [rsp+48h+var_28], rcx
                movups  xmm0, xmmword ptr [r8]
                movaps  [rsp+48h+var_18], xmm0
                mov     r8, rdx
                lea     rdx, [rsp+48h+var_18]
                call    HandleExceptionAndCopyData
                nop
                lea     rax, off_140007750
                mov     [rbx], rax
                xor     r8d, r8d
                mov     [rbx+28h], r8
                mov     [rbx+38h], r8
                mov     qword ptr [rbx+40h], 7
                mov     [rbx+28h], r8w
                mov     [rbx+48h], r8
                mov     [rbx+58h], r8
                mov     qword ptr [rbx+60h], 7
                mov     [rbx+48h], r8w
                lea     rcx, [rbx+68h]  ; void *
                mov     rax, [rbx+8]
                lea     rdx, aUnknownExcepti ; "Unknown exception"
                test    rax, rax
                cmovnz  rdx, rax        ; Src
                mov     [rcx], r8
                mov     [rcx+10h], r8
                mov     qword ptr [rcx+18h], 0Fh
                mov     [rcx], r8b
                mov     r8, 0FFFFFFFFFFFFFFFFh
                nop     dword ptr [rax+rax+00h]

loc_1400023C0:                          ; CODE XREF: HandleAndCopyExceptionData+98↓j
                inc     r8              ; Size
                cmp     byte ptr [rdx+r8], 0
                jnz     short loc_1400023C0
                call    ResizeAndCopyData
                nop
                mov     rax, rbx
                add     rsp, 40h
                pop     rbx
                retn
; } // starts at 140002330
HandleAndCopyExceptionData endp

; ---------------------------------------------------------------------------
algn_1400023D9:                         ; DATA XREF: .pdata:000000014000B18C↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall HandleAndPrepareException(__int64 exceptionObj, __int64 dataSize, __int64 arraySize, __int128 *exceptionInfo)
HandleAndPrepareException proc near     ; CODE XREF: HandleAndThrowCustomException+4B↓p
                                        ; DATA XREF: .pdata:000000014000B198↓o

exceptionData   = xmmword ptr -58h
memoryBlock     = qword ptr -48h
xmmBlock        = xmmword ptr -38h
a1              = qword ptr -28h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006A7C SIZE 00000020 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                push    rdi
                sub     rsp, 68h
                mov     rdi, r8
                mov     rbx, rcx
                mov     [rsp+78h+a1], rcx
                movups  xmm0, xmmword ptr [r9]
                movaps  [rsp+78h+exceptionData], xmm0
                mov     r8, rdx
                lea     rdx, [rsp+78h+exceptionData]
                call    HandleExceptionAndCopyData
                nop
                lea     rax, off_140007750
                mov     [rbx], rax
                lea     rcx, [rbx+28h]
                mov     rdx, rdi
                call    CopyAndResizeArray
                nop
                xorps   xmm0, xmm0
                movups  xmmword ptr [rbx+48h], xmm0
                movups  xmmword ptr [rbx+58h], xmm0
                xor     eax, eax
                mov     [rbx+48h], rax
                mov     [rbx+58h], rax
                mov     qword ptr [rbx+60h], 7
                mov     [rbx+48h], ax
                movups  xmmword ptr [rsp+78h+memoryBlock], xmm0
                mov     [rsp+78h+memoryBlock], rax
                movdqa  xmm0, cs:xmmword_140007850
                movdqu  [rsp+78h+xmmBlock], xmm0
                mov     word ptr [rsp+78h+memoryBlock], ax
                mov     rax, [rbx+8]
                lea     rcx, aUnknownExcepti ; "Unknown exception"
                test    rax, rax
                cmovnz  rcx, rax
                mov     qword ptr [rsp+78h+exceptionData], rcx
                mov     rax, 0FFFFFFFFFFFFFFFFh
                nop     dword ptr [rax+00h]

loc_140002480:                          ; CODE XREF: HandleAndPrepareException+A7↓j
                inc     rax
                cmp     byte ptr [rcx+rax], 0
                jnz     short loc_140002480
                mov     qword ptr [rsp+78h+exceptionData+8], rax
                movaps  xmm0, [rsp+78h+exceptionData]
                movdqa  [rsp+78h+exceptionData], xmm0
                lea     rcx, [rbx+68h]  ; Src
                lea     r9, [rsp+78h+memoryBlock]
                mov     r8, rdi
                lea     rdx, [rsp+78h+exceptionData]
                call    sub_140002510
                nop
                mov     rdx, qword ptr [rsp+78h+xmmBlock+8]
                cmp     rdx, 8
                jb      short loc_1400024F6
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+78h+memoryBlock] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_1400024F0
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_1400024F0
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400024F0:                          ; CODE XREF: HandleAndPrepareException+F2↑j
                                        ; HandleAndPrepareException+107↑j
                call    j_j_free
                nop

loc_1400024F6:                          ; CODE XREF: HandleAndPrepareException+D9↑j
                mov     rax, rbx
                add     rsp, 68h
                pop     rdi
                pop     rbx
                retn
; } // starts at 1400023E0
HandleAndPrepareException endp


; =============== S U B R O U T I N E =======================================


sub_140002500   proc near               ; DATA XREF: .rdata:0000000140007758↓o
                                        ; .pdata:000000014000B198↓o
                lea     rax, [rcx+68h]
                cmp     qword ptr [rax+18h], 10h
                jb      short locret_14000250E
                mov     rax, [rax]

locret_14000250E:                       ; CODE XREF: sub_140002500+9↑j
                retn
sub_140002500   endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame fpd=57h

; __int64 __fastcall sub_140002510(void *Src)
sub_140002510   proc near               ; CODE XREF: HandleAndPrepareException+CA↑p
                                        ; DATA XREF: .pdata:000000014000B1A4↓o

var_90          = xmmword ptr -90h
var_80          = dword ptr -80h
var_78          = qword ptr -78h
Block           = qword ptr -70h
var_60          = qword ptr -60h
var_58          = qword ptr -58h
Src             = qword ptr -50h
var_40          = qword ptr -40h
var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_27          = dword ptr -27h
var_20          = byte ptr -20h
var_1F          = qword ptr -1Fh
arg_10          = qword ptr  20h
arg_18          = qword ptr  28h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006AB0 SIZE 00000026 BYTES

; __unwind { // __GSHandlerCheck_EH4
                mov     [rsp-8+arg_10], rbx
                mov     [rsp-8+arg_18], rsi
                push    rbp
                push    rdi
                push    r12
                push    r14
                push    r15
                lea     rbp, [rsp-37h]
                sub     rsp, 90h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+57h+var_30], rax
                mov     rsi, r9
                mov     rbx, r8
                mov     r15, rdx
                mov     rdi, rcx
                mov     [rbp+57h+var_78], rcx
                xor     r12d, r12d
                mov     [rbp+57h+var_80], r12d
                mov     [rcx], r12
                mov     [rcx+10h], r12
                mov     qword ptr [rcx+18h], 0Fh
                mov     [rcx], r12b
                mov     [rbp+57h+var_80], 1
                call    __std_fs_code_page
                mov     r14d, eax
                mov     rcx, rbx
                cmp     qword ptr [rbx+18h], 8
                jb      short loc_140002581
                mov     rcx, [rbx]

loc_140002581:                          ; CODE XREF: sub_140002510+6C↑j
                mov     rax, [rbx+10h]
                mov     qword ptr [rbp+57h+var_90], rcx
                mov     qword ptr [rbp+57h+var_90+8], rax
                movaps  xmm0, [rbp+57h+var_90]
                movdqa  [rbp+57h+var_90], xmm0
                lea     r8, [rbp+57h+var_90]
                mov     edx, r14d       ; CodePage
                lea     rcx, [rbp+57h+Src] ; Src
                call    sub_1400042E0
                nop
                mov     rcx, rsi
                cmp     qword ptr [rsi+18h], 8
                jb      short loc_1400025B4
                mov     rcx, [rsi]

loc_1400025B4:                          ; CODE XREF: sub_140002510+9F↑j
                mov     rax, [rsi+10h]
                mov     qword ptr [rbp+57h+var_90], rcx
                mov     qword ptr [rbp+57h+var_90+8], rax
                movaps  xmm0, [rbp+57h+var_90]
                movdqa  [rbp+57h+var_90], xmm0
                lea     r8, [rbp+57h+var_90]
                mov     edx, r14d       ; CodePage
                lea     rcx, [rbp+57h+Block] ; Src
;   try {
                call    sub_1400042E0
                nop
                mov     edx, 8
                mov     esi, 4
                mov     rax, [rbp+57h+var_60]
                test    rax, rax
                cmovz   edx, esi
                add     rdx, [r15+8]
                add     rdx, [rbp+57h+var_40]
                add     rdx, rax
                cmp     [rdi+18h], rdx
                jnb     short loc_140002612
                mov     rbx, [rdi+10h]
                sub     rdx, rbx
                mov     rcx, rdi        ; Src
;   } // starts at 1400025D4
;   try {
                call    sub_140004910
                mov     [rdi+10h], rbx

loc_140002612:                          ; CODE XREF: sub_140002510+ED↑j
                movups  xmm1, xmmword ptr [r15]
                movdqa  xmm0, xmm1
                psrldq  xmm0, 8
                movq    r8, xmm0
                movq    rdx, xmm1
                mov     rcx, rdi        ; Src
                call    CopyDataToMemoryBlock
                mov     r8d, 3
                lea     rdx, asc_1400075A0 ; ": \""
                mov     rcx, rdi        ; Src
                call    CopyDataToMemoryBlock
                lea     rdx, [rbp+57h+Src]
                cmp     [rbp+57h+var_38], 10h
                cmovnb  rdx, [rbp+57h+Src]
                mov     r8, [rbp+57h+var_40]
                mov     rcx, rdi        ; Src
                call    CopyDataToMemoryBlock
                cmp     [rbp+57h+var_60], 0
                jz      short loc_140002693
                mov     r8, rsi
                lea     rdx, asc_1400075A4 ; "\", \""
                mov     rcx, rdi        ; Src
                call    CopyDataToMemoryBlock
                lea     rdx, [rbp+57h+Block]
                cmp     [rbp+57h+var_58], 10h
                cmovnb  rdx, [rbp+57h+Block]
                mov     r8, [rbp+57h+var_60]
                mov     rcx, rdi        ; Src
                call    CopyDataToMemoryBlock

loc_140002693:                          ; CODE XREF: sub_140002510+155↑j
                mov     rcx, [rdi+10h]
                mov     rdx, [rdi+18h]
                cmp     rcx, rdx
                jnb     short loc_1400026BC
                lea     rax, [rcx+1]
                mov     [rdi+10h], rax
                mov     rax, rdi
                cmp     rdx, 10h
                jb      short loc_1400026B4
                mov     rax, [rdi]

loc_1400026B4:                          ; CODE XREF: sub_140002510+19F↑j
                mov     word ptr [rax+rcx], 22h ; '"'
                jmp     short loc_1400026C8
; ---------------------------------------------------------------------------

loc_1400026BC:                          ; CODE XREF: sub_140002510+18E↑j
                mov     r9b, 22h ; '"'
                mov     rcx, rdi        ; Src
                call    ExtendAndCopyStringWithChar
                nop
;   } // starts at 140002609

loc_1400026C8:                          ; CODE XREF: sub_140002510+1AA↑j
;   try {
                mov     rdx, [rbp+57h+var_58]
                cmp     rdx, 10h
                jb      short loc_140002706
                inc     rdx
                mov     rcx, [rbp+57h+Block] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140002701
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140002701
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140002701:                          ; CODE XREF: sub_140002510+1D3↑j
                                        ; sub_140002510+1E8↑j
                call    j_j_free

loc_140002706:                          ; CODE XREF: sub_140002510+1C0↑j
                mov     [rbp+57h+var_60], r12
                mov     [rbp+57h+var_58], 0Fh
                mov     byte ptr [rbp+57h+Block], 0
                mov     rdx, [rbp+57h+var_38]
                cmp     rdx, 10h
                jb      short loc_140002754
                inc     rdx
                mov     rcx, [rbp+57h+Src] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_14000274F
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_14000274F
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_14000274F:                          ; CODE XREF: sub_140002510+221↑j
                                        ; sub_140002510+236↑j
                call    j_j_free

loc_140002754:                          ; CODE XREF: sub_140002510+20E↑j
                mov     rax, rdi
                mov     rcx, [rbp+57h+var_30]
                xor     rcx, rsp        ; StackCookie
;   } // starts at 1400026C8
                call    __security_check_cookie
                lea     r11, [rsp+0B0h+var_20]
                mov     rbx, [r11+40h]
                mov     rsi, [r11+48h]
                mov     rsp, r11
                pop     r15
                pop     r14
                pop     r12
                pop     rdi
                pop     rbp
                retn
; ---------------------------------------------------------------------------
                align 20h
; } // starts at 140002510
sub_140002510   endp


; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140002780(void *Block)
sub_140002780   proc near               ; DATA XREF: .rdata:off_140007750↓o
                                        ; .pdata:000000014000B1A4↓o ...

arg_8           = qword ptr  10h
arg_10          = qword ptr  18h

                mov     [rsp+arg_8], rbx
                mov     [rsp+arg_10], rsi
                push    rdi
                sub     rsp, 20h
                mov     edi, edx
                mov     rbx, rcx
                mov     rdx, [rcx+80h]
                cmp     rdx, 10h
                jb      short loc_1400027D2
                mov     rcx, [rcx+68h]
                inc     rdx
                cmp     rdx, 1000h
                jb      short loc_1400027CD
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      loc_1400028BD
                mov     rcx, r8         ; Block

loc_1400027CD:                          ; CODE XREF: sub_140002780+2F↑j
                call    j_j_free

loc_1400027D2:                          ; CODE XREF: sub_140002780+1F↑j
                mov     byte ptr [rbx+68h], 0
                xor     esi, esi
                mov     [rbx+78h], rsi
                mov     qword ptr [rbx+80h], 0Fh
                mov     rdx, [rbx+60h]
                cmp     rdx, 8
                jb      short loc_140002827
                mov     rcx, [rbx+48h]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_140002822
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      loc_1400028BD
                mov     rcx, r8         ; Block

loc_140002822:                          ; CODE XREF: sub_140002780+84↑j
                call    j_j_free

loc_140002827:                          ; CODE XREF: sub_140002780+6F↑j
                mov     [rbx+48h], si
                mov     [rbx+58h], rsi
                mov     qword ptr [rbx+60h], 7
                mov     rdx, [rbx+40h]
                cmp     rdx, 8
                jb      short loc_140002873
                mov     rcx, [rbx+28h]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_14000286E
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_1400028BD
                mov     rcx, r8         ; Block

loc_14000286E:                          ; CODE XREF: sub_140002780+D4↑j
                call    j_j_free

loc_140002873:                          ; CODE XREF: sub_140002780+BF↑j
                mov     [rbx+28h], si
                lea     rax, off_1400074D8
                mov     [rbx+38h], rsi
                lea     rcx, [rbx+8]
                mov     qword ptr [rbx+40h], 7
                mov     [rbx], rax
                call    cs:__std_exception_destroy
                test    dil, 1
                jz      short loc_1400028AA
                mov     edx, 88h
                mov     rcx, rbx        ; Block
                call    j_j_free

loc_1400028AA:                          ; CODE XREF: sub_140002780+11B↑j
                mov     rsi, [rsp+28h+arg_10]
                mov     rax, rbx
                mov     rbx, [rsp+28h+arg_8]
                add     rsp, 20h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_1400028BD:                          ; CODE XREF: sub_140002780+44↑j
                                        ; sub_140002780+99↑j ...
                call    cs:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                db 0CCh
sub_140002780   endp

algn_1400028C4:                         ; DATA XREF: .pdata:000000014000B1B0↓o
                align 10h

; =============== S U B R O U T I N E =======================================


sub_1400028D0   proc near               ; DATA XREF: .pdata:000000014000B1BC↓o

arg_8           = qword ptr  10h

                mov     [rsp+arg_8], rbx
                push    rdi
                sub     rsp, 20h
                mov     rdx, [rcx+80h]
                mov     rbx, rcx
                cmp     rdx, 10h
                jb      short loc_14000291B
                mov     rcx, [rcx+68h]
                inc     rdx
                cmp     rdx, 1000h
                jb      short loc_140002916
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      loc_1400029EB
                mov     rcx, r8         ; Block

loc_140002916:                          ; CODE XREF: sub_1400028D0+28↑j
                call    j_j_free

loc_14000291B:                          ; CODE XREF: sub_1400028D0+18↑j
                mov     byte ptr [rbx+68h], 0
                xor     edi, edi
                mov     [rbx+78h], rdi
                mov     qword ptr [rbx+80h], 0Fh
                mov     rdx, [rbx+60h]
                cmp     rdx, 8
                jb      short loc_140002970
                mov     rcx, [rbx+48h]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_14000296B
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      loc_1400029EB
                mov     rcx, r8         ; Block

loc_14000296B:                          ; CODE XREF: sub_1400028D0+7D↑j
                call    j_j_free

loc_140002970:                          ; CODE XREF: sub_1400028D0+68↑j
                mov     [rbx+48h], di
                mov     [rbx+58h], rdi
                mov     qword ptr [rbx+60h], 7
                mov     rdx, [rbx+40h]
                cmp     rdx, 8
                jb      short loc_1400029BC
                mov     rcx, [rbx+28h]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_1400029B7
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_1400029EB
                mov     rcx, r8         ; Block

loc_1400029B7:                          ; CODE XREF: sub_1400028D0+CD↑j
                call    j_j_free

loc_1400029BC:                          ; CODE XREF: sub_1400028D0+B8↑j
                mov     [rbx+28h], di
                lea     rax, off_1400074D8
                mov     [rbx+38h], rdi
                lea     rcx, [rbx+8]
                mov     qword ptr [rbx+40h], 7
                mov     [rbx], rax
                mov     rbx, [rsp+28h+arg_8]
                add     rsp, 20h
                pop     rdi
                jmp     cs:__std_exception_destroy
; ---------------------------------------------------------------------------

loc_1400029EB:                          ; CODE XREF: sub_1400028D0+3D↑j
                                        ; sub_1400028D0+92↑j ...
                call    cs:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                db 0CCh
sub_1400028D0   endp

algn_1400029F2:                         ; DATA XREF: .pdata:000000014000B1BC↓o
                align 20h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __fastcall __noreturn HandleAndThrowException(__int64 exceptionCode, __int64 a2, __int64 a3, __int64 a4)
HandleAndThrowException proc near       ; CODE XREF: ProcessDirectory+4EC↓p
                                        ; DATA XREF: .pdata:000000014000B1C8↓o

var_D8          = xmmword ptr -0D8h
var_C8          = byte ptr -0C8h
var_B8          = byte ptr -0B8h
pExceptionObject= qword ptr -98h

; __unwind { // __CxxFrameHandler4
                sub     rsp, 0F8h
                lea     rcx, [rsp+0F8h+var_C8]
                call    ?make_error_code@std@@YA?AVerror_code@1@W4io_errc@1@@Z ; std::make_error_code(std::io_errc)
                movups  xmm0, xmmword ptr [rax]
                movups  [rsp+0F8h+var_D8], xmm0
                lea     rdx, aDirectoryItera ; "directory_iterator::operator++"
                lea     rcx, [rsp+0F8h+var_B8]
                call    InitializeAndCopyByteArray
                nop
                movups  xmm0, [rsp+0F8h+var_D8]
                movaps  [rsp+0F8h+var_D8], xmm0
                lea     r8, [rsp+0F8h+var_D8]
                lea     rdx, [rsp+0F8h+var_B8]
                lea     rcx, [rsp+0F8h+pExceptionObject]
                call    HandleAndCopyExceptionData
                lea     rdx, stru_140008F78 ; pThrowInfo
                lea     rcx, [rsp+0F8h+pExceptionObject] ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 140002A00
HandleAndThrowException endp

algn_140002A5B:                         ; DATA XREF: .pdata:000000014000B1C8↓o
                align 20h

; =============== S U B R O U T I N E =======================================


sub_140002A60   proc near               ; DATA XREF: .pdata:000000014000B1D4↓o

arg_0           = qword ptr  8
arg_8           = qword ptr  10h

; FUNCTION CHUNK AT 0000000140006B0C SIZE 00000020 BYTES

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_8], rbx
                mov     [rsp+arg_0], rcx
                push    rdi
                sub     rsp, 20h
                mov     rbx, rdx
                mov     rdi, rcx
                lea     rax, off_1400074D8
                mov     [rcx], rax
                lea     rdx, [rcx+8]
                xorps   xmm0, xmm0
                movups  xmmword ptr [rdx], xmm0
                lea     rcx, [rbx+8]
                call    cs:__std_exception_copy
                lea     rax, off_1400077C8
                mov     [rdi], rax
                movups  xmm0, xmmword ptr [rbx+18h]
                movups  xmmword ptr [rdi+18h], xmm0
                lea     rax, off_140007750
                mov     [rdi], rax
                lea     rcx, [rdi+28h]
                lea     rdx, [rbx+28h]
                call    CopyAndResizeArray
                nop
                lea     rcx, [rdi+48h]
                lea     rdx, [rbx+48h]
                call    CopyAndResizeArray
                nop
                lea     rcx, [rdi+68h]
                lea     rdx, [rbx+68h]
                call    sub_140004010
                nop
                mov     rax, rdi
                mov     rbx, [rsp+28h+arg_8]
                add     rsp, 20h
                pop     rdi
                retn
; } // starts at 140002A60
sub_140002A60   endp

; ---------------------------------------------------------------------------
algn_140002AE7:                         ; DATA XREF: .pdata:000000014000B1D4↓o
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __fastcall __noreturn HandleAndThrowCustomException(__int64 errorCode, __int64 param1, __int64 param2)
HandleAndThrowCustomException proc near ; CODE XREF: ProcessDirectory+4FE↓p
                                        ; ProcessDirectory+50F↓p
                                        ; DATA XREF: ...

exceptionData   = xmmword ptr -0D8h
exceptionCode   = byte ptr -0C8h
exceptionMessage= byte ptr -0B8h
exceptionObject = byte ptr -98h

; __unwind { // __CxxFrameHandler4
                push    rbx
                sub     rsp, 0F0h
                mov     rbx, r8
                mov     r9, rcx
                lea     rcx, [rsp+0F8h+exceptionCode]
                call    ?make_error_code@std@@YA?AVerror_code@1@W4io_errc@1@@Z ; std::make_error_code(std::io_errc)
                movups  xmm0, xmmword ptr [rax]
                movups  [rsp+0F8h+exceptionData], xmm0
                mov     rdx, r9
                lea     rcx, [rsp+0F8h+exceptionMessage]
                call    InitializeAndCopyByteArray
                nop
                movups  xmm0, [rsp+0F8h+exceptionData]
                movaps  [rsp+0F8h+exceptionData], xmm0
                lea     r9, [rsp+0F8h+exceptionData]
                mov     r8, rbx
                lea     rdx, [rsp+0F8h+exceptionMessage]
                lea     rcx, [rsp+0F8h+exceptionObject]
                call    HandleAndPrepareException
                lea     rdx, stru_140008F78 ; pThrowInfo
                lea     rcx, [rsp+0F8h+exceptionObject] ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 140002AF0
HandleAndThrowCustomException endp

algn_140002B52:                         ; DATA XREF: .pdata:000000014000B1E0↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; int *__fastcall GetFileAttributes(__int64 fileHandle, int *attributes)
GetFileAttributes proc near             ; CODE XREF: ProcessDirectory+F8↓p
                                        ; DATA XREF: .pdata:000000014000B1EC↓o

var_38          = byte ptr -38h
fileMode        = dword ptr -28h
errorCode2      = dword ptr -24h
var_18          = qword ptr -18h

; __unwind { // __GSHandlerCheck
                push    rbx
                sub     rsp, 50h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rsp+58h+var_18], rax
                mov     rbx, rdx
                mov     rdx, rcx
                mov     dword ptr [rbx], 0
                mov     dword ptr [rbx+4], 0FFFFh
                mov     ecx, [rcx+1Ch]
                mov     eax, ecx
                and     eax, 3
                cmp     al, 3
                jnz     short loc_140002C00
                mov     dword ptr [rbx+8], 0
                mov     eax, 16Dh
                mov     ecx, [rdx+10h]
                mov     r8d, 1FFh
                test    cl, 1
                cmovz   eax, r8d
                mov     [rbx+4], eax
                mov     eax, ecx
                shr     eax, 0Ah
                test    al, 1
                jz      short loc_140002BE1
                mov     eax, [rdx+14h]
                cmp     eax, 0A000000Ch
                jnz     short loc_140002BD0

loc_140002BC6:                          ; CODE XREF: GetFileAttributes+106↓j
                mov     ecx, 4
                jmp     loc_140002CA6
; ---------------------------------------------------------------------------

loc_140002BD0:                          ; CODE XREF: GetFileAttributes+64↑j
                cmp     eax, 0A0000003h
                jnz     short loc_140002BE1

loc_140002BD7:                          ; CODE XREF: GetFileAttributes+111↓j
                mov     ecx, 0Ah
                jmp     loc_140002CA6
; ---------------------------------------------------------------------------

loc_140002BE1:                          ; CODE XREF: GetFileAttributes+5A↑j
                                        ; GetFileAttributes+75↑j
                shr     ecx, 4
                mov     rax, rbx
                test    cl, 1
                jz      short loc_140002BF6
                mov     ecx, 3
                jmp     loc_140002CA9
; ---------------------------------------------------------------------------

loc_140002BF6:                          ; CODE XREF: GetFileAttributes+8A↑j
                mov     ecx, 2
                jmp     loc_140002CA9
; ---------------------------------------------------------------------------

loc_140002C00:                          ; CODE XREF: GetFileAttributes+32↑j
                shr     ecx, 1
                test    cl, 1
                jz      short loc_140002C0D
                mov     r9d, [rdx+10h]
                jmp     short loc_140002C13
; ---------------------------------------------------------------------------

loc_140002C0D:                          ; CODE XREF: GetFileAttributes+A5↑j
                mov     r9d, 0FFFFFFFFh

loc_140002C13:                          ; CODE XREF: GetFileAttributes+AB↑j
                cmp     qword ptr [rdx+38h], 8
                lea     rax, [rdx+20h]
                jb      short loc_140002C21
                mov     rax, [rax]

loc_140002C21:                          ; CODE XREF: GetFileAttributes+BC↑j
                mov     r8d, 3
                lea     rdx, [rsp+58h+var_38]
                mov     rcx, rax        ; lpFileName
                call    __std_fs_get_stats
                mov     [rbx+8], eax
                test    eax, eax
                jnz     short loc_140002C82
                mov     ecx, [rsp+58h+fileMode]
                mov     eax, 16Dh
                test    cl, 1
                mov     r8d, 1FFh
                cmovz   eax, r8d
                mov     [rbx+4], eax
                mov     eax, ecx
                shr     eax, 0Ah
                test    al, 1
                jz      short loc_140002C77
                mov     eax, [rsp+58h+errorCode2]
                cmp     eax, 0A000000Ch
                jz      loc_140002BC6
                cmp     eax, 0A0000003h
                jz      loc_140002BD7

loc_140002C77:                          ; CODE XREF: GetFileAttributes+FB↑j
                shr     ecx, 4
                and     ecx, 1
                add     ecx, 2
                jmp     short loc_140002CA6
; ---------------------------------------------------------------------------

loc_140002C82:                          ; CODE XREF: GetFileAttributes+D9↑j
                mov     dword ptr [rbx+4], 0FFFFh
                sub     eax, 2
                jz      short loc_140002CA1
                sub     eax, 1
                jz      short loc_140002CA1
                sub     eax, 32h ; '2'
                jz      short loc_140002CA1
                cmp     eax, 46h ; 'F'
                jz      short loc_140002CA1
                xor     ecx, ecx
                jmp     short loc_140002CA6
; ---------------------------------------------------------------------------

loc_140002CA1:                          ; CODE XREF: GetFileAttributes+12C↑j
                                        ; GetFileAttributes+131↑j ...
                mov     ecx, 1

loc_140002CA6:                          ; CODE XREF: GetFileAttributes+6B↑j
                                        ; GetFileAttributes+7C↑j ...
                mov     rax, rbx

loc_140002CA9:                          ; CODE XREF: GetFileAttributes+91↑j
                                        ; GetFileAttributes+9B↑j
                mov     [rax], ecx
                mov     rax, rbx
                mov     rcx, [rsp+58h+var_18]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                add     rsp, 50h
                pop     rbx
                retn
; } // starts at 140002B60
GetFileAttributes endp

; ---------------------------------------------------------------------------
algn_140002CC1:                         ; DATA XREF: .pdata:000000014000B1EC↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; DWORD __fastcall OpenAndIterateDirectory(WCHAR *directoryPath, char flags, void **fileIterator, struct _WIN32_FIND_DATAW *fileData)
OpenAndIterateDirectory proc near       ; CODE XREF: ProcessFiles+4F↓p
                                        ; DATA XREF: .pdata:000000014000B1F8↓o

Block           = qword ptr -48h
var_38          = qword ptr -38h
dataSize        = qword ptr -30h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                push    rbp
                push    rsi
                push    rdi
                push    r14
                sub     rsp, 40h
                mov     rbx, r9
                mov     r14, r8
                mov     esi, edx
                mov     rdi, rcx
                xor     ebp, ebp
                cmp     qword ptr [rcx+18h], 8
                jb      short loc_140002CF2
                mov     rcx, [rcx]

loc_140002CF2:                          ; CODE XREF: OpenAndIterateDirectory+1D↑j
                mov     rax, 0FFFFFFFFFFFFFFFFh
                nop     dword ptr [rax+00000000h]

loc_140002D00:                          ; CODE XREF: OpenAndIterateDirectory+37↓j
                inc     rax
                cmp     [rcx+rax*2], bp
                jnz     short loc_140002D00
                test    rax, rax
                jz      loc_140002E16
                cmp     rax, [rdi+10h]
                jnz     loc_140002E16
                lea     rax, word_1400075C8
                mov     [rsp+68h+Block], rax
                mov     [rsp+68h+Block], rbp
                mov     [rsp+68h+dataSize], 7
                mov     dword ptr [rsp+68h+Block], ebp
                mov     [rsp+68h+var_38], 1
                movzx   eax, cs:word_1400075C8
                mov     word ptr [rsp+68h+Block], ax
                lea     rdx, [rsp+68h+Block]
                mov     rcx, rdi        ; void *
                call    ProcessAndCopyData
                nop
                mov     rdx, [rsp+68h+dataSize]
                cmp     rdx, 8
                jb      short loc_140002DA2
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+68h+Block] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140002D9D
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140002D9D
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140002D9D:                          ; CODE XREF: OpenAndIterateDirectory+AF↑j
                                        ; OpenAndIterateDirectory+C4↑j
                call    j_j_free

loc_140002DA2:                          ; CODE XREF: OpenAndIterateDirectory+96↑j
                cmp     qword ptr [rdi+18h], 8
                jb      short loc_140002DAC
                mov     rdi, [rdi]

loc_140002DAC:                          ; CODE XREF: OpenAndIterateDirectory+D7↑j
                mov     r8, rbx
                mov     rdx, r14
                mov     rcx, rdi        ; lpFileName
                call    __std_fs_directory_iterator_open
                test    eax, eax
                jnz     short loc_140002DF8
                mov     rdi, [r14]
                mov     rcx, rbx
                call    CheckExtension
                test    al, al
                jz      short loc_140002DEB
                nop     dword ptr [rax]

loc_140002DD0:                          ; CODE XREF: OpenAndIterateDirectory+119↓j
                mov     rdx, rbx
                mov     rcx, rdi
                call    FindNextFileInfo
                test    eax, eax
                jnz     short loc_140002E1B
                mov     rcx, rbx
                call    CheckExtension
                test    al, al
                jnz     short loc_140002DD0

loc_140002DEB:                          ; CODE XREF: OpenAndIterateDirectory+FB↑j
                mov     eax, ebp
                add     rsp, 40h
                pop     r14
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140002DF8:                          ; CODE XREF: OpenAndIterateDirectory+EC↑j
                cmp     eax, 5
                jnz     short loc_140002E1B
                shr     esi, 1
                test    sil, 1
                mov     ecx, 12h
                cmovnz  eax, ecx
                add     rsp, 40h
                pop     r14
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140002E16:                          ; CODE XREF: OpenAndIterateDirectory+3C↑j
                                        ; OpenAndIterateDirectory+46↑j
                mov     eax, 2

loc_140002E1B:                          ; CODE XREF: OpenAndIterateDirectory+10D↑j
                                        ; OpenAndIterateDirectory+12B↑j
                add     rsp, 40h
                pop     r14
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; } // starts at 140002CD0
OpenAndIterateDirectory endp

; ---------------------------------------------------------------------------
algn_140002E26:                         ; DATA XREF: .pdata:000000014000B1F8↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; void __fastcall ProcessAndUpdateData(__int64 Dest, __int64 Source)
ProcessAndUpdateData proc near          ; CODE XREF: ProcessAndUpdate+C7↓p
                                        ; ProcessDirectory+2CE↓p
                                        ; DATA XREF: ...

Block           = qword ptr -38h
var_28          = qword ptr -28h
var_20          = qword ptr -20h
arg_8           = qword ptr  10h
arg_10          = qword ptr  18h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_8], rbx
                mov     [rsp+arg_10], rsi
                push    rdi
                sub     rsp, 50h
                mov     r8, rcx
                xor     esi, esi
                mov     eax, [rdx]
                mov     [rcx+10h], eax
                mov     eax, [rdx+24h]
                mov     [rcx+14h], eax
                mov     dword ptr [rcx+1Ch], 6
                test    dword ptr [rdx], 400h
                jnz     short loc_140002E7E
                mov     ecx, [rdx+1Ch]
                shl     rcx, 20h
                mov     eax, [rdx+20h]
                add     rcx, rax
                mov     [r8+8], rcx
                mov     rax, [rdx+14h]
                mov     [r8], rax
                mov     dword ptr [r8+1Ch], 2Eh ; '.'

loc_140002E7E:                          ; CODE XREF: ProcessAndUpdateData+2C↑j
                lea     rdi, [r8+20h]
                lea     r9, [rdx+2Ch]
                mov     rdx, 0FFFFFFFFFFFFFFFFh
                nop     dword ptr [rax]

loc_140002E90:                          ; CODE XREF: ProcessAndUpdateData+68↓j
                inc     rdx
                cmp     [r9+rdx*2], si
                jnz     short loc_140002E90
                mov     [rsp+58h+Block], rsi
                mov     [rsp+58h+var_28], rsi
                mov     [rsp+58h+var_20], 7
                mov     word ptr [rsp+58h+Block], si
                lea     rcx, [rsp+58h+Block] ; void *
                cmp     rdx, 7
                ja      short loc_140002ED8
                mov     [rsp+58h+var_28], rdx
                lea     rbx, [rdx+rdx]
                mov     r8, rbx         ; Size
                mov     rdx, r9         ; Src
                call    memmove
                mov     word ptr [rsp+rbx+58h+Block], si
                jmp     short loc_140002EDE
; ---------------------------------------------------------------------------

loc_140002ED8:                          ; CODE XREF: ProcessAndUpdateData+8B↑j
                call    AllocateAndCopyStringToStruct
                nop

loc_140002EDE:                          ; CODE XREF: ProcessAndUpdateData+A6↑j
                mov     rcx, rdi
                call    ProcessContent
                lea     rdx, [rsp+58h+Block]
                mov     rcx, rdi        ; void *
                call    ProcessAndCopyData
                nop
                mov     rdx, [rsp+58h+var_20]
                cmp     rdx, 8
                jb      short loc_140002F39
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+58h+Block] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140002F34
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140002F34
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140002F34:                          ; CODE XREF: ProcessAndUpdateData+E6↑j
                                        ; ProcessAndUpdateData+FB↑j
                call    j_j_free

loc_140002F39:                          ; CODE XREF: ProcessAndUpdateData+CD↑j
                mov     rbx, [rsp+58h+arg_8]
                mov     rsi, [rsp+58h+arg_10]
                add     rsp, 50h
                pop     rdi
                retn
; } // starts at 140002E30
ProcessAndUpdateData endp

; ---------------------------------------------------------------------------
algn_140002F49:                         ; DATA XREF: .pdata:000000014000B204↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall ProcessAndUpdate(__int64 dest, __int64 src)
ProcessAndUpdate proc near              ; CODE XREF: ProcessFiles+BE↓p
                                        ; DATA XREF: .pdata:000000014000B210↓o

var_28          = qword ptr -28h
arg_10          = qword ptr  18h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006B4C SIZE 00000010 BYTES

; __unwind { // __CxxFrameHandler4
                mov     [rsp+arg_10], rbx
                push    rbp
                push    rsi
                push    rdi
                sub     rsp, 30h
                mov     rdi, rdx
                mov     rsi, rcx
                mov     [rsp+48h+var_28], rcx
                xorps   xmm0, xmm0
                movups  xmmword ptr [rcx], xmm0
                movups  xmmword ptr [rcx+10h], xmm0
                lea     rbx, [rcx+20h]
                movups  xmmword ptr [rbx], xmm0
                movups  xmmword ptr [rbx+10h], xmm0
                xor     ebp, ebp
                mov     [rbx], rbp
                mov     [rbx+10h], rbp
                mov     qword ptr [rbx+18h], 7
                mov     [rbx], bp
                mov     rax, [rdx+20h]
                mov     qword ptr [rdx+20h], 0FFFFFFFFFFFFFFFFh
                mov     [rcx+40h], rax
                cmp     rbx, rdx
                jz      short loc_140003010
                mov     rdx, [rbx+18h]
                cmp     rdx, 8
                jb      short loc_140002FE0
                mov     rcx, [rbx]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_140002FDB
                add     rdx, 27h ; '''
                mov     r8, [rcx-8]
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_14000302D
                mov     rcx, r8         ; Block

loc_140002FDB:                          ; CODE XREF: ProcessAndUpdate+71↑j
                call    j_j_free

loc_140002FE0:                          ; CODE XREF: ProcessAndUpdate+5D↑j
                mov     [rbx], bp
                mov     [rbx+10h], rbp
                mov     qword ptr [rbx+18h], 7
                movups  xmm0, xmmword ptr [rdi]
                movups  xmmword ptr [rbx], xmm0
                movups  xmm1, xmmword ptr [rdi+10h]
                movups  xmmword ptr [rbx+10h], xmm1
                mov     [rdi+10h], rbp
                mov     qword ptr [rdi+18h], 7
                mov     [rdi], bp
                nop     dword ptr [rax+00h]

loc_140003010:                          ; CODE XREF: ProcessAndUpdate+53↑j
                lea     rdx, [rdi+28h]
                mov     rcx, rsi
                call    ProcessAndUpdateData
                nop
                mov     rax, rsi
                mov     rbx, [rsp+48h+arg_10]
                add     rsp, 30h
                pop     rdi
                pop     rsi
                pop     rbp
                retn
; ---------------------------------------------------------------------------

loc_14000302D:                          ; CODE XREF: ProcessAndUpdate+86↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                nop
; } // starts at 140002F50
ProcessAndUpdate endp ; sp-analysis failed


loc_140003034:                          ; DATA XREF: .pdata:000000014000B210↓o
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger
                int     3               ; Trap to Debugger

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140003040(_QWORD)
sub_140003040   proc near               ; CODE XREF: sub_140006B40+7↓j
                                        ; DATA XREF: .rdata:0000000140008800↓o ...
                push    rbx
                sub     rsp, 20h
                mov     rdx, [rcx+38h]
                mov     rbx, rcx
                cmp     rdx, 8
                jb      short loc_140003085
                mov     rcx, [rcx+20h]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_140003080
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_14000309D
                mov     rcx, r8         ; Block

loc_140003080:                          ; CODE XREF: sub_140003040+26↑j
                call    j_j_free

loc_140003085:                          ; CODE XREF: sub_140003040+11↑j
                xor     eax, eax
                mov     qword ptr [rbx+38h], 7
                mov     [rbx+30h], rax
                mov     [rbx+20h], ax
                add     rsp, 20h
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_14000309D:                          ; CODE XREF: sub_140003040+3B↑j
                call    cs:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                db 0CCh
sub_140003040   endp

algn_1400030A4:                         ; DATA XREF: .pdata:000000014000B21C↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_1400030B0(_QWORD)
sub_1400030B0   proc near               ; CODE XREF: sub_140006B60+7↓j
                                        ; sub_140006B6C+7↓j ...

arg_0           = qword ptr  8

                push    rbx
                sub     rsp, 20h
                mov     rbx, [rcx+8]
                test    rbx, rbx
                jz      short loc_1400030F5

loc_1400030BF:                          ; DATA XREF: .rdata:000000014000881C↓o
                                        ; .rdata:000000014000882C↓o ...
                mov     [rsp+28h+arg_0], rdi
                mov     edi, 0FFFFFFFFh
                mov     eax, edi
                lock xadd [rbx+8], eax
                cmp     eax, 1
                jnz     short loc_1400030F0
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                lock xadd [rbx+0Ch], edi
                cmp     edi, 1
                jnz     short loc_1400030F0
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax+8]

loc_1400030F0:                          ; CODE XREF: sub_1400030B0+23↑j
                                        ; sub_1400030B0+35↑j
                mov     rdi, [rsp+28h+arg_0]

loc_1400030F5:                          ; CODE XREF: sub_1400030B0+D↑j
                                        ; DATA XREF: .pdata:000000014000B234↓o ...
                add     rsp, 20h
                pop     rbx
                retn
sub_1400030B0   endp

; ---------------------------------------------------------------------------
algn_1400030FB:                         ; DATA XREF: .pdata:000000014000B240↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall IsModuleInProcess(DWORD processID, const char *moduleName)
IsModuleInProcess proc near             ; CODE XREF: main+34A↓p
                                        ; main+3AC↓p
                                        ; DATA XREF: ...

moduleEntry     = MODULEENTRY32 ptr -258h
var_18          = qword ptr -18h
var_8           = byte ptr -8
arg_8           = qword ptr  10h
arg_10          = qword ptr  18h

; __unwind { // __GSHandlerCheck
                mov     [rsp+arg_8], rbx
                mov     [rsp+arg_10], rsi
                push    rdi
                sub     rsp, 270h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rsp+278h+var_18], rax
                mov     rdi, rdx
                xor     sil, sil
                mov     edx, ecx        ; th32ProcessID
                mov     ecx, 8          ; dwFlags
                call    cs:CreateToolhelp32Snapshot
                xor     edx, edx        ; Val
                mov     [rsp+278h+moduleEntry.dwSize], 238h
                mov     r8d, 234h       ; Size
                lea     rcx, [rsp+278h+moduleEntry.th32ModuleID] ; void *
                mov     rbx, rax
                call    memset
                lea     rdx, [rsp+278h+moduleEntry] ; lpme
                mov     rcx, rbx        ; hSnapshot
                call    cs:Module32Next
                test    eax, eax
                jz      short loc_1400031AE
                db      66h, 66h
                nop     word ptr [rax+rax+00000000h]

loc_140003170:                          ; CODE XREF: IsModuleInProcess+A7↓j
                lea     rax, [rsp+278h+moduleEntry.szModule]
                mov     r8, rdi
                sub     r8, rax
                nop     dword ptr [rax+rax+00h]

loc_140003180:                          ; CODE XREF: IsModuleInProcess+91↓j
                movzx   edx, byte ptr [rax]
                movzx   ecx, byte ptr [rax+r8]
                sub     edx, ecx
                jnz     short loc_140003193
                inc     rax
                test    ecx, ecx
                jnz     short loc_140003180

loc_140003193:                          ; CODE XREF: IsModuleInProcess+8A↑j
                test    edx, edx
                jz      short loc_1400031AB
                lea     rdx, [rsp+278h+moduleEntry] ; lpme
                mov     rcx, rbx        ; hSnapshot
                call    cs:Module32Next
                test    eax, eax
                jnz     short loc_140003170
                jmp     short loc_1400031AE
; ---------------------------------------------------------------------------

loc_1400031AB:                          ; CODE XREF: IsModuleInProcess+95↑j
                mov     sil, 1

loc_1400031AE:                          ; CODE XREF: IsModuleInProcess+64↑j
                                        ; IsModuleInProcess+A9↑j
                mov     rcx, rbx        ; hObject
                call    cs:CloseHandle
                movzx   eax, sil
                mov     rcx, [rsp+278h+var_18]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                lea     r11, [rsp+278h+var_8]
                mov     rbx, [r11+18h]
                mov     rsi, [r11+20h]
                mov     rsp, r11
                pop     rdi
                retn
; } // starts at 140003100
IsModuleInProcess endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame fpd=2B0h

; char __fastcall ProcessDirectory(__int64 dirPath, __int64 outputPath, void **customPath)
ProcessDirectory proc near              ; CODE XREF: main+1CB↓p
                                        ; DATA XREF: .pdata:000000014000B24C↓o ...

lockHandle9     = qword ptr -388h
lockSize7       = dword ptr -380h
lockArray8      = qword ptr -378h
var_368         = qword ptr -368h
lockSize8       = qword ptr -360h
lockPath        = qword ptr -350h
lockPathSize    = qword ptr -348h
lockData        = xmmword ptr -340h
lockSegment     = qword ptr -330h
var_320         = qword ptr -320h
lockSegmentSize = qword ptr -318h
lockSegmentData = xmmword ptr -310h
lockSegmentInfo = xmmword ptr -2E0h
lockSegmentCopy = xmmword ptr -2D0h
lockCopy        = qword ptr -2C0h
lockCopySize    = qword ptr -2B0h
lockCopySize2   = qword ptr -2A8h
lockCopyInfo    = xmmword ptr -2A0h
lockCopyBuffer  = byte ptr -290h
lockCopyFlag1   = word ptr -264h
lockCopyFlag2   = word ptr -262h
lockCopyFlag3   = word ptr -260h
var_40          = qword ptr -40h
arg_8           = qword ptr  18h

; __unwind { // __GSHandlerCheck_EH4
                mov     [rsp-8+arg_8], rbx
                push    rbp
                push    rsi
                push    rdi
                push    r12
                push    r13
                push    r14
                push    r15
                lea     rbp, [rsp-280h]
                sub     rsp, 380h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+2B0h+var_40], rax
                mov     r13, r8
                mov     rbx, rcx
                xor     r15d, r15d
                xorps   xmm0, xmm0
                movdqa  [rbp+2B0h+lockSegmentCopy], xmm0
                mov     rdx, rcx
                lea     rcx, [rbp+2B0h+lockSegmentCopy]
                call    ProcessFiles
                test    eax, eax
                jnz     loc_1400036D2
                xorps   xmm0, xmm0
                movups  [rbp+2B0h+lockSegmentInfo], xmm0
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                test    rcx, rcx
                jz      short loc_14000324D
                lock inc dword ptr [rcx+8]
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]

loc_14000324D:                          ; CODE XREF: ProcessDirectory+63↑j
                movaps  xmm0, [rbp+2B0h+lockSegmentCopy]
                movdqa  [rbp+2B0h+lockSegmentInfo], xmm0
                test    rcx, rcx
                jz      short loc_140003263
                lock inc dword ptr [rcx+8]
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]

loc_140003263:                          ; CODE XREF: ProcessDirectory+79↑j
                xorps   xmm1, xmm1
                movdqu  [rbp+2B0h+lockCopyInfo], xmm1
                mov     esi, 0FFFFFFFFh
                test    rcx, rcx
                jz      short loc_1400032A4
                mov     eax, esi
                lock xadd [rcx+8], eax
                cmp     eax, 1
                jnz     short loc_1400032A4
                mov     rbx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                mov     eax, esi
                lock xadd [rbx+0Ch], eax
                cmp     eax, 1
                jnz     short loc_1400032A4
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                mov     rax, [rcx]
                call    qword ptr [rax+8]
                nop

loc_1400032A4:                          ; CODE XREF: ProcessDirectory+93↑j
                                        ; ProcessDirectory+9F↑j ...
                nop     dword ptr [rax+00h]
                nop     dword ptr [rax+rax+00000000h]

loc_1400032B0:                          ; CODE XREF: ProcessDirectory+2FC↓j
                                        ; ProcessDirectory+314↓j ...
                mov     rdi, qword ptr [rbp+2B0h+lockSegmentInfo]
                mov     r14, qword ptr [rbp+2B0h+lockSegmentInfo+8]
                nop     dword ptr [rax+rax+00000000h]

loc_1400032C0:                          ; CODE XREF: ProcessDirectory+2D3↓j
                                        ; ProcessDirectory+2EC↓j
                lea     rbx, aDll       ; ".dll"
                test    rdi, rdi
                jz      loc_140003634
                lea     rdx, [rsp+3B0h+lockHandle9]
                mov     rcx, rdi
                call    GetFileAttributes
                mov     rax, [rsp+3B0h+lockHandle9]
                mov     edx, [rsp+3B0h+lockSize7]
                test    edx, edx
                jz      short loc_1400032F9
                lea     ecx, [rax-1]
                test    ecx, 0FFFFFFF7h
                jnz     loc_1400036E4

loc_1400032F9:                          ; CODE XREF: ProcessDirectory+108↑j
                cmp     eax, 2
                jnz     loc_140003470
                lea     rdx, [rdi+20h]
                lea     rcx, [rbp+2B0h+lockCopy]
                call    CopyAndResizeArray
                nop
                call    __std_fs_code_page
                mov     [rsp+3B0h+lockPath], rbx
                mov     [rsp+3B0h+lockPathSize], 4
                lea     r8, [rsp+3B0h+lockPath]
                mov     edx, eax
                lea     rcx, [rsp+3B0h+lockArray8] ; Src
                call    ExtendAndCopyString_1
                nop
                lea     rdx, [rbp+2B0h+lockSegment]
                lea     rcx, [rbp+2B0h+lockCopy]
                call    CreatePathFromSegments
                lea     rcx, [rsp+3B0h+lockArray8]
                mov     rbx, [rsp+3B0h+lockArray8]
                mov     r15, [rsp+3B0h+lockSize8]
                cmp     r15, 8
                cmovnb  rcx, rbx
                mov     qword ptr [rsp+3B0h+lockData], rcx
                mov     rcx, [rsp+3B0h+var_368]
                mov     qword ptr [rsp+3B0h+lockData+8], rcx
                movaps  xmm0, [rsp+3B0h+lockData]
                movdqa  [rbp+2B0h+lockSegmentData], xmm0
                lea     rdx, [rbp+2B0h+lockSegmentData]
                mov     rcx, rax
                call    ComparePaths
                mov     r12d, eax
                mov     rdx, [rbp+2B0h+lockSegmentSize]
                cmp     rdx, 8
                jb      short loc_1400033CB
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rbp+2B0h+lockSegment]
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_1400033BC
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]    ; Block
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                ja      loc_140003508

loc_1400033BC:                          ; CODE XREF: ProcessDirectory+1C1↑j
                call    j_j_free
                mov     r15, [rsp+3B0h+lockSize8]
                mov     rbx, [rsp+3B0h+lockArray8]

loc_1400033CB:                          ; CODE XREF: ProcessDirectory+1A9↑j
                xor     eax, eax
                mov     [rbp+2B0h+var_320], rax
                mov     [rbp+2B0h+lockSegmentSize], 7
                mov     word ptr [rbp+2B0h+lockSegment], ax
                cmp     r15, 8
                jb      short loc_140003418
                lea     rdx, ds:2[r15*2]
                mov     rax, rbx
                cmp     rdx, 1000h
                jb      short loc_140003410
                add     rdx, 27h ; '''
                mov     rbx, [rbx-8]
                sub     rax, rbx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                ja      loc_14000350F

loc_140003410:                          ; CODE XREF: ProcessDirectory+215↑j
                mov     rcx, rbx        ; Block
                call    j_j_free

loc_140003418:                          ; CODE XREF: ProcessDirectory+201↑j
                test    r12d, r12d
                jz      loc_140003516
                mov     rdx, [rbp+2B0h+lockCopySize2]
                cmp     rdx, 8
                jb      short loc_140003461
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rbp+2B0h+lockCopy]
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_14000345C
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]    ; Block
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                ja      loc_1400035A9

loc_14000345C:                          ; CODE XREF: ProcessDirectory+261↑j
                call    j_j_free

loc_140003461:                          ; CODE XREF: ProcessDirectory+249↑j
                xor     r15d, r15d
                nop     dword ptr [rax+00h]
                nop     dword ptr [rax+rax+00000000h]

loc_140003470:                          ; CODE XREF: ProcessDirectory+11C↑j
                                        ; ProcessDirectory+2B8↓j ...
                lea     rdx, [rbp+2B0h+lockCopyBuffer]
                mov     rcx, [rdi+40h]
                call    FindNextFileInfo
                cmp     eax, 12h
                jz      short loc_1400034B8
                test    eax, eax
                jnz     loc_1400036CA
                cmp     [rbp+2B0h+lockCopyFlag1], 2Eh ; '.'
                jnz     short loc_1400034A7
                movzx   eax, [rbp+2B0h+lockCopyFlag2]
                test    ax, ax
                jz      short loc_140003470
                cmp     ax, 2Eh ; '.'
                jnz     short loc_1400034A7
                cmp     [rbp+2B0h+lockCopyFlag3], 0
                jz      short loc_140003470

loc_1400034A7:                          ; CODE XREF: ProcessDirectory+2AF↑j
                                        ; ProcessDirectory+2BE↑j
                lea     rdx, [rbp+2B0h+lockCopyBuffer]
                mov     rcx, rdi
                call    ProcessAndUpdateData
                jmp     loc_1400032C0
; ---------------------------------------------------------------------------

loc_1400034B8:                          ; CODE XREF: ProcessDirectory+2A0↑j
                mov     rdi, r15
                mov     qword ptr [rbp+2B0h+lockSegmentInfo], r15
                mov     rbx, r14
                mov     r14, r15
                mov     qword ptr [rbp+2B0h+lockSegmentInfo+8], r15
                test    rbx, rbx
                jz      loc_1400032C0
                mov     eax, esi
                lock xadd [rbx+8], eax
                cmp     eax, 1
                jnz     loc_1400032B0
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                mov     eax, esi
                lock xadd [rbx+0Ch], eax
                cmp     eax, 1
                jnz     loc_1400032B0
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax+8]
                jmp     loc_1400032B0
; ---------------------------------------------------------------------------

loc_140003508:                          ; CODE XREF: ProcessDirectory+1D6↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                nop

loc_14000350F:                          ; CODE XREF: ProcessDirectory+22A↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003516:                          ; CODE XREF: ProcessDirectory+23B↑j
                lea     rax, [rbp+2B0h+lockCopy]
                cmp     r13, rax
                jz      short loc_14000356F
                mov     rbx, [rbp+2B0h+lockCopySize]
                lea     r9, [rbp+2B0h+lockCopy]
                cmp     [rbp+2B0h+lockCopySize2], 8
                cmovnb  r9, [rbp+2B0h+lockCopy]
                mov     rax, [r13+18h]
                cmp     rbx, rax
                ja      short loc_140003564
                mov     rdi, r13
                cmp     rax, 8
                jb      short loc_140003547
                mov     rdi, [r13+0]

loc_140003547:                          ; CODE XREF: ProcessDirectory+361↑j
                mov     [r13+10h], rbx
                lea     r8, [rbx+rbx]   ; Size
                mov     rdx, r9         ; Src
                mov     rcx, rdi        ; void *
                call    memmove
                xor     r15d, r15d
                mov     [rdi+rbx*2], r15w
                jmp     short loc_140003572
; ---------------------------------------------------------------------------

loc_140003564:                          ; CODE XREF: ProcessDirectory+358↑j
                mov     rdx, rbx
                mov     rcx, r13
                call    AllocateAndCopyStringToStruct

loc_14000356F:                          ; CODE XREF: ProcessDirectory+33D↑j
                xor     r15d, r15d

loc_140003572:                          ; CODE XREF: ProcessDirectory+382↑j
                mov     rdx, [rbp+2B0h+lockCopySize2]
                cmp     rdx, 8
                jb      short loc_1400035B5
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rbp+2B0h+lockCopy] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_1400035B0
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_1400035B0

loc_1400035A9:                          ; CODE XREF: ProcessDirectory+276↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400035B0:                          ; CODE XREF: ProcessDirectory+3B2↑j
                                        ; ProcessDirectory+3C7↑j
                call    j_j_free

loc_1400035B5:                          ; CODE XREF: ProcessDirectory+39A↑j
                mov     [rbp+2B0h+lockCopySize], r15
                mov     [rbp+2B0h+lockCopySize2], 7
                mov     word ptr [rbp+2B0h+lockCopy], r15w
                test    r14, r14
                jz      short loc_1400035FB
                mov     eax, esi
                lock xadd [r14+8], eax
                cmp     eax, 1
                jnz     short loc_1400035FB
                mov     rbx, qword ptr [rbp+2B0h+lockSegmentInfo+8]
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                mov     eax, esi
                lock xadd [rbx+0Ch], eax
                cmp     eax, 1
                jnz     short loc_1400035FB
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentInfo+8]
                mov     rax, [rcx]
                call    qword ptr [rax+8]
                nop

loc_1400035FB:                          ; CODE XREF: ProcessDirectory+3E9↑j
                                        ; ProcessDirectory+3F6↑j ...
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                test    rcx, rcx
                jz      short loc_140003630
                mov     eax, esi
                lock xadd [rcx+8], eax
                cmp     eax, 1
                jnz     short loc_140003630
                mov     rbx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                lock xadd [rbx+0Ch], esi
                cmp     esi, 1
                jnz     short loc_140003630
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                mov     rax, [rcx]
                call    qword ptr [rax+8]

loc_140003630:                          ; CODE XREF: ProcessDirectory+422↑j
                                        ; ProcessDirectory+42E↑j ...
                mov     al, 1
                jmp     short loc_1400036A0
; ---------------------------------------------------------------------------

loc_140003634:                          ; CODE XREF: ProcessDirectory+EA↑j
                test    r14, r14
                jz      short loc_140003669
                mov     eax, esi
                lock xadd [r14+8], eax
                cmp     eax, 1
                jnz     short loc_140003669
                mov     rbx, qword ptr [rbp+2B0h+lockSegmentInfo+8]
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                mov     eax, esi
                lock xadd [rbx+0Ch], eax
                cmp     eax, 1
                jnz     short loc_140003669
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentInfo+8]
                mov     rax, [rcx]
                call    qword ptr [rax+8]
                nop

loc_140003669:                          ; CODE XREF: ProcessDirectory+457↑j
                                        ; ProcessDirectory+464↑j ...
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                test    rcx, rcx
                jz      short loc_14000369E
                mov     eax, esi
                lock xadd [rcx+8], eax
                cmp     eax, 1
                jnz     short loc_14000369E
                mov     rbx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                lock xadd [rbx+0Ch], esi
                cmp     esi, 1
                jnz     short loc_14000369E
                mov     rcx, qword ptr [rbp+2B0h+lockSegmentCopy+8]
                mov     rax, [rcx]
                call    qword ptr [rax+8]

loc_14000369E:                          ; CODE XREF: ProcessDirectory+490↑j
                                        ; ProcessDirectory+49C↑j ...
                xor     al, al

loc_1400036A0:                          ; CODE XREF: ProcessDirectory+452↑j
                mov     rcx, [rbp+2B0h+var_40]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                mov     rbx, [rsp+3B0h+arg_8]
                add     rsp, 380h
                pop     r15
                pop     r14
                pop     r13
                pop     r12
                pop     rdi
                pop     rsi
                pop     rbp
                retn
; ---------------------------------------------------------------------------

loc_1400036CA:                          ; CODE XREF: ProcessDirectory+2A4↑j
                mov     edx, eax
                call    HandleAndThrowException
; ---------------------------------------------------------------------------
                align 2

loc_1400036D2:                          ; CODE XREF: ProcessDirectory+4F↑j
                mov     r8, rbx
                mov     edx, eax
                lea     rcx, aDirectoryItera_0 ; "directory_iterator::directory_iterator"
                call    HandleAndThrowCustomException
; ---------------------------------------------------------------------------
                align 4

loc_1400036E4:                          ; CODE XREF: ProcessDirectory+113↑j
                lea     r8, [rdi+20h]
                lea     rcx, aDirectoryEntry ; "directory_entry::status"
                call    HandleAndThrowCustomException
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 1400031E0
ProcessDirectory endp

algn_1400036F5:                         ; DATA XREF: .pdata:000000014000B258↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; char __fastcall PerformRemoteExecution(HANDLE *processHandle, WCHAR **dataToWrite)
PerformRemoteExecution proc near        ; CODE XREF: main+391↓p
                                        ; DATA XREF: .pdata:000000014000B264↓o

ppsidGroup      = qword ptr -0A8h
ppDacl          = qword ptr -0A0h
ppSacl          = qword ptr -98h
ppSecurityDescriptor= qword ptr -90h
newAcl          = qword ptr -88h
securityIdentifier= qword ptr -80h
oldAcl          = qword ptr -78h
securityDescriptor= qword ptr -70h
explicitAccessList= _EXPLICIT_ACCESS_W ptr -68h
var_38          = qword ptr -38h
arg_10          = qword ptr  18h

; __unwind { // __GSHandlerCheck
                mov     [rsp+arg_10], rbx
                push    rbp
                push    rsi
                push    rdi
                push    r14
                push    r15
                sub     rsp, 0A0h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rsp+0C8h+var_38], rax
                cmp     qword ptr [rdx+18h], 8
                mov     rbx, rdx
                mov     r14, rcx
                mov     rdi, rdx
                jb      short loc_140003738
                mov     rdi, [rdx]

loc_140003738:                          ; CODE XREF: PerformRemoteExecution+33↑j
                xor     ebp, ebp
                mov     [rsp+0C8h+securityDescriptor], rbp
                xor     sil, sil
                mov     [rsp+0C8h+oldAcl], rbp
                mov     [rsp+0C8h+securityIdentifier], rbp
                mov     [rsp+0C8h+newAcl], rbp
                lea     rax, [rsp+0C8h+securityDescriptor]
                mov     r15d, 1
                mov     [rsp+0C8h+ppSecurityDescriptor], rax ; ppSecurityDescriptor
                lea     r8d, [rbp+4]    ; SecurityInfo
                lea     rax, [rsp+0C8h+oldAcl]
                mov     [rsp+0C8h+ppSacl], rbp ; ppSacl
                mov     [rsp+0C8h+ppDacl], rax ; ppDacl
                xor     r9d, r9d        ; ppsidOwner
                mov     edx, r15d       ; ObjectType
                mov     [rsp+0C8h+ppsidGroup], rbp ; ppsidGroup
                mov     rcx, rdi        ; pObjectName
                call    cs:GetNamedSecurityInfoW
                test    eax, eax
                jnz     loc_140003835
                lea     rdx, [rsp+0C8h+securityIdentifier] ; Sid
                lea     rcx, StringSid  ; "S-1-15-2-1"
                call    cs:ConvertStringSidToSidW
                test    eax, eax
                jz      loc_140003835
                mov     rax, [rsp+0C8h+securityIdentifier]
                lea     r9, [rsp+0C8h+newAcl] ; NewAcl
                mov     r8, [rsp+0C8h+oldAcl] ; OldAcl
                lea     rdx, [rsp+0C8h+explicitAccessList] ; pListOfExplicitEntries
                xorps   xmm0, xmm0
                mov     [rsp+0C8h+explicitAccessList.Trustee.ptstrName], rax
                mov     ecx, r15d       ; cCountOfExplicitEntries
                mov     qword ptr [rsp+0C8h+explicitAccessList.Trustee.TrusteeType], 5
                movdqu  xmmword ptr [rsp+0C8h+explicitAccessList+0Ch], xmm0
                mov     [rsp+0C8h+explicitAccessList.grfAccessPermissions], 0E0000000h
                mov     [rsp+0C8h+explicitAccessList.grfAccessMode], 2
                mov     [rsp+0C8h+explicitAccessList.grfInheritance], 3
                mov     [rsp+0C8h+explicitAccessList.Trustee.TrusteeForm], ebp
                call    cs:SetEntriesInAclW
                test    eax, eax
                jnz     short loc_140003835
                mov     rax, [rsp+0C8h+newAcl]
                lea     r8d, [rbp+4]    ; SecurityInfo
                mov     [rsp+0C8h+ppSacl], rbp ; pSacl
                xor     r9d, r9d        ; psidOwner
                mov     [rsp+0C8h+ppDacl], rax ; pDacl
                mov     edx, r15d       ; ObjectType
                mov     rcx, rdi        ; pObjectName
                mov     [rsp+0C8h+ppsidGroup], rbp ; psidGroup
                call    cs:SetNamedSecurityInfoW
                test    eax, eax
                movzx   esi, sil
                cmovz   esi, r15d

loc_140003835:                          ; CODE XREF: PerformRemoteExecution+8A↑j
                                        ; PerformRemoteExecution+A4↑j ...
                mov     rcx, [rsp+0C8h+newAcl] ; hMem
                test    rcx, rcx
                jz      short loc_140003845
                call    cs:__imp_LocalFree

loc_140003845:                          ; CODE XREF: PerformRemoteExecution+13D↑j
                mov     rcx, [rsp+0C8h+securityIdentifier] ; hMem
                test    rcx, rcx
                jz      short loc_140003855
                call    cs:__imp_LocalFree

loc_140003855:                          ; CODE XREF: PerformRemoteExecution+14D↑j
                mov     rcx, [rsp+0C8h+securityDescriptor] ; hMem
                test    rcx, rcx
                jz      short loc_140003865
                call    cs:__imp_LocalFree

loc_140003865:                          ; CODE XREF: PerformRemoteExecution+15D↑j
                test    sil, sil
                jz      loc_14000390F
                mov     rdi, [rbx+18h]
                mov     r9d, 1000h      ; flAllocationType
                mov     rcx, [r14]      ; hProcess
                add     rdi, rdi
                mov     r8, rdi         ; dwSize
                mov     dword ptr [rsp+0C8h+ppsidGroup], 4 ; flProtect
                xor     edx, edx        ; lpAddress
                call    cs:VirtualAllocEx
                mov     rsi, rax
                test    rax, rax
                jz      short loc_14000390F
                cmp     qword ptr [rbx+18h], 8
                jb      short loc_1400038A3
                mov     rbx, [rbx]

loc_1400038A3:                          ; CODE XREF: PerformRemoteExecution+19E↑j
                mov     rcx, [r14]      ; hProcess
                mov     r9, rdi         ; nSize
                mov     r8, rbx         ; lpBuffer
                mov     [rsp+0C8h+ppsidGroup], rbp ; lpNumberOfBytesWritten
                mov     rdx, rsi        ; lpBaseAddress
                call    cs:WriteProcessMemory
                test    eax, eax
                jz      short loc_14000390F
                mov     r9, cs:LoadLibraryW ; lpStartAddress
                xor     r8d, r8d        ; dwStackSize
                mov     rcx, [r14]      ; hProcess
                xor     edx, edx        ; lpThreadAttributes
                mov     [rsp+0C8h+ppSacl], rbp ; lpThreadId
                mov     dword ptr [rsp+0C8h+ppDacl], ebp ; dwCreationFlags
                mov     [rsp+0C8h+ppsidGroup], rsi ; lpParameter
                call    cs:CreateRemoteThread
                test    rax, rax
                jz      short loc_14000390F
                mov     edx, 0FFFFFFFFh ; dwMilliseconds
                mov     rcx, rax        ; hHandle
                call    cs:WaitForSingleObject
                mov     rcx, [r14]      ; hProcess
                mov     r9d, 2000h      ; dwFreeType
                mov     r8, rdi         ; dwSize
                mov     rdx, rsi        ; lpAddress
                call    cs:VirtualFreeEx
                movzx   eax, r15b
                jmp     short loc_140003911
; ---------------------------------------------------------------------------

loc_14000390F:                          ; CODE XREF: PerformRemoteExecution+168↑j
                                        ; PerformRemoteExecution+197↑j ...
                xor     al, al

loc_140003911:                          ; CODE XREF: PerformRemoteExecution+20D↑j
                mov     rcx, [rsp+0C8h+var_38]
                xor     rcx, rsp        ; StackCookie
                call    __security_check_cookie
                mov     rbx, [rsp+0C8h+arg_10]
                add     rsp, 0A0h
                pop     r15
                pop     r14
                pop     rdi
                pop     rsi
                pop     rbp
                retn
; } // starts at 140003700
PerformRemoteExecution endp

; ---------------------------------------------------------------------------
algn_140003938:                         ; DATA XREF: .pdata:000000014000B264↓o
                align 20h

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame fpd=110h

; int __fastcall main(int argc, const char **argv, const char **envp)
main            proc near               ; CODE XREF: __scrt_common_main_seh(void)+107↓p
                                        ; DATA XREF: .pdata:000000014000B270↓o

directoryBlock  = qword ptr -1F0h
xmmBlock        = xmmword ptr -1E0h
pathBuffer      = qword ptr -1D0h
pathBufferSize  = qword ptr -1B8h
processHandlePtr= qword ptr -1B0h
pathSegments    = qword ptr -1A8h
var_198         = qword ptr -198h
pathSegmentSize = qword ptr -190h
segmentBuffer   = qword ptr -188h
xmmSegment      = xmmword ptr -178h
moduleSegment   = qword ptr -168h
moduleSegmentSize= qword ptr -150h
processEntry    = PROCESSENTRY32 ptr -140h
var_10          = qword ptr -10h
var_s0          = byte ptr  0
arg_0           = qword ptr  10h
arg_8           = qword ptr  18h
arg_10          = qword ptr  20h
arg_18          = qword ptr  28h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __GSHandlerCheck_EH4
                mov     [rsp-8+arg_0], rbx
                mov     [rsp-8+arg_8], rsi
                mov     [rsp-8+arg_10], rdi
                mov     [rsp-8+arg_18], r14
                push    rbp
                lea     rbp, [rsp-110h]
                sub     rsp, 210h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rbp+110h+var_10], rax
                mov     rsi, rdx
                xor     r14d, r14d
                xor     edx, edx        ; th32ProcessID
                lea     ecx, [rdx+2]    ; dwFlags
                call    cs:CreateToolhelp32Snapshot
                mov     rbx, rax
                mov     [rbp+110h+processEntry.dwSize], 130h
                mov     edi, r14d
                lea     rdx, [rbp+110h+processEntry] ; lppe
                mov     rcx, rax        ; hSnapshot
                call    cs:Process32Next
                test    eax, eax
                jz      short loc_1400039E3
                nop     dword ptr [rax+00h]
                nop     dword ptr [rax+rax+00000000h]

loc_1400039B0:                          ; CODE XREF: main+93↓j
                lea     rdx, Str2       ; "SoTGame.exe"
                lea     rcx, [rbp+110h+processEntry.szExeFile] ; Str1
                call    strcmp
                test    eax, eax
                jz      short loc_1400039E0
                lea     rdx, [rbp+110h+processEntry] ; lppe
                mov     rcx, rbx        ; hSnapshot
                call    cs:Process32Next
                test    eax, eax
                jnz     short loc_1400039B0
                mov     rcx, rbx        ; hObject
                call    cs:CloseHandle
                jmp     short loc_1400039F0
; ---------------------------------------------------------------------------

loc_1400039E0:                          ; CODE XREF: main+82↑j
                mov     edi, [rbp+110h+processEntry.th32ProcessID]

loc_1400039E3:                          ; CODE XREF: main+62↑j
                mov     rcx, rbx        ; hObject
                call    cs:CloseHandle
                test    edi, edi
                jnz     short loc_140003A06

loc_1400039F0:                          ; CODE XREF: main+9E↑j
                lea     rcx, aGameProcessNot ; "Game process not found\n"
                call    PrintFormattedOutputToStdout
                mov     eax, 1
                jmp     loc_140003E51
; ---------------------------------------------------------------------------

loc_140003A06:                          ; CODE XREF: main+AE↑j
                mov     r8d, edi        ; dwProcessId
                xor     edx, edx        ; bInheritHandle
                mov     ecx, 1FFFFFh    ; dwDesiredAccess
                call    cs:OpenProcess
                mov     [rsp+210h+processHandlePtr], rax
                cmp     rax, 0FFFFFFFFFFFFFFFFh
                jnz     short loc_140003A37
                lea     rcx, aCanTGetProcess ; "Can't get process handle\n"
                call    PrintFormattedOutputToStdout
                mov     eax, 1
                jmp     loc_140003E51
; ---------------------------------------------------------------------------

loc_140003A37:                          ; CODE XREF: main+DF↑j
                mov     r9, [rsi]
                mov     rdx, 0FFFFFFFFFFFFFFFFh

loc_140003A41:                          ; CODE XREF: main+109↓j
                inc     rdx
                cmp     [r9+rdx*2], r14w
                jnz     short loc_140003A41
                mov     [rsp+210h+directoryBlock], r14
                mov     qword ptr [rsp+210h+xmmBlock], r14
                mov     qword ptr [rsp+210h+xmmBlock+8], 7
                mov     word ptr [rsp+210h+directoryBlock], r14w
                lea     rcx, [rsp+210h+directoryBlock] ; void *
                cmp     rdx, 7
                ja      short loc_140003A8B
                mov     qword ptr [rsp+210h+xmmBlock], rdx
                lea     rbx, [rdx+rdx]
                mov     r8, rbx         ; Size
                mov     rdx, r9         ; Src
                call    memmove
                mov     word ptr [rsp+rbx+210h+directoryBlock], r14w
                jmp     short loc_140003A91
; ---------------------------------------------------------------------------

loc_140003A8B:                          ; CODE XREF: main+12D↑j
                call    AllocateAndCopyStringToStruct
                nop

loc_140003A91:                          ; CODE XREF: main+149↑j
                lea     rcx, [rsp+210h+directoryBlock]
                call    ProcessContent
                mov     rdx, rax
                lea     rcx, [rbp+110h+moduleSegment]
;   try {
                call    CopyAndResizeArray
                nop
                mov     rdx, qword ptr [rsp+210h+xmmBlock+8]
                cmp     rdx, 8
                jb      short loc_140003AED
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+210h+directoryBlock] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140003AE8
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140003AE8
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003AE8:                          ; CODE XREF: main+18A↑j
                                        ; main+19F↑j
                call    j_j_free

loc_140003AED:                          ; CODE XREF: main+171↑j
                mov     [rbp+110h+segmentBuffer], r14
                movdqa  xmm0, cs:xmmword_140007850
                movdqu  [rbp+110h+xmmSegment], xmm0
                mov     word ptr [rbp+110h+segmentBuffer], r14w
                lea     r8, [rbp+110h+segmentBuffer]
                lea     rcx, [rbp+110h+moduleSegment]
;   } // starts at 140003AA2
;   try {
                call    ProcessDirectory
                test    al, al
                jnz     short loc_140003B2A
                lea     rcx, aCanTFindDynami ; "Can't find dynamic library in the curre"...
                call    PrintFormattedOutputToStdout
                mov     ebx, 1
                jmp     loc_140003DB7
; ---------------------------------------------------------------------------

loc_140003B2A:                          ; CODE XREF: main+1D2↑j
                lea     rcx, [rbp+110h+segmentBuffer]
                cmp     qword ptr [rbp+110h+xmmSegment+8], 8
                cmovnb  rcx, [rbp+110h+segmentBuffer]
                mov     rax, qword ptr [rbp+110h+xmmSegment]
                lea     r11, [rcx+rax*2]
                mov     r10, r11
                mov     rdx, r11
                call    ProcessPath
                cmp     rax, r11
                jz      short loc_140003B8B

loc_140003B50:                          ; CODE XREF: main+226↓j
                movzx   ecx, word ptr [rax]
                cmp     cx, 5Ch ; '\'
                jz      short loc_140003B5F
                cmp     cx, 2Fh ; '/'
                jnz     short loc_140003B68

loc_140003B5F:                          ; CODE XREF: main+217↑j
                add     rax, 2
                cmp     rax, r11
                jnz     short loc_140003B50

loc_140003B68:                          ; CODE XREF: main+21D↑j
                cmp     rax, r11
                jz      short loc_140003B8B
                nop     dword ptr [rax]

loc_140003B70:                          ; CODE XREF: main+249↓j
                lea     rdx, [r10-2]
                movzx   ecx, word ptr [rdx]
                cmp     cx, 5Ch ; '\'
                jz      short loc_140003B8B
                cmp     cx, 2Fh ; '/'
                jz      short loc_140003B8B
                mov     r10, rdx
                cmp     rax, rdx
                jnz     short loc_140003B70

loc_140003B8B:                          ; CODE XREF: main+20E↑j
                                        ; main+22B↑j ...
                sub     r11, r10
                sar     r11, 1
                mov     [rsp+210h+directoryBlock], r14
                mov     qword ptr [rsp+210h+xmmBlock], r14
                mov     qword ptr [rsp+210h+xmmBlock+8], 7
                mov     word ptr [rsp+210h+directoryBlock], r14w
                lea     rcx, [rsp+210h+directoryBlock] ; void *
                cmp     r11, 7
                ja      short loc_140003BD1
                mov     qword ptr [rsp+210h+xmmBlock], r11
                lea     rbx, [r11+r11]
                mov     r8, rbx         ; Size
                mov     rdx, r10        ; Src
                call    memmove
                mov     word ptr [rsp+rbx+210h+directoryBlock], r14w
                jmp     short loc_140003BDD
; ---------------------------------------------------------------------------

loc_140003BD1:                          ; CODE XREF: main+273↑j
                mov     r9, r10
                mov     rdx, r11
                call    AllocateAndCopyStringToStruct
                nop
;   } // starts at 140003B0B

loc_140003BDD:                          ; CODE XREF: main+28F↑j
;   try {
                lea     rax, [rsp+210h+directoryBlock]
                cmp     qword ptr [rsp+210h+xmmBlock+8], 8
                cmovnb  rax, [rsp+210h+directoryBlock]
                mov     [rsp+210h+pathBuffer], rax
                mov     rax, qword ptr [rsp+210h+xmmBlock]
                mov     [rsp+210h+pathBuffer+8], rax
                call    __std_fs_code_page
                movaps  xmm0, xmmword ptr [rsp+210h+pathBuffer]
                movdqa  xmmword ptr [rsp+210h+pathBuffer], xmm0
                lea     r8, [rsp+210h+pathBuffer]
                mov     edx, eax        ; CodePage
                lea     rcx, [rsp+210h+pathSegments] ; Src
                call    ConvertAndCopyWideToNarrow
                nop
;   } // starts at 140003BDD
;   try {
                mov     rdx, qword ptr [rsp+210h+xmmBlock+8]
                cmp     rdx, 8
                jb      short loc_140003C64
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+210h+directoryBlock] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140003C5F
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140003C5F
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003C5F:                          ; CODE XREF: main+301↑j
                                        ; main+316↑j
                call    j_j_free

loc_140003C64:                          ; CODE XREF: main+2E8↑j
                movdqa  xmm0, cs:xmmword_140007850
                movdqu  [rsp+210h+xmmBlock], xmm0
                mov     word ptr [rsp+210h+directoryBlock], r14w
                lea     rdx, [rsp+210h+pathSegments]
                cmp     [rbp+110h+pathSegmentSize], 10h
                cmovnb  rdx, [rsp+210h+pathSegments]
                mov     ecx, edi        ; th32ProcessID
                call    IsModuleInProcess
                test    al, al
                jz      short loc_140003CB9
                lea     rdx, [rsp+210h+pathSegments]
                cmp     [rbp+110h+pathSegmentSize], 10h
                cmovnb  rdx, [rsp+210h+pathSegments]
                lea     rcx, aSHasBeenLoaded ; "%s has been loaded to process already\n"
                call    PrintFormattedOutputToStdout
                mov     ebx, 1
                jmp     loc_140003D66
; ---------------------------------------------------------------------------

loc_140003CB9:                          ; CODE XREF: main+351↑j
                lea     rdx, [rbp+110h+segmentBuffer]
                lea     rcx, [rsp+210h+pathBuffer]
                call    CopyAndResizeArray
                lea     rdx, [rsp+210h+pathBuffer]
                lea     rcx, [rsp+210h+processHandlePtr]
                call    PerformRemoteExecution
                test    al, al
                jz      short loc_140003CF9
                lea     rdx, [rsp+210h+pathSegments]
                cmp     [rbp+110h+pathSegmentSize], 10h
                cmovnb  rdx, [rsp+210h+pathSegments]
                mov     ecx, edi        ; th32ProcessID
                call    IsModuleInProcess
                test    al, al
                jz      short loc_140003CF9
                xor     bl, bl
                jmp     short loc_140003CFB
; ---------------------------------------------------------------------------

loc_140003CF9:                          ; CODE XREF: main+398↑j
                                        ; main+3B3↑j
                mov     bl, 1

loc_140003CFB:                          ; CODE XREF: main+3B7↑j
                mov     rdx, [rsp+210h+pathBufferSize]
                cmp     rdx, 8
                jb      short loc_140003D40
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+210h+pathBuffer] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140003D3B
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140003D3B
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003D3B:                          ; CODE XREF: main+3DD↑j
                                        ; main+3F2↑j
                call    j_j_free

loc_140003D40:                          ; CODE XREF: main+3C4↑j
                test    bl, bl
                jz      short loc_140003D57
                lea     rcx, aInjectionHasFa ; "Injection has failed or module has unlo"...
                call    PrintFormattedOutputToStdout
                mov     ebx, 1
                jmp     short loc_140003D66
; ---------------------------------------------------------------------------

loc_140003D57:                          ; CODE XREF: main+402↑j
                lea     rcx, aSuccessfullyIn ; "Successfully injected!\n"
                call    PrintFormattedOutputToStdout
                mov     ebx, r14d
;   } // starts at 140003C1F

loc_140003D66:                          ; CODE XREF: main+374↑j
                                        ; main+415↑j
;   try {
                mov     rdx, [rbp+110h+pathSegmentSize]
                cmp     rdx, 10h
                jb      short loc_140003DA5
                inc     rdx
                mov     rcx, [rsp+210h+pathSegments] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140003DA0
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140003DA0
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003DA0:                          ; CODE XREF: main+442↑j
                                        ; main+457↑j
                call    j_j_free

loc_140003DA5:                          ; CODE XREF: main+42E↑j
                mov     [rsp+210h+var_198], r14
                mov     [rbp+110h+pathSegmentSize], 0Fh
                mov     byte ptr [rsp+210h+pathSegments], 0

loc_140003DB7:                          ; CODE XREF: main+1E5↑j
                mov     rdx, qword ptr [rbp+110h+xmmSegment+8]
                cmp     rdx, 8
                jb      short loc_140003DFA
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rbp+110h+segmentBuffer] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140003DF5
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140003DF5
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003DF5:                          ; CODE XREF: main+497↑j
                                        ; main+4AC↑j
                call    j_j_free

loc_140003DFA:                          ; CODE XREF: main+47F↑j
                movdqa  xmm0, cs:xmmword_140007850
                movdqu  [rbp+110h+xmmSegment], xmm0
                mov     word ptr [rbp+110h+segmentBuffer], r14w
                mov     rdx, [rbp+110h+moduleSegmentSize]
                cmp     rdx, 8
                jb      short loc_140003E4F
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rbp+110h+moduleSegment] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_140003E4A
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_140003E4A
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003E4A:                          ; CODE XREF: main+4EC↑j
                                        ; main+501↑j
                call    j_j_free

loc_140003E4F:                          ; CODE XREF: main+4D4↑j
                mov     eax, ebx

loc_140003E51:                          ; CODE XREF: main+C1↑j
                                        ; main+F2↑j
                mov     rcx, [rbp+110h+var_10]
                xor     rcx, rsp        ; StackCookie
;   } // starts at 140003D66
                call    __security_check_cookie
                lea     r11, [rsp+210h+var_s0]
                mov     rbx, [r11+10h]
                mov     rsi, [r11+18h]
                mov     rdi, [r11+20h]
                mov     r14, [r11+28h]
                mov     rsp, r11
                pop     rbp
                retn
; } // starts at 140003940
main            endp

; ---------------------------------------------------------------------------
algn_140003E7D:                         ; DATA XREF: .pdata:000000014000B270↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall CopyAndResizeArray(_QWORD *outputArray, __int64 inputArray)
CopyAndResizeArray proc near            ; CODE XREF: HandleAndPrepareException+3A↑p
                                        ; sub_140002A60+57↑p ...

arg_10          = qword ptr  18h

                push    rbx
                push    rbp
                push    rdi
                sub     rsp, 20h
                xor     eax, eax
                mov     rdi, rdx
                mov     [rcx], rax
                mov     rbx, rcx
                mov     [rcx+10h], rax
                mov     [rcx+18h], rax
                cmp     qword ptr [rdx+18h], 8
                mov     rbp, [rdx+10h]
                jb      short loc_140003EA9
                mov     rdi, [rdx]

loc_140003EA9:                          ; CODE XREF: CopyAndResizeArray+24↑j
                mov     [rsp+38h+arg_10], rsi
                cmp     rbp, 8
                jnb     short loc_140003EC4
                movups  xmm0, xmmword ptr [rdi]
                mov     esi, 7
                movups  xmmword ptr [rcx], xmm0
                jmp     loc_140003F49
; ---------------------------------------------------------------------------

loc_140003EC4:                          ; CODE XREF: CopyAndResizeArray+32↑j
                mov     rcx, 7FFFFFFFFFFFFFFEh
                mov     rsi, rbp
                or      rsi, 7
                mov     rdx, 7FFFFFFFFFFFFFFFh
                cmp     rsi, rcx
                cmova   rsi, rcx
                lea     rcx, [rsi+1]
                cmp     rcx, rdx
                ja      short loc_140003F61
                add     rcx, rcx        ; Size
                cmp     rcx, 1000h
                jb      short loc_140003F29
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     short loc_140003F61
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rcx, rax
                test    rax, rax
                jz      short loc_140003F22
                add     rax, 27h ; '''
                and     rax, 0FFFFFFFFFFFFFFE0h
                mov     [rax-8], rcx
                jmp     short loc_140003F33
; ---------------------------------------------------------------------------

loc_140003F22:                          ; CODE XREF: CopyAndResizeArray+92↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140003F29:                          ; CODE XREF: CopyAndResizeArray+79↑j
                test    rcx, rcx
                jz      short loc_140003F33
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)

loc_140003F33:                          ; CODE XREF: CopyAndResizeArray+A0↑j
                                        ; CopyAndResizeArray+AC↑j
                lea     r8, ds:2[rbp*2] ; Size
                mov     [rbx], rax
                mov     rdx, rdi        ; Src
                mov     rcx, rax        ; void *
                call    memcpy

loc_140003F49:                          ; CODE XREF: CopyAndResizeArray+3F↑j
                mov     [rbx+10h], rbp
                mov     rax, rbx
                mov     [rbx+18h], rsi
                mov     rsi, [rsp+38h+arg_10]
                add     rsp, 20h
                pop     rdi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140003F61:                          ; CODE XREF: CopyAndResizeArray+6D↑j
                                        ; CopyAndResizeArray+82↑j
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
CopyAndResizeArray endp

algn_140003F67:                         ; DATA XREF: .pdata:000000014000B27C↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; void __fastcall sub_140003F70(__int64)
sub_140003F70   proc near               ; CODE XREF: sub_1400069D0+7↓j
                                        ; sub_1400069DC+7↓j ...
                push    rbx
                sub     rsp, 20h
                mov     rdx, [rcx+18h]
                mov     rbx, rcx
                cmp     rdx, 10h
                jb      short loc_140003FAF
                mov     rcx, [rcx]
                inc     rdx
                cmp     rdx, 1000h
                jb      short loc_140003FAA
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_140003FC8
                mov     rcx, r8         ; Block

loc_140003FAA:                          ; CODE XREF: sub_140003F70+20↑j
                call    j_j_free

loc_140003FAF:                          ; CODE XREF: sub_140003F70+11↑j
                mov     qword ptr [rbx+10h], 0
                mov     qword ptr [rbx+18h], 0Fh
                mov     byte ptr [rbx], 0
                add     rsp, 20h
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140003FC8:                          ; CODE XREF: sub_140003F70+35↑j
                call    cs:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                db 0CCh
sub_140003F70   endp

algn_140003FCF:                         ; DATA XREF: .pdata:000000014000B288↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; void **__fastcall InitializeAndCopyByteArray(void **targetArray, _BYTE *sourceArray)
InitializeAndCopyByteArray proc near    ; CODE XREF: HandleAndThrowException+25↑p
                                        ; HandleAndThrowCustomException+29↑p
                                        ; DATA XREF: ...

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                xor     eax, eax
                mov     [rcx], rax
                mov     [rcx+10h], rax
                mov     qword ptr [rcx+18h], 0Fh
                mov     r8, 0FFFFFFFFFFFFFFFFh

loc_140003FF1:                          ; CODE XREF: InitializeAndCopyByteArray+29↓j
                inc     r8              ; Size
                cmp     byte ptr [rdx+r8], 0
                jnz     short loc_140003FF1
                call    ResizeAndCopyData
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
; } // starts at 140003FD0
InitializeAndCopyByteArray endp

; ---------------------------------------------------------------------------
algn_140004009:                         ; DATA XREF: .pdata:000000014000B294↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140004010(_QWORD, _QWORD)
sub_140004010   proc near               ; CODE XREF: HandleExceptionAndCopyData+35↑p
                                        ; sub_140002A60+73↑p
                                        ; DATA XREF: ...

arg_10          = qword ptr  18h

                push    rbx
                push    rbp
                push    rsi
                sub     rsp, 20h
                xor     eax, eax
                mov     rsi, rdx
                mov     [rcx], rax
                mov     rbx, rcx
                mov     [rcx+10h], rax
                mov     [rcx+18h], rax
                cmp     qword ptr [rdx+18h], 10h
                mov     rbp, [rdx+10h]
                jb      short loc_140004039
                mov     rsi, [rdx]

loc_140004039:                          ; CODE XREF: sub_140004010+24↑j
                mov     [rsp+38h+arg_10], rdi
                cmp     rbp, 10h
                jnb     short loc_140004051
                movups  xmm0, xmmword ptr [rsi]
                mov     edi, 0Fh
                movups  xmmword ptr [rcx], xmm0
                jmp     short loc_1400040C0
; ---------------------------------------------------------------------------

loc_140004051:                          ; CODE XREF: sub_140004010+32↑j
                mov     rcx, 7FFFFFFFFFFFFFFFh
                mov     rdi, rbp
                or      rdi, 0Fh
                cmp     rdi, rcx
                cmova   rdi, rcx
                lea     rcx, [rdi+1]    ; Size
                cmp     rcx, 1000h
                jb      short loc_1400040A4
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     short loc_1400040D8
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rcx, rax
                test    rax, rax
                jz      short loc_14000409D
                add     rax, 27h ; '''
                and     rax, 0FFFFFFFFFFFFFFE0h
                mov     [rax-8], rcx
                jmp     short loc_1400040AE
; ---------------------------------------------------------------------------

loc_14000409D:                          ; CODE XREF: sub_140004010+7D↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400040A4:                          ; CODE XREF: sub_140004010+64↑j
                test    rcx, rcx
                jz      short loc_1400040AE
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)

loc_1400040AE:                          ; CODE XREF: sub_140004010+8B↑j
                                        ; sub_140004010+97↑j
                lea     r8, [rbp+1]     ; Size
                mov     [rbx], rax
                mov     rdx, rsi        ; Src
                mov     rcx, rax        ; void *
                call    memcpy

loc_1400040C0:                          ; CODE XREF: sub_140004010+3F↑j
                mov     [rbx+10h], rbp
                mov     rax, rbx
                mov     [rbx+18h], rdi
                mov     rdi, [rsp+38h+arg_10]
                add     rsp, 20h
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_1400040D8:                          ; CODE XREF: sub_140004010+6D↑j
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
sub_140004010   endp

algn_1400040DE:                         ; DATA XREF: .pdata:000000014000B2A0↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; void **__fastcall ResizeAndCopyData(void **targetArray, void *sourceData, size_t dataSize)
ResizeAndCopyData proc near             ; CODE XREF: ProcessAndCopyData_0+3D↑p
                                        ; sub_1400016E0+70↑p ...

arg_18          = qword ptr  20h

                push    rbx
                push    rbp
                push    rdi
                push    r14
                push    r15
                sub     rsp, 20h
                mov     rbp, [rcx+18h]
                mov     r14, r8
                mov     r15, rdx
                mov     rbx, rcx
                cmp     r8, rbp
                ja      short loc_14000412A
                mov     rdi, rcx
                cmp     rbp, 10h
                jb      short loc_14000410A
                mov     rdi, [rcx]

loc_14000410A:                          ; CODE XREF: ResizeAndCopyData+25↑j
                mov     [rcx+10h], r14
                mov     rcx, rdi        ; void *
                call    memmove
                mov     rax, rbx
                mov     byte ptr [r14+rdi], 0
                add     rsp, 20h
                pop     r15
                pop     r14
                pop     rdi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_14000412A:                          ; CODE XREF: ResizeAndCopyData+1C↑j
                mov     rdi, 7FFFFFFFFFFFFFFFh
                cmp     r14, rdi
                ja      loc_140004237
                mov     rcx, r14
                or      rcx, 0Fh
                cmp     rcx, rdi
                ja      short loc_140004168
                mov     rdx, rbp
                mov     rax, rdi
                shr     rdx, 1
                sub     rax, rdx
                cmp     rbp, rax
                ja      short loc_140004168
                lea     rax, [rdx+rbp]
                mov     rdi, rcx
                cmp     rcx, rax
                cmovb   rdi, rax

loc_140004168:                          ; CODE XREF: ResizeAndCopyData+67↑j
                                        ; ResizeAndCopyData+78↑j
                mov     rcx, rdi

loc_14000416B:                          ; DATA XREF: .rdata:00000001400089C0↓o
                                        ; .rdata:00000001400089D4↓o ...
                mov     [rsp+48h+arg_18], rsi
                add     rcx, 1
                mov     rax, 0FFFFFFFFFFFFFFFFh
                cmovb   rcx, rax        ; Size
                cmp     rcx, 1000h
                jb      short loc_1400041B4
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_140004231
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_14000422A
                lea     rsi, [rax+27h]
                and     rsi, 0FFFFFFFFFFFFFFE0h
                mov     [rsi-8], rax
                jmp     short loc_1400041C5
; ---------------------------------------------------------------------------

loc_1400041B4:                          ; CODE XREF: ResizeAndCopyData+A6↑j
                test    rcx, rcx
                jz      short loc_1400041C3
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rsi, rax
                jmp     short loc_1400041C5
; ---------------------------------------------------------------------------

loc_1400041C3:                          ; CODE XREF: ResizeAndCopyData+D7↑j
                xor     esi, esi

loc_1400041C5:                          ; CODE XREF: ResizeAndCopyData+D2↑j
                                        ; ResizeAndCopyData+E1↑j
                mov     r8, r14         ; Size
                mov     [rbx+10h], r14
                mov     rdx, r15        ; Src
                mov     [rbx+18h], rdi
                mov     rcx, rsi        ; void *
                call    memcpy
                mov     byte ptr [r14+rsi], 0
                cmp     rbp, 10h
                jb      short loc_140004213
                mov     rcx, [rbx]
                lea     rdx, [rbp+1]
                cmp     rdx, 1000h
                jb      short loc_14000420E
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_14000422A
                mov     rcx, r8         ; Block

loc_14000420E:                          ; CODE XREF: ResizeAndCopyData+114↑j
                call    j_j_free

loc_140004213:                          ; CODE XREF: ResizeAndCopyData+104↑j
                mov     [rbx], rsi
                mov     rax, rbx
                mov     rsi, [rsp+48h+arg_18]
                add     rsp, 20h
                pop     r15
                pop     r14
                pop     rdi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_14000422A:                          ; CODE XREF: ResizeAndCopyData+C0↑j
                                        ; ResizeAndCopyData+129↑j
                                        ; DATA XREF: ...
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140004231:                          ; CODE XREF: ResizeAndCopyData+AF↑j
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_140004237:                          ; CODE XREF: ResizeAndCopyData+57↑j
                                        ; DATA XREF: .pdata:000000014000B2C4↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
ResizeAndCopyData endp

algn_14000423D:                         ; DATA XREF: .pdata:000000014000B2D0↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; void **__fastcall CopyDataToMemoryBlock(void **sourceArray, const void *dataToCopy, size_t dataSize)
CopyDataToMemoryBlock proc near         ; CODE XREF: HandleExceptionAndCopyData+5C↑p
                                        ; HandleExceptionAndCopyData+89↑p ...

Size            = qword ptr -18h
arg_0           = qword ptr  8
arg_8           = qword ptr  10h

                mov     [rsp+arg_8], rsi
                push    rdi
                sub     rsp, 30h
                mov     rdi, rcx
                mov     rsi, r8
                mov     rcx, [rcx+10h]
                mov     r8, [rdi+18h]
                mov     rax, r8
                sub     rax, rcx
                cmp     rsi, rax
                ja      short loc_1400042A2

loc_140004263:                          ; DATA XREF: .rdata:0000000140008A04↓o
                                        ; .rdata:0000000140008A14↓o ...
                mov     [rsp+38h+arg_0], rbx
                lea     rax, [rcx+rsi]
                mov     [rdi+10h], rax
                mov     rax, rdi
                cmp     r8, 10h
                jb      short loc_14000427C
                mov     rax, [rdi]

loc_14000427C:                          ; CODE XREF: CopyDataToMemoryBlock+37↑j
                lea     rbx, [rax+rcx]
                mov     r8, rsi         ; Size
                mov     rcx, rbx        ; void *
                call    memmove
                mov     byte ptr [rbx+rsi], 0
                mov     rax, rdi
                mov     rbx, [rsp+38h+arg_0]
                mov     rsi, [rsp+38h+arg_8]
                add     rsp, 30h
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_1400042A2:                          ; CODE XREF: CopyDataToMemoryBlock+21↑j
                                        ; DATA XREF: .pdata:000000014000B2E8↓o ...
                mov     r9, rdx
                mov     [rsp+38h+Size], rsi ; Size
                mov     rdx, rsi
                mov     rcx, rdi        ; Src
                call    ResizeAndCopyMemoryBlock
                mov     rsi, [rsp+38h+arg_8]
                add     rsp, 30h
                pop     rdi
                retn
CopyDataToMemoryBlock endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; void __noreturn HandleInvalidStringPosition()
HandleInvalidStringPosition proc near   ; CODE XREF: ProcessAndCopyData:loc_140001E49↑p
                                        ; ProcessContent:loc_140001EE7↑p
                                        ; DATA XREF: ...
                sub     rsp, 28h
                lea     rcx, aInvalidStringP ; "invalid string position"
                call    cs:?_Xout_of_range@std@@YAXPEBD@Z ; std::_Xout_of_range(char const *)
; ---------------------------------------------------------------------------
                db 0CCh
HandleInvalidStringPosition endp

algn_1400042D2:                         ; DATA XREF: .pdata:000000014000B300↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_1400042E0(void *Src, UINT CodePage)
sub_1400042E0   proc near               ; CODE XREF: sub_140002510+91↑p
                                        ; sub_140002510+C4↑p
                                        ; DATA XREF: ...

var_58          = dword ptr -58h
var_48          = dword ptr -48h
var_40          = qword ptr -40h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006BF0 SIZE 00000026 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                push    rbp
                push    rsi
                push    rdi
                push    r12
                push    r14
                push    r15
                sub     rsp, 40h
                mov     r12d, edx
                mov     rsi, rcx
                mov     [rsp+78h+var_40], rcx
                xor     eax, eax
                mov     [rsp+78h+var_48], eax
                mov     [rcx], rax
                mov     [rcx+10h], rax
                mov     qword ptr [rcx+18h], 0Fh
                mov     [rcx], al
                mov     [rsp+78h+var_48], 1
                mov     r14, [r8+8]
                test    r14, r14
                jz      loc_1400043EE
                cmp     r14, 7FFFFFFFh
                ja      loc_140004408
                mov     r15, [r8]
                mov     [rsp+78h+var_58], eax ; int
                xor     r9d, r9d        ; lpMultiByteStr
                mov     r8d, r14d       ; cchWideChar
                mov     rdx, r15        ; lpWideCharStr
                mov     ecx, r12d       ; CodePage
                call    __std_fs_convert_wide_to_narrow_replace_chars
                mov     rbx, rax
                shr     rax, 20h
                test    eax, eax
                jnz     loc_14000440E
                movsxd  rcx, ebx
                mov     rdx, [rsi+10h]
                cmp     rcx, rdx
                ja      short loc_14000437D
                mov     rax, rsi
                cmp     qword ptr [rsi+18h], 10h
                jb      short loc_140004373
                mov     rax, [rsi]

loc_140004373:                          ; CODE XREF: sub_1400042E0+8E↑j
                mov     [rsi+10h], rcx
                mov     byte ptr [rax+rcx], 0
                jmp     short loc_1400043C7
; ---------------------------------------------------------------------------

loc_14000437D:                          ; CODE XREF: sub_1400042E0+84↑j
                mov     rbp, rcx
                sub     rbp, rdx
                mov     r8, [rsi+18h]
                mov     rax, r8
                sub     rax, rdx
                cmp     rbp, rax
                ja      short loc_1400043B9
                mov     [rsi+10h], rcx
                mov     rax, rsi
                cmp     r8, 10h
                jb      short loc_1400043A2
                mov     rax, [rsi]

loc_1400043A2:                          ; CODE XREF: sub_1400042E0+BD↑j
                lea     rdi, [rax+rdx]
                mov     r8, rbp         ; Size
                xor     edx, edx        ; Val
                mov     rcx, rdi        ; void *
                call    memset
                mov     byte ptr [rdi+rbp], 0
                jmp     short loc_1400043C7
; ---------------------------------------------------------------------------

loc_1400043B9:                          ; CODE XREF: sub_1400042E0+B0↑j
                mov     r9, rbp
                mov     rdx, rbp
                mov     rcx, rsi        ; Src
                call    ExtendAndCopyString

loc_1400043C7:                          ; CODE XREF: sub_1400042E0+9B↑j
                                        ; sub_1400042E0+D7↑j
                mov     r9, rsi
                cmp     qword ptr [rsi+18h], 10h
                jb      short loc_1400043D4
                mov     r9, [rsi]       ; lpMultiByteStr

loc_1400043D4:                          ; CODE XREF: sub_1400042E0+EF↑j
                mov     [rsp+78h+var_58], ebx ; int
                mov     r8d, r14d       ; cchWideChar
                mov     rdx, r15        ; lpWideCharStr
                mov     ecx, r12d       ; CodePage
                call    __std_fs_convert_wide_to_narrow_replace_chars
                shr     rax, 20h
                test    eax, eax
                jnz     short loc_140004400

loc_1400043EE:                          ; CODE XREF: sub_1400042E0+40↑j
                mov     rax, rsi
                add     rsp, 40h
                pop     r15
                pop     r14
                pop     r12
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140004400:                          ; CODE XREF: sub_1400042E0+10C↑j
                mov     ecx, eax
                call    ThrowErrorAndException
; ---------------------------------------------------------------------------
                align 8

loc_140004408:                          ; CODE XREF: sub_1400042E0+4D↑j
                call    ThrowException
; ---------------------------------------------------------------------------
                align 2

loc_14000440E:                          ; CODE XREF: sub_1400042E0+74↑j
                mov     ecx, eax
                call    ThrowErrorAndException
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 1400042E0
sub_1400042E0   endp

algn_140004416:                         ; DATA XREF: .pdata:000000014000B30C↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall ProcessFiles(_QWORD *output, __int64 input)
ProcessFiles    proc near               ; CODE XREF: ProcessDirectory+48↑p
                                        ; DATA XREF: .pdata:000000014000B318↓o

closeResult     = qword ptr -2B8h
blockArray      = qword ptr -2A8h
blockSize       = qword ptr -290h
iteratorHandle  = qword ptr -288h
fileData        = byte ptr -280h
finalResult     = qword ptr -30h
var_28          = qword ptr -28h
arg_10          = qword ptr  18h

; FUNCTION CHUNK AT 0000000140006C2C SIZE 00000010 BYTES
; FUNCTION CHUNK AT 0000000140006C48 SIZE 0000001D BYTES

; __unwind { // __GSHandlerCheck_EH4
                mov     [rsp+arg_10], rbx
                push    rsi
                push    rdi
                push    r14
                sub     rsp, 2C0h
                mov     rax, cs:__security_cookie
                xor     rax, rsp
                mov     [rsp+2D8h+var_28], rax
                mov     r14, rcx
                xor     ebx, ebx
                lea     rcx, [rsp+2D8h+blockArray]
                call    CopyAndResizeArray
                nop
                mov     rsi, 0FFFFFFFFFFFFFFFFh
                mov     [rsp+2D8h+iteratorHandle], rsi
                lea     r9, [rsp+2D8h+fileData]
                lea     r8, [rsp+2D8h+iteratorHandle]
                xor     edx, edx
                lea     rcx, [rsp+2D8h+blockArray] ; void *
                call    OpenAndIterateDirectory
                mov     dword ptr [rsp+2D8h+closeResult+4], ebx
                test    eax, eax
                jnz     short loc_140004483
                mov     byte ptr [rsp+2D8h+closeResult], 1
                jmp     short loc_140004491
; ---------------------------------------------------------------------------

loc_140004483:                          ; CODE XREF: ProcessFiles+5A↑j
                mov     byte ptr [rsp+2D8h+closeResult], 0
                cmp     eax, 12h
                jz      short loc_140004491
                mov     dword ptr [rsp+2D8h+closeResult+4], eax

loc_140004491:                          ; CODE XREF: ProcessFiles+61↑j
                                        ; ProcessFiles+6B↑j
                mov     rax, [rsp+2D8h+closeResult]
                mov     [rsp+2D8h+finalResult], rax
                test    al, al
                jz      short loc_14000451B
                mov     ecx, 58h ; 'X'  ; Size
;   try {
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                mov     [rsp+2D8h+closeResult], rax
                xorps   xmm0, xmm0
                movups  xmmword ptr [rax], xmm0
                mov     dword ptr [rax+8], 1
                mov     dword ptr [rax+0Ch], 1
                lea     rax, off_1400077E0
                mov     [rdi], rax
                lea     rbx, [rdi+10h]
                lea     rdx, [rsp+2D8h+blockArray]
                mov     rcx, rbx
;   } // starts at 1400044A7
;   try {
                call    ProcessAndUpdate
                nop
                mov     [r14], rbx
                mov     rbx, [r14+8]
                mov     [r14+8], rdi
                test    rbx, rbx
                jz      short loc_14000451B
                mov     eax, esi
                lock xadd [rbx+8], eax
                cmp     eax, 1
                jnz     short loc_14000451B
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax]
                lock xadd [rbx+0Ch], esi
                cmp     esi, 1
                jnz     short loc_14000451B
                mov     rax, [rbx]
                mov     rcx, rbx
                call    qword ptr [rax+8]

loc_14000451B:                          ; CODE XREF: ProcessFiles+80↑j
                                        ; ProcessFiles+D2↑j ...
                mov     ebx, dword ptr [rsp+2D8h+finalResult+4]
                mov     rcx, [rsp+2D8h+iteratorHandle]
                call    CloseFileHandleAndCheck
                mov     rdx, [rsp+2D8h+blockSize]
                cmp     rdx, 8
                jb      short loc_140004571
                lea     rdx, ds:2[rdx*2]
                mov     rcx, [rsp+2D8h+blockArray] ; Block
                mov     rax, rcx
                cmp     rdx, 1000h
                jb      short loc_14000456C
                add     rdx, 27h ; '''
                mov     rcx, [rcx-8]
                sub     rax, rcx
                add     rax, 0FFFFFFFFFFFFFFF8h
                cmp     rax, 1Fh
                jbe     short loc_14000456C
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_14000456C:                          ; CODE XREF: ProcessFiles+12E↑j
                                        ; ProcessFiles+143↑j
                call    j_j_free

loc_140004571:                          ; CODE XREF: ProcessFiles+115↑j
                mov     eax, ebx
                mov     rcx, [rsp+2D8h+var_28]
                xor     rcx, rsp        ; StackCookie
;   } // starts at 1400044DE
                call    __security_check_cookie
                mov     rbx, [rsp+2D8h+arg_10]
                add     rsp, 2C0h
                pop     r14
                pop     rdi
                pop     rsi
                retn
; } // starts at 140004420
ProcessFiles    endp

; ---------------------------------------------------------------------------
algn_140004597:                         ; DATA XREF: .pdata:000000014000B318↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; void **__fastcall ModifyAndCopyData(void **Src, __int64, __int64, __int16)
ModifyAndCopyData proc near             ; CODE XREF: ProcessAndCopyData+205↑p
                                        ; DATA XREF: .rdata:0000000140008AC4↓o ...

var_28          = qword ptr -28h
arg_8           = qword ptr  10h
arg_10          = qword ptr  18h
arg_18          = qword ptr  20h

                push    rbx
                push    rsi
                push    r14
                push    r15
                sub     rsp, 28h
                mov     r14, [rcx+10h]
                mov     rbx, 7FFFFFFFFFFFFFFEh
                mov     rax, rbx
                movzx   r15d, r9w
                sub     rax, r14
                mov     rsi, rcx
                cmp     rax, 1
                jb      loc_140004729

loc_1400045D0:                          ; DATA XREF: .rdata:0000000140008AC4↓o
                                        ; .rdata:0000000140008AD4↓o ...
                mov     [rsp+48h+arg_8], rbp
                mov     rbp, [rcx+18h]
                mov     [rsp+48h+arg_18], r12
                lea     r12, [r14+1]
                mov     rdx, r12
                or      rdx, 7
                cmp     rdx, rbx
                ja      short loc_14000460D
                mov     rcx, rbp
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     rbp, rax
                ja      short loc_14000460D
                lea     rax, [rcx+rbp]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_14000460D:                          ; CODE XREF: ModifyAndCopyData+4C↑j
                                        ; ModifyAndCopyData+5D↑j
                mov     rcx, 0FFFFFFFFFFFFFFFFh
                mov     [rsp+48h+arg_10], rdi
                mov     rax, rbx
                mov     [rsp+48h+var_28], r13
                add     rax, 1
                cmovb   rax, rcx
                mov     rcx, 7FFFFFFFFFFFFFFFh
                cmp     rax, rcx
                ja      loc_14000472F
                lea     rcx, [rax+rax]  ; Size
                xor     r13d, r13d
                cmp     rcx, 1000h
                jb      short loc_140004678
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_14000472F
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_1400046EA
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_14000468A
; ---------------------------------------------------------------------------

loc_140004678:                          ; CODE XREF: ModifyAndCopyData+AA↑j
                test    rcx, rcx
                jz      short loc_140004687
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                jmp     short loc_14000468A
; ---------------------------------------------------------------------------

loc_140004687:                          ; CODE XREF: ModifyAndCopyData+DB↑j
                mov     rdi, r13

loc_14000468A:                          ; CODE XREF: ModifyAndCopyData+D6↑j
                                        ; ModifyAndCopyData+E5↑j
                add     r14, r14
                mov     [rsi+10h], r12
                mov     [rsi+18h], rbx
                mov     r8, r14         ; Size
                mov     rcx, rdi        ; void *
                cmp     rbp, 8
                jb      short loc_1400046F1
                mov     rbx, [rsi]
                mov     rdx, rbx        ; Src
                call    memcpy
                lea     rdx, ds:2[rbp*2]
                mov     [r14+rdi], r15w
                mov     [r14+rdi+2], r13w
                cmp     rdx, 1000h
                jb      short loc_1400046E0
                mov     rcx, [rbx-8]
                add     rdx, 27h ; '''
                sub     rbx, rcx
                lea     rax, [rbx-8]
                cmp     rax, 1Fh
                ja      short loc_1400046EA
                mov     rbx, rcx

loc_1400046E0:                          ; CODE XREF: ModifyAndCopyData+126↑j
                mov     rcx, rbx        ; Block
                call    j_j_free
                jmp     short loc_140004704
; ---------------------------------------------------------------------------

loc_1400046EA:                          ; CODE XREF: ModifyAndCopyData+C4↑j
                                        ; ModifyAndCopyData+13B↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400046F1:                          ; CODE XREF: ModifyAndCopyData+FF↑j
                mov     rdx, rsi        ; Src
                call    memcpy
                mov     [r14+rdi], r15w
                mov     [r14+rdi+2], r13w

loc_140004704:                          ; CODE XREF: ModifyAndCopyData+148↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     rdi, [rsp+48h+arg_10]
                mov     r13, [rsp+48h+var_28]
                mov     rbp, [rsp+48h+arg_8]
                mov     r12, [rsp+48h+arg_18]
                add     rsp, 28h
                pop     r15
                pop     r14
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140004729:                          ; CODE XREF: ModifyAndCopyData+2A↑j
                                        ; DATA XREF: .pdata:000000014000B330↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_14000472F:                          ; CODE XREF: ModifyAndCopyData+96↑j
                                        ; ModifyAndCopyData+B3↑j
                                        ; DATA XREF: ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
ModifyAndCopyData endp

algn_140004735:                         ; DATA XREF: .pdata:000000014000B348↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall ModifyAndCopyData_0(_QWORD *Src, unsigned __int64, __int64, const void *, __int64)
ModifyAndCopyData_0 proc near           ; CODE XREF: ProcessAndCopyData+25D↑p
                                        ; DATA XREF: .rdata:0000000140008B24↓o ...

Src             = qword ptr -48h
var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h
arg_10          = qword ptr  18h
arg_20          = qword ptr  28h

                push    rbx
                push    rsi
                push    r13
                push    r15
                sub     rsp, 48h
                mov     r15, [rcx+10h]
                mov     rbx, 7FFFFFFFFFFFFFFEh
                mov     r13, [rsp+68h+arg_20]
                mov     rax, rbx
                sub     rax, r15
                mov     [rsp+68h+Src], r9
                mov     rsi, rcx
                cmp     rax, rdx
                jb      loc_1400048F9

loc_140004778:                          ; DATA XREF: .rdata:0000000140008B24↓o
                                        ; .rdata:0000000140008B34↓o ...
                mov     [rsp+68h+arg_10], rbp
                mov     rbp, [rcx+18h]
                mov     [rsp+68h+var_38], r14
                lea     r14, [rdx+r15]
                mov     rdx, r14
                or      rdx, 7
                cmp     rdx, rbx
                ja      short loc_1400047B8
                mov     rcx, rbp
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     rbp, rax
                ja      short loc_1400047B8
                lea     rax, [rcx+rbp]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_1400047B8:                          ; CODE XREF: ModifyAndCopyData_0+57↑j
                                        ; ModifyAndCopyData_0+68↑j
                mov     rcx, 0FFFFFFFFFFFFFFFFh
                mov     [rsp+68h+var_28], rdi
                mov     rax, rbx
                mov     [rsp+68h+var_30], r12
                add     rax, 1
                cmovb   rax, rcx
                mov     rcx, 7FFFFFFFFFFFFFFFh
                cmp     rax, rcx
                ja      loc_1400048FF
                lea     rcx, [rax+rax]  ; Size
                xor     eax, eax
                cmp     rcx, 1000h
                jb      short loc_140004822
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_1400048FF
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_1400048AC
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_14000482F
; ---------------------------------------------------------------------------

loc_140004822:                          ; CODE XREF: ModifyAndCopyData_0+B4↑j
                test    rcx, rcx
                jz      short loc_14000482C
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)

loc_14000482C:                          ; CODE XREF: ModifyAndCopyData_0+E5↑j
                mov     rdi, rax

loc_14000482F:                          ; CODE XREF: ModifyAndCopyData_0+E0↑j
                mov     [rsi+10h], r14
                lea     r8, [r15+r15]   ; Size
                mov     [rsi+18h], rbx
                lea     rax, [r15+r13]
                lea     r12, [rdi+r8]
                mov     rcx, rdi        ; void *
                lea     r15, [rdi+rax*2]
                lea     r14, ds:0[r13*2]
                cmp     rbp, 8
                jb      short loc_1400048B3
                mov     rbx, [rsi]
                mov     rdx, rbx        ; Src
                call    memcpy
                mov     rdx, [rsp+68h+Src] ; Src
                mov     r8, r14         ; Size
                mov     rcx, r12        ; void *
                call    memcpy
                xor     eax, eax
                lea     rdx, ds:2[rbp*2]
                mov     [r15], ax
                cmp     rdx, 1000h
                jb      short loc_1400048A2
                mov     rcx, [rbx-8]
                add     rdx, 27h ; '''
                sub     rbx, rcx
                lea     rax, [rbx-8]
                cmp     rax, 1Fh
                ja      short loc_1400048AC
                mov     rbx, rcx

loc_1400048A2:                          ; CODE XREF: ModifyAndCopyData_0+148↑j
                mov     rcx, rbx        ; Block
                call    j_j_free
                jmp     short loc_1400048D1
; ---------------------------------------------------------------------------

loc_1400048AC:                          ; CODE XREF: ModifyAndCopyData_0+CE↑j
                                        ; ModifyAndCopyData_0+15D↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400048B3:                          ; CODE XREF: ModifyAndCopyData_0+116↑j
                mov     rdx, rsi        ; Src
                call    memcpy
                mov     rdx, [rsp+68h+Src] ; Src
                mov     r8, r14         ; Size
                mov     rcx, r12        ; void *
                call    memcpy
                xor     eax, eax
                mov     [r15], ax

loc_1400048D1:                          ; CODE XREF: ModifyAndCopyData_0+16A↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     r12, [rsp+68h+var_30]
                mov     rdi, [rsp+68h+var_28]
                mov     rbp, [rsp+68h+arg_10]
                mov     r14, [rsp+68h+var_38]
                add     rsp, 48h
                pop     r15
                pop     r13
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_1400048F9:                          ; CODE XREF: ModifyAndCopyData_0+32↑j
                                        ; DATA XREF: .pdata:000000014000B360↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_1400048FF:                          ; CODE XREF: ModifyAndCopyData_0+A1↑j
                                        ; ModifyAndCopyData_0+BD↑j
                                        ; DATA XREF: ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
ModifyAndCopyData_0 endp

algn_140004905:                         ; DATA XREF: .pdata:000000014000B378↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall sub_140004910(_QWORD *Src, unsigned __int64)
sub_140004910   proc near               ; CODE XREF: sub_140002510+F9↑p
                                        ; DATA XREF: .rdata:0000000140008B7C↓o ...

var_28          = qword ptr -28h
var_20          = qword ptr -20h
arg_10          = qword ptr  18h

                push    rbx
                push    rsi
                push    r14
                sub     rsp, 30h
                mov     r14, [rcx+10h]
                mov     rbx, 7FFFFFFFFFFFFFFFh
                mov     rax, rbx
                mov     rsi, rcx
                sub     rax, r14
                cmp     rax, rdx
                jb      loc_140004A51

loc_140004939:                          ; DATA XREF: .rdata:0000000140008B7C↓o
                                        ; .rdata:0000000140008B98↓o ...
                mov     [rsp+48h+arg_10], rbp
                mov     rbp, [rcx+18h]
                mov     [rsp+48h+var_28], r15
                lea     r15, [rdx+r14]
                mov     rdx, r15
                or      rdx, 0Fh
                cmp     rdx, rbx
                ja      short loc_140004976
                mov     rcx, rbp
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     rbp, rax
                ja      short loc_140004976
                lea     rax, [rcx+rbp]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_140004976:                          ; CODE XREF: sub_140004910+45↑j
                                        ; sub_140004910+56↑j
                mov     rcx, rbx
                mov     [rsp+48h+var_20], rdi
                add     rcx, 1
                mov     rax, 0FFFFFFFFFFFFFFFFh
                cmovb   rcx, rax        ; Size
                cmp     rcx, 1000h
                jb      short loc_1400049BE
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_140004A4B
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      short loc_140004A1E
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_1400049CF
; ---------------------------------------------------------------------------

loc_1400049BE:                          ; CODE XREF: sub_140004910+84↑j
                test    rcx, rcx
                jz      short loc_1400049CD
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                jmp     short loc_1400049CF
; ---------------------------------------------------------------------------

loc_1400049CD:                          ; CODE XREF: sub_140004910+B1↑j
                xor     edi, edi

loc_1400049CF:                          ; CODE XREF: sub_140004910+AC↑j
                                        ; sub_140004910+BB↑j
                mov     [rsi+10h], r15
                lea     r8, [r14+1]     ; Size
                mov     [rsi+18h], rbx
                mov     rcx, rdi        ; void *
                cmp     rbp, 10h
                jb      short loc_140004A25
                mov     rbx, [rsi]
                mov     rdx, rbx        ; Src
                call    memcpy
                lea     rdx, [rbp+1]
                cmp     rdx, 1000h
                jb      short loc_140004A14
                mov     rcx, [rbx-8]
                add     rdx, 27h ; '''
                sub     rbx, rcx
                lea     rax, [rbx-8]
                cmp     rax, 1Fh
                ja      short loc_140004A1E
                mov     rbx, rcx

loc_140004A14:                          ; CODE XREF: sub_140004910+EA↑j
                mov     rcx, rbx        ; Block
                call    j_j_free
                jmp     short loc_140004A2D
; ---------------------------------------------------------------------------

loc_140004A1E:                          ; CODE XREF: sub_140004910+9E↑j
                                        ; sub_140004910+FF↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140004A25:                          ; CODE XREF: sub_140004910+D2↑j
                mov     rdx, rsi        ; Src
                call    memcpy

loc_140004A2D:                          ; CODE XREF: sub_140004910+10C↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     rdi, [rsp+48h+var_20]
                mov     rbp, [rsp+48h+arg_10]
                mov     r15, [rsp+48h+var_28]
                add     rsp, 30h
                pop     r14
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140004A4B:                          ; CODE XREF: sub_140004910+8D↑j
                                        ; DATA XREF: .pdata:000000014000B390↓o ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_140004A51:                          ; CODE XREF: sub_140004910+23↑j
                                        ; DATA XREF: .pdata:000000014000B39C↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
sub_140004910   endp

algn_140004A57:                         ; DATA XREF: .pdata:000000014000B3A8↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall AllocateAndCopyStringToStruct(__int64 inputStruct, unsigned __int64 newLength, __int64 a3, const void *sourceString)
AllocateAndCopyStringToStruct proc near ; CODE XREF: CreatePathFromSegments:loc_14000221F↑p
                                        ; CopyAndResizeString+70↑p ...

var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h

                push    rbx
                push    rsi
                push    r14
                push    r15
                sub     rsp, 38h
                mov     rbx, 7FFFFFFFFFFFFFFEh
                mov     r15, r9
                mov     r14, rdx
                mov     rsi, rcx
                cmp     rdx, rbx
                ja      loc_140004BB2
                or      rdx, 7

loc_140004A8B:                          ; DATA XREF: .rdata:0000000140008BD4↓o
                                        ; .rdata:0000000140008BF0↓o ...
                mov     [rsp+58h+var_28], rbp
                mov     rbp, [rcx+18h]
                cmp     rdx, rbx
                ja      short loc_140004AB8
                mov     rcx, rbp
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     rbp, rax
                ja      short loc_140004AB8
                lea     rax, [rcx+rbp]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_140004AB8:                          ; CODE XREF: AllocateAndCopyStringToStruct+37↑j
                                        ; AllocateAndCopyStringToStruct+48↑j
                mov     rcx, 0FFFFFFFFFFFFFFFFh
                mov     [rsp+58h+var_30], rdi
                mov     rax, rbx
                mov     [rsp+58h+var_38], r12
                add     rax, 1
                cmovb   rax, rcx
                mov     rcx, 7FFFFFFFFFFFFFFFh
                cmp     rax, rcx
                ja      loc_140004BB8
                lea     rcx, [rax+rax]  ; Size
                xor     r12d, r12d
                cmp     rcx, 1000h
                jb      short loc_140004B23
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_140004BB8
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_140004BAB
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_140004B35
; ---------------------------------------------------------------------------

loc_140004B23:                          ; CODE XREF: AllocateAndCopyStringToStruct+95↑j
                test    rcx, rcx
                jz      short loc_140004B32
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                jmp     short loc_140004B35
; ---------------------------------------------------------------------------

loc_140004B32:                          ; CODE XREF: AllocateAndCopyStringToStruct+C6↑j
                mov     rdi, r12

loc_140004B35:                          ; CODE XREF: AllocateAndCopyStringToStruct+C1↑j
                                        ; AllocateAndCopyStringToStruct+D0↑j
                mov     [rsi+18h], rbx
                mov     rdx, r15        ; Src
                lea     rbx, [r14+r14]
                mov     [rsi+10h], r14
                mov     r8, rbx         ; Size
                mov     rcx, rdi        ; void *
                call    memcpy
                mov     [rbx+rdi], r12w
                cmp     rbp, 8
                jb      short loc_140004B8B
                mov     rcx, [rsi]
                lea     rdx, ds:2[rbp*2]
                cmp     rdx, 1000h
                jb      short loc_140004B86
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_140004BAB
                mov     rcx, r8         ; Block

loc_140004B86:                          ; CODE XREF: AllocateAndCopyStringToStruct+10C↑j
                call    j_j_free

loc_140004B8B:                          ; CODE XREF: AllocateAndCopyStringToStruct+F8↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     rdi, [rsp+58h+var_30]
                mov     r12, [rsp+58h+var_38]
                mov     rbp, [rsp+58h+var_28]
                add     rsp, 38h
                pop     r15
                pop     r14
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140004BAB:                          ; CODE XREF: AllocateAndCopyStringToStruct+AF↑j
                                        ; AllocateAndCopyStringToStruct+121↑j
                                        ; DATA XREF: ...
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140004BB2:                          ; CODE XREF: AllocateAndCopyStringToStruct+21↑j
                                        ; DATA XREF: .pdata:000000014000B3CC↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                align 8

loc_140004BB8:                          ; CODE XREF: AllocateAndCopyStringToStruct+81↑j
                                        ; AllocateAndCopyStringToStruct+9E↑j
                                        ; DATA XREF: ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
AllocateAndCopyStringToStruct endp

algn_140004BBE:                         ; DATA XREF: .pdata:000000014000B3E4↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; const void **__fastcall ExtendAndCopyString_0(const void **Src, unsigned __int64 extensionSize, __int64 lengthLimit, __int64 additionalDataSize)
ExtendAndCopyString_0 proc near         ; CODE XREF: ExtendAndCopyString_1+E8↑p
                                        ; DATA XREF: .rdata:0000000140008C30↓o ...

var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h
arg_10          = qword ptr  18h

                push    rdi
                push    r12
                push    r14
                push    r15
                sub     rsp, 38h
                mov     r12, [rcx+10h]
                mov     rdi, 7FFFFFFFFFFFFFFEh
                mov     rax, rdi
                mov     r15, r9
                sub     rax, r12
                mov     r14, rcx
                cmp     rax, rdx
                jb      loc_140004D6A

loc_140004BEF:                          ; DATA XREF: .rdata:0000000140008C30↓o
                                        ; .rdata:0000000140008C40↓o ...
                mov     [rsp+58h+var_28], rbp
                mov     rbp, [rcx+18h]
                mov     [rsp+58h+var_30], rsi
                lea     rsi, [rdx+r12]
                mov     rdx, rsi
                or      rdx, 7
                cmp     rdx, rdi
                ja      short loc_140004C2C
                mov     rcx, rbp
                mov     rax, rdi
                shr     rcx, 1
                sub     rax, rcx
                cmp     rbp, rax
                ja      short loc_140004C2C
                lea     rax, [rcx+rbp]
                mov     rdi, rdx
                cmp     rdx, rax
                cmovb   rdi, rax

loc_140004C2C:                          ; CODE XREF: ExtendAndCopyString_0+4B↑j
                                        ; ExtendAndCopyString_0+5C↑j
                mov     rcx, 0FFFFFFFFFFFFFFFFh
                mov     [rsp+58h+arg_10], rbx
                mov     rax, rdi
                mov     [rsp+58h+var_38], r13
                add     rax, 1
                cmovb   rax, rcx
                mov     rcx, 7FFFFFFFFFFFFFFFh
                cmp     rax, rcx
                ja      loc_140004D70
                lea     rcx, [rax+rax]  ; Size
                xor     r13d, r13d
                cmp     rcx, 1000h
                jb      short loc_140004C97
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_140004D70
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_140004D1A
                lea     rbx, [rax+27h]
                and     rbx, 0FFFFFFFFFFFFFFE0h
                mov     [rbx-8], rax
                jmp     short loc_140004CA9
; ---------------------------------------------------------------------------

loc_140004C97:                          ; CODE XREF: ExtendAndCopyString_0+A9↑j
                test    rcx, rcx
                jz      short loc_140004CA6
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rbx, rax
                jmp     short loc_140004CA9
; ---------------------------------------------------------------------------

loc_140004CA6:                          ; CODE XREF: ExtendAndCopyString_0+DA↑j
                mov     rbx, r13

loc_140004CA9:                          ; CODE XREF: ExtendAndCopyString_0+D5↑j
                                        ; ExtendAndCopyString_0+E4↑j
                mov     [r14+18h], rdi
                lea     rdi, [r12+r12]
                mov     [r14+10h], rsi
                mov     r8, rdi         ; Size
                mov     rcx, rbx        ; void *
                cmp     rbp, 8
                jb      short loc_140004D21
                mov     rsi, [r14]
                mov     rdx, rsi        ; Src
                call    memcpy
                add     rdi, rbx
                test    r15, r15
                jz      short loc_140004CDE
                movzx   eax, r13w
                mov     rcx, r15
                rep stosw

loc_140004CDE:                          ; CODE XREF: ExtendAndCopyString_0+112↑j
                lea     rdx, ds:2[rbp*2]
                lea     rax, [r15+r12]
                mov     [rbx+rax*2], r13w
                cmp     rdx, 1000h
                jb      short loc_140004D10
                mov     rcx, [rsi-8]
                add     rdx, 27h ; '''
                sub     rsi, rcx
                lea     rax, [rsi-8]
                cmp     rax, 1Fh
                ja      short loc_140004D1A
                mov     rsi, rcx

loc_140004D10:                          ; CODE XREF: ExtendAndCopyString_0+136↑j
                mov     rcx, rsi        ; Block
                call    j_j_free
                jmp     short loc_140004D44
; ---------------------------------------------------------------------------

loc_140004D1A:                          ; CODE XREF: ExtendAndCopyString_0+C3↑j
                                        ; ExtendAndCopyString_0+14B↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140004D21:                          ; CODE XREF: ExtendAndCopyString_0+FF↑j
                mov     rdx, r14        ; Src
                call    memcpy
                add     rdi, rbx
                test    r15, r15
                jz      short loc_140004D3B
                movzx   eax, r13w
                mov     rcx, r15
                rep stosw

loc_140004D3B:                          ; CODE XREF: ExtendAndCopyString_0+16F↑j
                lea     rcx, [r15+r12]
                mov     [rbx+rcx*2], r13w

loc_140004D44:                          ; CODE XREF: ExtendAndCopyString_0+158↑j
                mov     [r14], rbx
                mov     rax, r14
                mov     rbx, [rsp+58h+arg_10]
                mov     r13, [rsp+58h+var_38]
                mov     rbp, [rsp+58h+var_28]
                mov     rsi, [rsp+58h+var_30]
                add     rsp, 38h
                pop     r15
                pop     r14
                pop     r12
                pop     rdi
                retn
; ---------------------------------------------------------------------------

loc_140004D6A:                          ; CODE XREF: ExtendAndCopyString_0+29↑j
                                        ; DATA XREF: .pdata:000000014000B3FC↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                align 10h

loc_140004D70:                          ; CODE XREF: ExtendAndCopyString_0+95↑j
                                        ; ExtendAndCopyString_0+B2↑j
                                        ; DATA XREF: ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
ExtendAndCopyString_0 endp

algn_140004D76:                         ; DATA XREF: .pdata:000000014000B414↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall ExtendAndCopyStringWithChar(_QWORD *Src, __int64, __int64, char)
ExtendAndCopyStringWithChar proc near   ; CODE XREF: sub_140002510+1B2↑p
                                        ; DATA XREF: .rdata:0000000140008C7C↓o ...

var_28          = qword ptr -28h
arg_8           = qword ptr  10h
arg_10          = qword ptr  18h

                push    rbx
                push    rsi
                push    r14
                push    r15
                sub     rsp, 28h
                mov     r14, [rcx+10h]
                mov     rbx, 7FFFFFFFFFFFFFFFh
                mov     rax, rbx
                movzx   r15d, r9b
                sub     rax, r14
                mov     rsi, rcx
                cmp     rax, 1
                jb      loc_140004EDD

loc_140004DB0:                          ; DATA XREF: .rdata:0000000140008C7C↓o
                                        ; .rdata:0000000140008C98↓o ...
                mov     [rsp+48h+arg_8], rbp
                mov     rbp, [rcx+18h]
                mov     [rsp+48h+var_28], r12
                lea     r12, [r14+1]
                mov     rdx, r12
                or      rdx, 0Fh
                cmp     rdx, rbx
                ja      short loc_140004DED
                mov     rcx, rbp
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     rbp, rax
                ja      short loc_140004DED
                lea     rax, [rcx+rbp]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_140004DED:                          ; CODE XREF: ExtendAndCopyStringWithChar+4C↑j
                                        ; ExtendAndCopyStringWithChar+5D↑j
                mov     rcx, rbx
                mov     [rsp+48h+arg_10], rdi
                add     rcx, 1
                mov     rax, 0FFFFFFFFFFFFFFFFh
                cmovb   rcx, rax        ; Size
                cmp     rcx, 1000h
                jb      short loc_140004E35
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_140004ED7
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      short loc_140004E9E
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_140004E46
; ---------------------------------------------------------------------------

loc_140004E35:                          ; CODE XREF: ExtendAndCopyStringWithChar+8B↑j
                test    rcx, rcx
                jz      short loc_140004E44
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                jmp     short loc_140004E46
; ---------------------------------------------------------------------------

loc_140004E44:                          ; CODE XREF: ExtendAndCopyStringWithChar+B8↑j
                xor     edi, edi

loc_140004E46:                          ; CODE XREF: ExtendAndCopyStringWithChar+B3↑j
                                        ; ExtendAndCopyStringWithChar+C2↑j
                mov     [rsi+10h], r12
                mov     r8, r14         ; Size
                mov     [rsi+18h], rbx
                mov     rcx, rdi        ; void *
                cmp     rbp, 10h
                jb      short loc_140004EA5
                mov     rbx, [rsi]
                mov     rdx, rbx        ; Src
                call    memcpy
                lea     rdx, [rbp+1]
                mov     [r14+rdi], r15b
                mov     byte ptr [r14+rdi+1], 0
                cmp     rdx, 1000h
                jb      short loc_140004E94
                mov     rcx, [rbx-8]
                add     rdx, 27h ; '''
                sub     rbx, rcx
                lea     rax, [rbx-8]
                cmp     rax, 1Fh
                ja      short loc_140004E9E
                mov     rbx, rcx

loc_140004E94:                          ; CODE XREF: ExtendAndCopyStringWithChar+FA↑j
                mov     rcx, rbx        ; Block
                call    j_j_free
                jmp     short loc_140004EB7
; ---------------------------------------------------------------------------

loc_140004E9E:                          ; CODE XREF: ExtendAndCopyStringWithChar+A5↑j
                                        ; ExtendAndCopyStringWithChar+10F↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_140004EA5:                          ; CODE XREF: ExtendAndCopyStringWithChar+D8↑j
                mov     rdx, rsi        ; Src
                call    memcpy
                mov     [r14+rdi], r15b
                mov     byte ptr [r14+rdi+1], 0

loc_140004EB7:                          ; CODE XREF: ExtendAndCopyStringWithChar+11C↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     rdi, [rsp+48h+arg_10]
                mov     rbp, [rsp+48h+arg_8]
                mov     r12, [rsp+48h+var_28]
                add     rsp, 28h
                pop     r15
                pop     r14
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140004ED7:                          ; CODE XREF: ExtendAndCopyStringWithChar+94↑j
                                        ; DATA XREF: .pdata:000000014000B42C↓o ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_140004EDD:                          ; CODE XREF: ExtendAndCopyStringWithChar+2A↑j
                                        ; DATA XREF: .pdata:000000014000B438↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
ExtendAndCopyStringWithChar endp

algn_140004EE3:                         ; DATA XREF: .pdata:000000014000B444↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; void **__fastcall ExtendAndCopyString(void **Src, size_t extensionSize, __int64 lengthLimit, size_t additionalDataSize)
ExtendAndCopyString proc near           ; CODE XREF: sub_1400042E0+E2↑p
                                        ; ConvertAndCopyWideToNarrow+E2↓p
                                        ; DATA XREF: ...

var_38          = qword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h
arg_10          = qword ptr  18h

                push    rbx
                push    rsi
                push    r12
                push    r15
                sub     rsp, 38h
                mov     r15, [rcx+10h]
                mov     rbx, 7FFFFFFFFFFFFFFFh
                mov     rax, rbx
                mov     r12, r9
                sub     rax, r15
                mov     rsi, rcx
                cmp     rax, rdx
                jb      loc_140005071

loc_140004F1E:                          ; DATA XREF: .rdata:0000000140008CD8↓o
                                        ; .rdata:0000000140008CF8↓o ...
                mov     [rsp+58h+arg_10], rbp
                lea     rbp, [rdx+r15]
                mov     rdx, rbp
                mov     [rsp+58h+var_30], r13
                mov     r13, [rcx+18h]
                or      rdx, 0Fh
                cmp     rdx, rbx
                ja      short loc_140004F5B
                mov     rcx, r13
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     r13, rax
                ja      short loc_140004F5B
                lea     rax, [rcx+r13]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_140004F5B:                          ; CODE XREF: ExtendAndCopyString+4A↑j
                                        ; ExtendAndCopyString+5B↑j
                mov     rcx, rbx
                mov     [rsp+58h+var_28], rdi
                add     rcx, 1
                mov     [rsp+58h+var_38], r14
                mov     rax, 0FFFFFFFFFFFFFFFFh
                cmovb   rcx, rax        ; Size
                cmp     rcx, 1000h
                jb      short loc_140004FAC
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_14000506B
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_140005025
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_140004FBD
; ---------------------------------------------------------------------------

loc_140004FAC:                          ; CODE XREF: ExtendAndCopyString+8E↑j
                test    rcx, rcx
                jz      short loc_140004FBB
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                jmp     short loc_140004FBD
; ---------------------------------------------------------------------------

loc_140004FBB:                          ; CODE XREF: ExtendAndCopyString+BF↑j
                xor     edi, edi

loc_140004FBD:                          ; CODE XREF: ExtendAndCopyString+BA↑j
                                        ; ExtendAndCopyString+C9↑j
                mov     [rsi+10h], rbp
                lea     rbp, [rdi+r15]
                mov     [rsi+18h], rbx
                lea     r14, [rdi+r15]
                mov     r8, r15         ; Size
                mov     rcx, rdi        ; void *
                cmp     r13, 10h
                jb      short loc_14000502C
                mov     rbx, [rsi]
                mov     rdx, rbx        ; Src
                call    memcpy
                mov     r8, r12         ; Size
                xor     edx, edx        ; Val
                mov     rcx, rbp        ; void *
                call    memset
                lea     rdx, [r13+1]
                mov     byte ptr [r14+r12], 0
                cmp     rdx, 1000h
                jb      short loc_14000501B
                mov     rcx, [rbx-8]
                add     rdx, 27h ; '''
                sub     rbx, rcx
                lea     rax, [rbx-8]
                cmp     rax, 1Fh
                ja      short loc_140005025
                mov     rbx, rcx

loc_14000501B:                          ; CODE XREF: ExtendAndCopyString+111↑j
                mov     rcx, rbx        ; Block
                call    j_j_free
                jmp     short loc_140005046
; ---------------------------------------------------------------------------

loc_140005025:                          ; CODE XREF: ExtendAndCopyString+A8↑j
                                        ; ExtendAndCopyString+126↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_14000502C:                          ; CODE XREF: ExtendAndCopyString+E7↑j
                mov     rdx, rsi        ; Src
                call    memcpy
                mov     r8, r12         ; Size
                xor     edx, edx        ; Val
                mov     rcx, rbp        ; void *
                call    memset
                mov     byte ptr [r14+r12], 0

loc_140005046:                          ; CODE XREF: ExtendAndCopyString+133↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     rdi, [rsp+58h+var_28]
                mov     r14, [rsp+58h+var_38]
                mov     rbp, [rsp+58h+arg_10]
                mov     r13, [rsp+58h+var_30]
                add     rsp, 38h
                pop     r15
                pop     r12
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_14000506B:                          ; CODE XREF: ExtendAndCopyString+97↑j
                                        ; DATA XREF: .pdata:000000014000B45C↓o ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_140005071:                          ; CODE XREF: ExtendAndCopyString+28↑j
                                        ; DATA XREF: .pdata:000000014000B468↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
ExtendAndCopyString endp

algn_140005077:                         ; DATA XREF: .pdata:000000014000B474↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; void **__fastcall ResizeAndCopyMemoryBlock(void **sourceArray, size_t newLength, __int64 a3, const void *dataToCopy, size_t dataSize)
ResizeAndCopyMemoryBlock proc near      ; CODE XREF: CopyDataToMemoryBlock+70↑p
                                        ; DATA XREF: .rdata:0000000140008D34↓o ...

var_38          = qword ptr -38h
var_30          = qword ptr -30h
arg_10          = qword ptr  18h
dataSize        = qword ptr  28h

                push    rbx
                push    rsi
                push    r12
                push    r13
                push    r15
                sub     rsp, 30h
                mov     r15, [rcx+10h]
                mov     rbx, 7FFFFFFFFFFFFFFFh
                mov     r12, [rsp+58h+dataSize]
                mov     rax, rbx
                sub     rax, r15
                mov     r13, r9
                mov     rsi, rcx
                cmp     rax, rdx
                jb      loc_140005201

loc_1400050B8:                          ; DATA XREF: .rdata:0000000140008D34↓o
                                        ; .rdata:0000000140008D50↓o ...
                mov     [rsp+58h+arg_10], rbp
                lea     rbp, [rdx+r15]
                mov     rdx, rbp
                mov     [rsp+58h+var_38], r14
                mov     r14, [rcx+18h]
                or      rdx, 0Fh
                cmp     rdx, rbx
                ja      short loc_1400050F5
                mov     rcx, r14
                mov     rax, rbx
                shr     rcx, 1
                sub     rax, rcx
                cmp     r14, rax
                ja      short loc_1400050F5
                lea     rax, [rcx+r14]
                mov     rbx, rdx
                cmp     rdx, rax
                cmovb   rbx, rax

loc_1400050F5:                          ; CODE XREF: ResizeAndCopyMemoryBlock+54↑j
                                        ; ResizeAndCopyMemoryBlock+65↑j
                mov     rcx, rbx
                mov     [rsp+58h+var_30], rdi
                add     rcx, 1
                mov     rax, 0FFFFFFFFFFFFFFFFh
                cmovb   rcx, rax        ; Size
                cmp     rcx, 1000h
                jb      short loc_140005141
                lea     rax, [rcx+27h]
                cmp     rax, rcx
                jbe     loc_1400051FB
                mov     rcx, rax        ; Size
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                test    rax, rax
                jz      loc_1400051B7
                lea     rdi, [rax+27h]
                and     rdi, 0FFFFFFFFFFFFFFE0h
                mov     [rdi-8], rax
                jmp     short loc_140005152
; ---------------------------------------------------------------------------

loc_140005141:                          ; CODE XREF: ResizeAndCopyMemoryBlock+93↑j
                test    rcx, rcx
                jz      short loc_140005150
                call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
                mov     rdi, rax
                jmp     short loc_140005152
; ---------------------------------------------------------------------------

loc_140005150:                          ; CODE XREF: ResizeAndCopyMemoryBlock+C4↑j
                xor     edi, edi

loc_140005152:                          ; CODE XREF: ResizeAndCopyMemoryBlock+BF↑j
                                        ; ResizeAndCopyMemoryBlock+CE↑j
                mov     [rsi+10h], rbp
                lea     rbp, [r15+rdi]
                mov     [rsi+18h], rbx
                mov     r8, r15         ; Size
                mov     rcx, rdi        ; void *
                cmp     r14, 10h
                jb      short loc_1400051BE
                mov     rbx, [rsi]
                mov     rdx, rbx        ; Src
                call    memcpy
                mov     r8, r12         ; Size
                mov     rdx, r13        ; Src
                mov     rcx, rbp        ; void *
                call    memcpy
                lea     rdx, [r14+1]
                mov     byte ptr [r12+rbp], 0
                cmp     rdx, 1000h
                jb      short loc_1400051AD
                mov     rcx, [rbx-8]
                add     rdx, 27h ; '''
                sub     rbx, rcx
                lea     rax, [rbx-8]
                cmp     rax, 1Fh
                ja      short loc_1400051B7
                mov     rbx, rcx

loc_1400051AD:                          ; CODE XREF: ResizeAndCopyMemoryBlock+113↑j
                mov     rcx, rbx        ; Block
                call    j_j_free
                jmp     short loc_1400051D9
; ---------------------------------------------------------------------------

loc_1400051B7:                          ; CODE XREF: ResizeAndCopyMemoryBlock+AD↑j
                                        ; ResizeAndCopyMemoryBlock+128↑j
                call    cs:_invalid_parameter_noinfo_noreturn
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_1400051BE:                          ; CODE XREF: ResizeAndCopyMemoryBlock+E8↑j
                mov     rdx, rsi        ; Src
                call    memcpy
                mov     r8, r12         ; Size
                mov     rdx, r13        ; Src
                mov     rcx, rbp        ; void *
                call    memcpy
                mov     byte ptr [r12+rbp], 0

loc_1400051D9:                          ; CODE XREF: ResizeAndCopyMemoryBlock+135↑j
                mov     [rsi], rdi
                mov     rax, rsi
                mov     rdi, [rsp+58h+var_30]
                mov     rbp, [rsp+58h+arg_10]
                mov     r14, [rsp+58h+var_38]
                add     rsp, 30h
                pop     r15
                pop     r13
                pop     r12
                pop     rsi
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_1400051FB:                          ; CODE XREF: ResizeAndCopyMemoryBlock+9C↑j
                                        ; DATA XREF: .pdata:000000014000B48C↓o ...
                call    ThrowBadArrayLengthException
; ---------------------------------------------------------------------------
                db 0CCh
; ---------------------------------------------------------------------------

loc_140005201:                          ; CODE XREF: ResizeAndCopyMemoryBlock+32↑j
                                        ; DATA XREF: .pdata:000000014000B498↓o ...
                call    ThrowStringLengthExceededException
; ---------------------------------------------------------------------------
                db 0CCh
ResizeAndCopyMemoryBlock endp

algn_140005207:                         ; DATA XREF: .pdata:000000014000B4A4↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall ResetFileHandleData(__int64 fileData)
ResetFileHandleData proc near           ; CODE XREF: ResetFileHandleWrapper+7↓j
                                        ; DATA XREF: .rdata:0000000140008A8A↓o ...
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rcx, [rcx+20h]
                call    CloseFileHandleAndCheck
                mov     rdx, [rbx+18h]
                cmp     rdx, 8
                jb      short loc_14000525D
                mov     rcx, [rbx]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_140005258
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_140005274
                mov     rcx, r8         ; Block

loc_140005258:                          ; CODE XREF: ResetFileHandleData+2E↑j
                call    j_j_free

loc_14000525D:                          ; CODE XREF: ResetFileHandleData+1A↑j
                xor     eax, eax
                mov     qword ptr [rbx+18h], 7
                mov     [rbx+10h], rax
                mov     [rbx], ax
                add     rsp, 20h
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140005274:                          ; CODE XREF: ResetFileHandleData+43↑j
                call    cs:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                db 0CCh
ResetFileHandleData endp

algn_14000527B:                         ; DATA XREF: .pdata:000000014000B4B0↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140005280(__int64)
sub_140005280   proc near               ; DATA XREF: .rdata:00000001400077E8↓o
                test    rcx, rcx
                jz      short locret_140005291
                mov     rax, [rcx]
                mov     edx, 1
                jmp     qword ptr [rax+10h]
; ---------------------------------------------------------------------------

locret_140005291:                       ; CODE XREF: sub_140005280+3↑j
                retn
sub_140005280   endp

; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_1400052A0(__int64)
sub_1400052A0   proc near               ; DATA XREF: .rdata:off_1400077E0↓o
                                        ; .pdata:000000014000B4BC↓o
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rcx, [rcx+50h]
                call    CloseFileHandleAndCheck
                mov     rdx, [rbx+48h]
                cmp     rdx, 8
                jb      short loc_1400052EE
                mov     rcx, [rbx+30h]
                lea     rdx, ds:2[rdx*2]
                cmp     rdx, 1000h
                jb      short loc_1400052E9
                mov     r8, [rcx-8]
                add     rdx, 27h ; '''
                sub     rcx, r8
                lea     rax, [rcx-8]
                cmp     rax, 1Fh
                ja      short loc_140005306
                mov     rcx, r8         ; Block

loc_1400052E9:                          ; CODE XREF: sub_1400052A0+2F↑j
                call    j_j_free

loc_1400052EE:                          ; CODE XREF: sub_1400052A0+1A↑j
                xor     eax, eax
                mov     [rbx+30h], ax
                mov     [rbx+40h], rax
                mov     qword ptr [rbx+48h], 7
                add     rsp, 20h
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140005306:                          ; CODE XREF: sub_1400052A0+44↑j
                call    cs:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                db 0CCh
sub_1400052A0   endp

algn_14000530D:                         ; DATA XREF: .pdata:000000014000B4BC↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall sub_140005310(_QWORD *, char)
sub_140005310   proc near               ; DATA XREF: .rdata:00000001400077F0↓o
                                        ; .pdata:000000014000B4C8↓o
                push    rbx
                sub     rsp, 20h
                lea     rax, off_1400077E0
                mov     rbx, rcx
                mov     [rcx], rax
                test    dl, 1
                jz      short loc_140005332
                mov     edx, 58h ; 'X'
                call    j_j_free

loc_140005332:                          ; CODE XREF: sub_140005310+16↑j
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
sub_140005310   endp

; ---------------------------------------------------------------------------
algn_14000533B:                         ; DATA XREF: .pdata:000000014000B4C8↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall ConvertAndCopyWideToNarrow(_QWORD *Src, UINT CodePage, __int64 wideStringInfo)
ConvertAndCopyWideToNarrow proc near    ; CODE XREF: main+2D9↑p
                                        ; DATA XREF: .pdata:000000014000B4D4↓o

var_58          = dword ptr -58h
var_48          = dword ptr -48h
var_40          = qword ptr -40h

; FUNCTION CHUNK AT 0000000140006836 SIZE 00000006 BYTES
; FUNCTION CHUNK AT 0000000140006BF0 SIZE 00000026 BYTES

; __unwind { // __CxxFrameHandler4
                push    rbx
                push    rbp
                push    rsi
                push    rdi
                push    r12
                push    r14
                push    r15
                sub     rsp, 40h
                mov     r12d, edx
                mov     rsi, rcx
                mov     [rsp+78h+var_40], rcx
                xor     eax, eax
                mov     [rsp+78h+var_48], eax
                mov     [rcx], rax
                mov     [rcx+10h], rax
                mov     qword ptr [rcx+18h], 0Fh
                mov     [rcx], al
                mov     [rsp+78h+var_48], 1
                mov     r14, [r8+8]
                test    r14, r14
                jz      loc_14000544E
                cmp     r14, 7FFFFFFFh
                ja      loc_140005468
                mov     r15, [r8]
                mov     [rsp+78h+var_58], eax ; int
                xor     r9d, r9d        ; lpMultiByteStr
                mov     r8d, r14d       ; cchWideChar
                mov     rdx, r15        ; lpWideCharStr
                mov     ecx, r12d       ; CodePage
                call    __std_fs_convert_wide_to_narrow
                mov     rbx, rax
                shr     rax, 20h
                test    eax, eax
                jnz     loc_14000546E
                movsxd  rcx, ebx
                mov     rdx, [rsi+10h]
                cmp     rcx, rdx
                ja      short loc_1400053DD
                mov     rax, rsi
                cmp     qword ptr [rsi+18h], 10h
                jb      short loc_1400053D3
                mov     rax, [rsi]

loc_1400053D3:                          ; CODE XREF: ConvertAndCopyWideToNarrow+8E↑j
                mov     [rsi+10h], rcx
                mov     byte ptr [rax+rcx], 0
                jmp     short loc_140005427
; ---------------------------------------------------------------------------

loc_1400053DD:                          ; CODE XREF: ConvertAndCopyWideToNarrow+84↑j
                mov     rbp, rcx
                sub     rbp, rdx
                mov     r8, [rsi+18h]
                mov     rax, r8
                sub     rax, rdx
                cmp     rbp, rax
                ja      short loc_140005419
                mov     [rsi+10h], rcx
                mov     rax, rsi
                cmp     r8, 10h
                jb      short loc_140005402
                mov     rax, [rsi]

loc_140005402:                          ; CODE XREF: ConvertAndCopyWideToNarrow+BD↑j
                lea     rdi, [rax+rdx]
                mov     r8, rbp         ; Size
                xor     edx, edx        ; Val
                mov     rcx, rdi        ; void *
                call    memset
                mov     byte ptr [rdi+rbp], 0
                jmp     short loc_140005427
; ---------------------------------------------------------------------------

loc_140005419:                          ; CODE XREF: ConvertAndCopyWideToNarrow+B0↑j
                mov     r9, rbp
                mov     rdx, rbp
                mov     rcx, rsi        ; Src
                call    ExtendAndCopyString

loc_140005427:                          ; CODE XREF: ConvertAndCopyWideToNarrow+9B↑j
                                        ; ConvertAndCopyWideToNarrow+D7↑j
                mov     r9, rsi
                cmp     qword ptr [rsi+18h], 10h
                jb      short loc_140005434
                mov     r9, [rsi]       ; lpMultiByteStr

loc_140005434:                          ; CODE XREF: ConvertAndCopyWideToNarrow+EF↑j
                mov     [rsp+78h+var_58], ebx ; int
                mov     r8d, r14d       ; cchWideChar
                mov     rdx, r15        ; lpWideCharStr
                mov     ecx, r12d       ; CodePage
                call    __std_fs_convert_wide_to_narrow
                shr     rax, 20h
                test    eax, eax
                jnz     short loc_140005460

loc_14000544E:                          ; CODE XREF: ConvertAndCopyWideToNarrow+40↑j
                mov     rax, rsi
                add     rsp, 40h
                pop     r15
                pop     r14
                pop     r12
                pop     rdi
                pop     rsi
                pop     rbp
                pop     rbx
                retn
; ---------------------------------------------------------------------------

loc_140005460:                          ; CODE XREF: ConvertAndCopyWideToNarrow+10C↑j
                mov     ecx, eax
                call    ThrowErrorAndException
; ---------------------------------------------------------------------------
                align 8

loc_140005468:                          ; CODE XREF: ConvertAndCopyWideToNarrow+4D↑j
                call    ThrowException
; ---------------------------------------------------------------------------
                align 2

loc_14000546E:                          ; CODE XREF: ConvertAndCopyWideToNarrow+74↑j
                mov     ecx, eax
                call    ThrowErrorAndException
; ---------------------------------------------------------------------------
                db 0CCh
; } // starts at 140005340
ConvertAndCopyWideToNarrow endp

algn_140005476:                         ; DATA XREF: .pdata:000000014000B4D4↓o
                align 8
; [0000005E BYTES: COLLAPSED FUNCTION __std_system_error_allocate_message. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400054D6:                         ; DATA XREF: .pdata:000000014000B4E0↓o
                align 8
; [00000007 BYTES: COLLAPSED FUNCTION LocalFree. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h
; [00000027 BYTES: COLLAPSED FUNCTION __std_fs_code_page. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005507:                         ; DATA XREF: .pdata:000000014000B4EC↓o
                align 8
; [00000045 BYTES: COLLAPSED FUNCTION __std_fs_convert_narrow_to_wide. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_14000554D:                         ; DATA XREF: .pdata:000000014000B4F8↓o
                align 10h
; [00000121 BYTES: COLLAPSED FUNCTION __std_fs_convert_wide_to_narrow. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005671:                         ; DATA XREF: .pdata:000000014000B504↓o
                align 4
; [000000CB BYTES: COLLAPSED FUNCTION __std_fs_convert_wide_to_narrow_replace_chars. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_14000573F:                         ; DATA XREF: .pdata:000000014000B510↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; DWORD __fastcall FindNextFileInfo(void *searchHandle, struct _WIN32_FIND_DATAW *fileInfo)
FindNextFileInfo proc near              ; CODE XREF: OpenAndIterateDirectory+106↑p
                                        ; ProcessDirectory+298↑p
                                        ; DATA XREF: ...
                sub     rsp, 28h
                call    cs:FindNextFileW
                test    eax, eax
                jz      short loc_140005755
                xor     eax, eax
                add     rsp, 28h
                retn
; ---------------------------------------------------------------------------

loc_140005755:                          ; CODE XREF: FindNextFileInfo+C↑j
                add     rsp, 28h
                jmp     cs:GetLastError
FindNextFileInfo endp


; =============== S U B R O U T I N E =======================================


; void __fastcall CloseFileHandleAndCheck(void *fileHandle)
CloseFileHandleAndCheck proc near       ; CODE XREF: sub_140001BB0+3↑j
                                        ; ProcessFiles+107↑p ...
                sub     rsp, 28h
                cmp     rcx, 0FFFFFFFFFFFFFFFFh
                jz      short loc_14000577B
                call    cs:FindClose
                test    eax, eax
                jnz     short loc_14000577B
                call    cs:__imp_terminate
                int     3               ; Trap to Debugger
; ---------------------------------------------------------------------------

loc_14000577B:                          ; CODE XREF: CloseFileHandleAndCheck+8↑j
                                        ; CloseFileHandleAndCheck+12↑j
                add     rsp, 28h
                retn
CloseFileHandleAndCheck endp

; [000000A8 BYTES: COLLAPSED FUNCTION __std_fs_directory_iterator_open. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000292 BYTES: COLLAPSED FUNCTION __std_fs_get_stats. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005ABA:                         ; DATA XREF: .pdata:000000014000B540↓o
                align 4
; [00000057 BYTES: COLLAPSED FUNCTION __std_fs_open_handle. PRESS CTRL-NUMPAD+ TO EXPAND]
byte_140005B13  db 13h dup(0CCh)        ; DATA XREF: .pdata:000000014000B54C↓o
                align 10h
; [0000001E BYTES: COLLAPSED FUNCTION __security_check_cookie. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005B4E:                         ; DATA XREF: .pdata:000000014000B558↓o
                align 10h
; [0000003C BYTES: COLLAPSED FUNCTION operator new(unsigned __int64). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION j_free. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000005 BYTES: COLLAPSED FUNCTION j_j_free. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall sub_140005B9C(_QWORD *, char)
sub_140005B9C   proc near               ; DATA XREF: .rdata:off_1400074B8↓o
                                        ; .pdata:000000014000B570↓o
                push    rbx
                sub     rsp, 20h
                lea     rax, off_1400074B8
                mov     rbx, rcx
                mov     [rcx], rax
                test    dl, 1
                jz      short loc_140005BBE
                mov     edx, 18h
                call    j_j_free

loc_140005BBE:                          ; CODE XREF: sub_140005B9C+16↑j
                mov     rax, rbx
                add     rsp, 20h
                pop     rbx
                retn
sub_140005B9C   endp

; ---------------------------------------------------------------------------
algn_140005BC7:                         ; DATA XREF: .pdata:000000014000B570↓o
                align 8
; [000000B6 BYTES: COLLAPSED FUNCTION pre_c_initialization(void). PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005C7E:                         ; DATA XREF: .pdata:000000014000B57C↓o
                align 20h
; [00000010 BYTES: COLLAPSED FUNCTION post_pgo_initialization(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000019 BYTES: COLLAPSED FUNCTION pre_cpp_initialization(void). PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005CA9:                         ; DATA XREF: .pdata:000000014000B594↓o
                align 4
; [0000017C BYTES: COLLAPSED FUNCTION __scrt_common_main_seh(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000012 BYTES: COLLAPSED FUNCTION start. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005E3A:                         ; DATA XREF: .pdata:000000014000B5AC↓o
                align 4
; [0000001D BYTES: COLLAPSED FUNCTION __GSHandlerCheck. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005E59:                         ; DATA XREF: .pdata:000000014000B5B8↓o
                align 4
; [0000005B BYTES: COLLAPSED FUNCTION __GSHandlerCheckCommon. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005EB7:                         ; DATA XREF: .pdata:000000014000B5C4↓o
                align 8
; [00000034 BYTES: COLLAPSED FUNCTION __raise_securityfailure. PRESS CTRL-NUMPAD+ TO EXPAND]
; [000000D2 BYTES: COLLAPSED FUNCTION __report_gsfailure. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140005FBE:                         ; DATA XREF: .pdata:000000014000B5DC↓o
                align 20h
; [00000071 BYTES: COLLAPSED FUNCTION capture_previous_context. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140006031:                         ; DATA XREF: .pdata:000000014000B5E8↓o
                align 4

; =============== S U B R O U T I N E =======================================


; _QWORD *__fastcall CreateBadAllocationException(_QWORD *)
CreateBadAllocationException proc near  ; CODE XREF: ThrowBadAllocationException+9↓p
                and     qword ptr [rcx+10h], 0
                lea     rax, aBadAllocation ; "bad allocation"
                mov     [rcx+8], rax
                lea     rax, off_1400074F0
                mov     [rcx], rax
                mov     rax, rcx
                retn
CreateBadAllocationException endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

ThrowBadAllocationException proc near   ; CODE XREF: operator new(unsigned __int64)+30↑p
                                        ; DATA XREF: .pdata:000000014000B5F4↓o

pExceptionObject= byte ptr -28h

                sub     rsp, 48h
                lea     rcx, [rsp+48h+pExceptionObject]
                call    CreateBadAllocationException
                lea     rdx, stru_140008EB0 ; pThrowInfo
                lea     rcx, [rsp+48h+pExceptionObject] ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                align 4
ThrowBadAllocationException endp

; [00000039 BYTES: COLLAPSED FUNCTION __scrt_acquire_startup_lock. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400060AD:                         ; DATA XREF: .pdata:000000014000B600↓o
                align 10h
; [00000049 BYTES: COLLAPSED FUNCTION __scrt_initialize_crt. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400060F9:                         ; DATA XREF: .pdata:000000014000B60C↓o
                align 4
; [0000008B BYTES: COLLAPSED FUNCTION __scrt_initialize_onexit_tables. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140006187:                         ; DATA XREF: .pdata:000000014000B618↓o
                align 8
; [00000098 BYTES: COLLAPSED FUNCTION __scrt_is_nonwritable_in_current_image. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000024 BYTES: COLLAPSED FUNCTION __scrt_release_startup_lock. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000029 BYTES: COLLAPSED FUNCTION __scrt_uninitialize_crt. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_14000626D:                         ; DATA XREF: .pdata:000000014000B63C↓o
                align 10h
; [0000003A BYTES: COLLAPSED FUNCTION _onexit. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400062AA:                         ; DATA XREF: .pdata:000000014000B648↓o
                align 4
; [00000017 BYTES: COLLAPSED FUNCTION atexit. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400062C3:                         ; DATA XREF: .pdata:000000014000B654↓o
                align 4
; [000000AC BYTES: COLLAPSED FUNCTION __security_init_cookie. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION charNode::raw_length(void). PRESS CTRL-NUMPAD+ TO EXPAND]
                align 8
; [00000006 BYTES: COLLAPSED FUNCTION _get_startup_file_mode. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h

; =============== S U B R O U T I N E =======================================


; void sub_140006380()
sub_140006380   proc near               ; CODE XREF: pre_c_initialization(void)+59↑p
                lea     rcx, stru_14000A890
                jmp     cs:InitializeSListHead
sub_140006380   endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================


; char sub_140006390()
sub_140006390   proc near               ; CODE XREF: pre_c_initialization(void)+89↑p
                                        ; __scrt_initialize_crt+22↑p ...
                mov     al, 1
                retn
sub_140006390   endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================


_guard_check_icall_nop proc near        ; CODE XREF: pre_c_initialization(void):loc_140005C3B↑p
                                        ; pre_c_initialization(void)+78↑p
                                        ; DATA XREF: ...
                retn    0
_guard_check_icall_nop endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================


; void *sub_140006398()
sub_140006398   proc near               ; CODE XREF: __scrt_initialize_default_local_stdio_options+D↓p
                lea     rax, unk_14000A8A0
                retn
sub_140006398   endp

; [0000001B BYTES: COLLAPSED FUNCTION __scrt_initialize_default_local_stdio_options. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400063BB:                         ; DATA XREF: .pdata:000000014000B66C↓o
                align 4
; [0000000C BYTES: COLLAPSED FUNCTION __scrt_is_user_matherr_present. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; void *sub_1400063C8()
sub_1400063C8   proc near               ; CODE XREF: __scrt_common_main_seh(void)+9C↑p
                lea     rax, unk_14000A8C0
                retn
sub_1400063C8   endp


; =============== S U B R O U T I N E =======================================


; void *sub_1400063D0()
sub_1400063D0   proc near               ; CODE XREF: __scrt_common_main_seh(void):loc_140005D74↑p
                lea     rax, unk_14000A8B8
                retn
sub_1400063D0   endp


; =============== S U B R O U T I N E =======================================


; void sub_1400063D8()
sub_1400063D8   proc near               ; CODE XREF: __scrt_fastfail+2F↓p
                                        ; __scrt_fastfail+135↓p
                and     cs:dword_14000A8A8, 0
                retn
sub_1400063D8   endp

; [0000014B BYTES: COLLAPSED FUNCTION __scrt_fastfail. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_14000652B:                         ; DATA XREF: .pdata:000000014000B678↓o
                align 4
; [00000005 BYTES: COLLAPSED FUNCTION j_UserMathErrorFunction. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 4
; [00000051 BYTES: COLLAPSED FUNCTION __scrt_is_managed_app. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140006585:                         ; DATA XREF: .pdata:000000014000B684↓o
                align 8
; [0000000E BYTES: COLLAPSED FUNCTION __scrt_set_unhandled_exception_filter. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 8
; [0000005B BYTES: COLLAPSED FUNCTION __scrt_unhandled_exception_filter. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400065F3:                         ; DATA XREF: .pdata:000000014000B690↓o
                align 4

; =============== S U B R O U T I N E =======================================


; void sub_1400065F4()
sub_1400065F4   proc near               ; CODE XREF: pre_c_initialization(void)+38↑p
                                        ; DATA XREF: .pdata:000000014000B69C↓o

arg_0           = qword ptr  8

                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                lea     rbx, qword_140008380
                lea     rdi, qword_140008380
                jmp     short loc_140006620
; ---------------------------------------------------------------------------

loc_14000660E:                          ; CODE XREF: sub_1400065F4+2F↓j
                mov     rax, [rbx]
                test    rax, rax
                jz      short loc_14000661C
                call    cs:__guard_dispatch_icall_fptr

loc_14000661C:                          ; CODE XREF: sub_1400065F4+20↑j
                add     rbx, 8

loc_140006620:                          ; CODE XREF: sub_1400065F4+18↑j
                cmp     rbx, rdi
                jb      short loc_14000660E
                mov     rbx, [rsp+28h+arg_0]
                add     rsp, 20h
                pop     rdi
                retn
sub_1400065F4   endp


; =============== S U B R O U T I N E =======================================


; void __fastcall sub_140006630()
sub_140006630   proc near               ; DATA XREF: pre_c_initialization(void)+3D↑o
                                        ; .pdata:000000014000B69C↓o ...

arg_0           = qword ptr  8

                mov     [rsp+arg_0], rbx
                push    rdi
                sub     rsp, 20h
                lea     rbx, qword_140008390
                lea     rdi, qword_140008390
                jmp     short loc_14000665C
; ---------------------------------------------------------------------------

loc_14000664A:                          ; CODE XREF: sub_140006630+2F↓j
                mov     rax, [rbx]
                test    rax, rax
                jz      short loc_140006658
                call    cs:__guard_dispatch_icall_fptr

loc_140006658:                          ; CODE XREF: sub_140006630+20↑j
                add     rbx, 8

loc_14000665C:                          ; CODE XREF: sub_140006630+18↑j
                cmp     rbx, rdi
                jb      short loc_14000664A
                mov     rbx, [rsp+28h+arg_0]
                add     rsp, 20h
                pop     rdi
                retn
sub_140006630   endp

; [000001AC BYTES: COLLAPSED FUNCTION __isa_available_init. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000C BYTES: COLLAPSED FUNCTION __scrt_is_ucrt_dll_in_use. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000006 BYTES: COLLAPSED FUNCTION __CxxFrameHandler4. PRESS CTRL-NUMPAD+ TO EXPAND]
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR ConvertAndCopyWideToNarrow
;   ADDITIONAL PARENT FUNCTION HandleExceptionAndCopyData
;   ADDITIONAL PARENT FUNCTION ProcessAndCopyData_0
;   ADDITIONAL PARENT FUNCTION sub_1400016E0
;   ADDITIONAL PARENT FUNCTION sub_1400017B0
;   ADDITIONAL PARENT FUNCTION ExtendAndCopyString_1
;   ADDITIONAL PARENT FUNCTION CreatePathFromSegments
;   ADDITIONAL PARENT FUNCTION HandleAndCopyExceptionData
;   ADDITIONAL PARENT FUNCTION HandleAndPrepareException
;   ADDITIONAL PARENT FUNCTION sub_140002510
;   ADDITIONAL PARENT FUNCTION OpenAndIterateDirectory
;   ADDITIONAL PARENT FUNCTION ProcessAndUpdateData
;   ADDITIONAL PARENT FUNCTION ProcessAndUpdate
;   ADDITIONAL PARENT FUNCTION main
;   ADDITIONAL PARENT FUNCTION InitializeAndCopyByteArray
;   ADDITIONAL PARENT FUNCTION sub_1400042E0

__std_terminate:                        ; DATA XREF: .rdata:0000000140008407↓o
                                        ; .rdata:0000000140008437↓o ...
;   cleanup() // owned by 1400025D4
;   cleanup() // owned by 140002609
;   cleanup() // owned by 1400026C8
;   cleanup() // owned by 140003AA2
;   cleanup() // owned by 140003B0B
;   cleanup() // owned by 140003BDD
;   cleanup() // owned by 140003C1F
;   cleanup() // owned by 140003D66
                jmp     cs:__imp___std_terminate
; END OF FUNCTION CHUNK FOR ConvertAndCopyWideToNarrow
; [00000006 BYTES: COLLAPSED FUNCTION __C_specific_handler. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _CxxThrowException. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __current_exception. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __current_exception_context. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memset. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION terminate. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION free. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION malloc. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _callnewh. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _seh_filter_exe. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _set_app_type. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __setusermatherr. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _configure_wide_argv. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initialize_wide_environment. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _get_initial_wide_environment. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initterm. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initterm_e. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION exit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _exit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _set_fmode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __p___argc. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __p___wargv. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _cexit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _c_exit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _register_thread_local_exe_atexit_callback. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _configthreadlocale. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _set_new_mode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __p__commode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initialize_onexit_table. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _register_onexit_function. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _crt_atexit. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 8
; [0000007F BYTES: COLLAPSED FUNCTION __GSHandlerCheck_EH4. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memcpy. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memmove. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION strcmp. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h
; [00000002 BYTES: COLLAPSED FUNCTION _guard_dispatch_icall_nop. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400069A2:                         ; DATA XREF: .pdata:000000014000B6CC↓o
                align 20h
; [00000006 BYTES: COLLAPSED FUNCTION _guard_xfg_dispatch_icall_nop. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_1400069C6:                         ; DATA XREF: .pdata:000000014000B6D8↓o
                align 10h

; =============== S U B R O U T I N E =======================================


; void __fastcall sub_1400069D0(__int64, __int64)
sub_1400069D0   proc near
                mov     rcx, [rdx+20h]
                jmp     sub_140003F70
sub_1400069D0   endp


; =============== S U B R O U T I N E =======================================


; void __fastcall sub_1400069DC(__int64, __int64)
sub_1400069DC   proc near
                lea     rcx, [rdx+70h]
                jmp     sub_140003F70
sub_1400069DC   endp

; ---------------------------------------------------------------------------
                align 10h
; [0000000C BYTES: COLLAPSED FUNCTION int `__acrt_get_current_directory<__crt_win32_buffer_internal_dynamic_resizing>(__crt_win32_buffer<char,__crt_win32_buffer_internal_dynamic_resizing> &)'::`1'::dtor$0. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006A00(__int64, __int64)
sub_140006A00   proc near
                lea     rcx, [rdx+28h]
                jmp     sub_1400016C0
sub_140006A00   endp

; ---------------------------------------------------------------------------
                align 10h
; START OF FUNCTION CHUNK FOR ExtendAndCopyString_1

loc_140006A10:                          ; DATA XREF: .rdata:00000001400084EF↓o
                                        ; .pdata:000000014000B6E4↓o
                push    rbp
                sub     rsp, 20h
                mov     rbp, rdx
                mov     eax, [rbp+30h]
                and     eax, 1
                test    eax, eax
                jz      short loc_140006A30
                and     dword ptr [rbp+30h], 0FFFFFFFEh
                mov     rcx, [rbp+38h]
                call    unknown_libname_1 ; Microsoft VisualC v14 64bit runtime

loc_140006A30:                          ; CODE XREF: ExtendAndCopyString_1+50D1↑j
                add     rsp, 20h
                pop     rbp
                retn
; END OF FUNCTION CHUNK FOR ExtendAndCopyString_1
; ---------------------------------------------------------------------------
algn_140006A36:                         ; DATA XREF: .pdata:000000014000B6E4↓o
                align 20h
                mov     rcx, [rdx+20h]
                jmp     loc_140001120
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR HandleAndCopyExceptionData

loc_140006A4C:                          ; DATA XREF: .rdata:0000000140008612↓o
                mov     rcx, [rdx+20h]
                add     rcx, 28h ; '('
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
; ---------------------------------------------------------------------------

loc_140006A5C:                          ; DATA XREF: .rdata:000000014000861C↓o
                mov     rcx, [rdx+20h]
                add     rcx, 48h ; 'H'
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
; END OF FUNCTION CHUNK FOR HandleAndCopyExceptionData
; ---------------------------------------------------------------------------
                align 10h
                mov     rcx, [rdx+50h]
                jmp     loc_140001120
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR HandleAndPrepareException

; int `public: std::_Locinfo::_Locinfo(char const *)'::`1'::dtor$3
?dtor$3@?0???0_Locinfo@std@@QEAA@PEBD@Z@4HA:
                                        ; DATA XREF: .rdata:0000000140008651↓o
                mov     rcx, [rdx+50h]
                add     rcx, 28h ; '('
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
; ---------------------------------------------------------------------------

; int `public: std::_Locinfo::_Locinfo(char const *)'::`1'::dtor$5
?dtor$5@?0???0_Locinfo@std@@QEAA@PEBD@Z@4HA:
                                        ; DATA XREF: .rdata:000000014000865B↓o
                mov     rcx, [rdx+50h]
                add     rcx, 48h ; 'H'
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
; END OF FUNCTION CHUNK FOR HandleAndPrepareException

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006A9C(__int64, __int64)
sub_140006A9C   proc near
                lea     rcx, [rdx+30h]
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
sub_140006A9C   endp

; ---------------------------------------------------------------------------
                align 10h
; START OF FUNCTION CHUNK FOR sub_140002510

loc_140006AB0:                          ; DATA XREF: .rdata:00000001400086A7↓o
                                        ; .pdata:000000014000B6F0↓o
                push    rbp
                sub     rsp, 20h
                mov     rbp, rdx
                mov     eax, [rbp+57h+var_27]
                and     eax, 1
                test    eax, eax
                jz      short loc_140006AD0
                and     [rbp+57h+var_27], 0FFFFFFFEh
                mov     rcx, [rbp+57h+var_1F]
                call    sub_140003F70

loc_140006AD0:                          ; CODE XREF: sub_140002510+45B1↑j
                add     rsp, 20h
                pop     rbp
                retn
; END OF FUNCTION CHUNK FOR sub_140002510
; [0000000C BYTES: COLLAPSED FUNCTION unknown_libname_2. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000C BYTES: COLLAPSED FUNCTION unknown_libname_3. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

; =============== S U B R O U T I N E =======================================


; void __fastcall sub_140006AF0(__int64, __int64)
sub_140006AF0   proc near
                lea     rcx, [rdx+40h]
                jmp     sub_140003F70
sub_140006AF0   endp

; ---------------------------------------------------------------------------
                align 20h
                mov     rcx, [rdx+30h]
                jmp     loc_140001120
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_140002A60

loc_140006B0C:                          ; DATA XREF: .rdata:0000000140008735↓o
                mov     rcx, [rdx+30h]
                add     rcx, 28h ; '('
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
; ---------------------------------------------------------------------------

; int `public: std::_Locinfo::_Locinfo(char const *)'::`1'::dtor$5
?dtor$5@?0???0_Locinfo@std@@QEAA@PEBD@Z@4HA_0:
                                        ; DATA XREF: .rdata:000000014000873A↓o
                mov     rcx, [rdx+30h]
                add     rcx, 48h ; 'H'
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
; END OF FUNCTION CHUNK FOR sub_140002A60
; ---------------------------------------------------------------------------
                align 10h
; [0000000C BYTES: COLLAPSED FUNCTION int `__acrt_get_current_directory<__crt_win32_buffer_internal_dynamic_resizing>(__crt_win32_buffer<char,__crt_win32_buffer_internal_dynamic_resizing> &)'::`1'::dtor$0. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006B40(__int64, __int64)
sub_140006B40   proc near
                mov     rcx, [rdx+20h]
                jmp     sub_140003040
sub_140006B40   endp

; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR ProcessAndUpdate

loc_140006B4C:                          ; DATA XREF: .rdata:0000000140008806↓o
                mov     rcx, [rdx+20h]
                add     rcx, 40h ; '@'
                jmp     sub_140001BB0
; END OF FUNCTION CHUNK FOR ProcessAndUpdate
; ---------------------------------------------------------------------------
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006B60(__int64, __int64)
sub_140006B60   proc near
                lea     rcx, [rdx+0E0h]
                jmp     sub_1400030B0
sub_140006B60   endp


; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006B6C(__int64, __int64)
sub_140006B6C   proc near
                lea     rcx, [rdx+0E0h]
                jmp     sub_1400030B0
sub_140006B6C   endp


; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006B78(__int64, __int64)
sub_140006B78   proc near
                lea     rcx, [rdx+0D0h]
                jmp     sub_1400030B0
sub_140006B78   endp

; [0000000C BYTES: COLLAPSED FUNCTION int `std::money_put<char,std::ostreambuf_iterator<char,std::char_traits<char>>>::_Putmfld(money_put<char,std::ostreambuf_iterator<char,std::char_traits<char>>>::std,bool,money_put<char,std::ostreambuf_iterator<char,std::char_traits<char>>>::ios_base &,char,bool,money_put<char,std::ostreambuf_iterator<char,std::char_traits<char>>>::basic_string<char,std::char_traits<char>,std::allocator<char>>,char)'::`1'::dtor$7. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006B90(__int64, __int64)
sub_140006B90   proc near
                lea     rcx, [rdx+0F0h]
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
sub_140006B90   endp


; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006B9C(__int64, __int64)
sub_140006B9C   proc near
                lea     rcx, [rdx+38h]
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
sub_140006B9C   endp

; ---------------------------------------------------------------------------
                align 10h
; [0000000C BYTES: COLLAPSED FUNCTION int `__acrt_get_current_directory<__crt_win32_buffer_internal_dynamic_resizing>(__crt_win32_buffer<char,__crt_win32_buffer_internal_dynamic_resizing> &)'::`1'::dtor$0. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006BBC(__int64, __int64)
sub_140006BBC   proc near
                lea     rcx, [rdx+0A8h]
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
sub_140006BBC   endp


; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006BC8(__int64, __int64)
sub_140006BC8   proc near
                lea     rcx, [rdx+88h]
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
sub_140006BC8   endp

; [0000000C BYTES: COLLAPSED FUNCTION int `__acrt_get_current_directory<__crt_win32_buffer_internal_dynamic_resizing>(__crt_win32_buffer<char,__crt_win32_buffer_internal_dynamic_resizing> &)'::`1'::dtor$0. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006BE0(__int64, __int64)
sub_140006BE0   proc near
                lea     rcx, [rdx+68h]
                jmp     sub_140003F70
sub_140006BE0   endp

; ---------------------------------------------------------------------------
                align 10h
; START OF FUNCTION CHUNK FOR ConvertAndCopyWideToNarrow
;   ADDITIONAL PARENT FUNCTION sub_1400042E0

loc_140006BF0:                          ; DATA XREF: .rdata:0000000140008A47↓o
                                        ; .pdata:000000014000B6FC↓o
                push    rbp
                sub     rsp, 20h
                mov     rbp, rdx
                mov     eax, [rbp+30h]
                and     eax, 1
                test    eax, eax
                jz      short loc_140006C10
                and     dword ptr [rbp+30h], 0FFFFFFFEh
                mov     rcx, [rbp+38h]
                call    sub_140003F70

loc_140006C10:                          ; CODE XREF: ConvertAndCopyWideToNarrow+18C1↑j
                add     rsp, 20h
                pop     rbp
                retn
; END OF FUNCTION CHUNK FOR ConvertAndCopyWideToNarrow
; ---------------------------------------------------------------------------
algn_140006C16:                         ; DATA XREF: .pdata:000000014000B6FC↓o
                align 20h

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall sub_140006C20(__int64, __int64)
sub_140006C20   proc near
                lea     rcx, [rdx+30h]
                jmp     unknown_libname_1 ; Microsoft VisualC v14 64bit runtime
sub_140006C20   endp

; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR ProcessFiles

loc_140006C2C:                          ; DATA XREF: .rdata:0000000140008A85↓o
;   cleanup() // owned by 1400044A7
;   cleanup() // owned by 1400044DE
                lea     rcx, [rdx+30h]
                add     rcx, 20h ; ' '
                jmp     sub_140001BB0
; END OF FUNCTION CHUNK FOR ProcessFiles

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall ResetFileHandleWrapper(__int64, __int64)
ResetFileHandleWrapper proc near
                lea     rcx, [rdx+30h]
                jmp     ResetFileHandleData
ResetFileHandleWrapper endp

; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR ProcessFiles

unknown_libname_4:                      ; DATA XREF: .rdata:0000000140008A90↓o
                                        ; .pdata:000000014000B708↓o
                push    rbp             ; Microsoft VisualC v14 64bit runtime
                sub     rsp, 20h
                mov     rbp, rdx
                mov     edx, 58h ; 'X'
                mov     rcx, [rbp+20h]  ; Block
                call    j_j_free
                add     rsp, 20h
                pop     rbp
                retn
; END OF FUNCTION CHUNK FOR ProcessFiles
; ---------------------------------------------------------------------------
; [0000001E BYTES: COLLAPSED CHUNK OF FUNCTION __scrt_common_main_seh(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; ---------------------------------------------------------------------------
; [00000018 BYTES: COLLAPSED CHUNK OF FUNCTION __scrt_is_nonwritable_in_current_image. PRESS CTRL-NUMPAD+ TO EXPAND]
algn_140006C9B:                         ; DATA XREF: .pdata:000000014000B720↓o
                align 200h
                dq 40h dup(?)
_text           ends

; Section 2. (virtual address 00007000)
; Virtual size                  : 00002CF8 (  11512.)
; Section size in file          : 00002E00 (  11776.)
; Offset to raw data for section: 00006200
; Flags 40000040: Data Readable
; Alignment     : default
;
; Imports from ADVAPI32.dll
;
; ===========================================================================

; Segment type: Externs
; _idata
; DWORD (__stdcall *SetNamedSecurityInfoW)(LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
                extrn SetNamedSecurityInfoW:qword
                                        ; CODE XREF: PerformRemoteExecution+125↑p
                                        ; DATA XREF: PerformRemoteExecution+125↑r ...
; DWORD (__stdcall *GetNamedSecurityInfoW)(LPCWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *ppSecurityDescriptor)
                extrn GetNamedSecurityInfoW:qword
                                        ; CODE XREF: PerformRemoteExecution+82↑p
                                        ; DATA XREF: PerformRemoteExecution+82↑r
; BOOL (__stdcall *ConvertStringSidToSidW)(LPCWSTR StringSid, PSID *Sid)
                extrn ConvertStringSidToSidW:qword
                                        ; CODE XREF: PerformRemoteExecution+9C↑p
                                        ; DATA XREF: PerformRemoteExecution+9C↑r
; DWORD (__stdcall *SetEntriesInAclW)(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_W pListOfExplicitEntries, PACL OldAcl, PACL *NewAcl)
                extrn SetEntriesInAclW:qword
                                        ; CODE XREF: PerformRemoteExecution+FA↑p
                                        ; DATA XREF: PerformRemoteExecution+FA↑r

;
; Imports from KERNEL32.dll
;
; BOOL (__stdcall *Process32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
                extrn Process32Next:qword ; CODE XREF: main+5A↑p
                                        ; main+8B↑p
                                        ; DATA XREF: ...
; BOOL (__stdcall *CloseHandle)(HANDLE hObject)
                extrn CloseHandle:qword ; CODE XREF: IsModuleInProcess+B1↑p
                                        ; main+98↑p ...
; HMODULE (__stdcall *LoadLibraryW)(LPCWSTR lpLibFileName)
                extrn LoadLibraryW:qword
                                        ; DATA XREF: PerformRemoteExecution+1BE↑r
; HANDLE (__stdcall *CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID)
                extrn CreateToolhelp32Snapshot:qword
                                        ; CODE XREF: IsModuleInProcess+31↑p
                                        ; main+40↑p
                                        ; DATA XREF: ...
; HLOCAL (__stdcall *LocalFree)(HLOCAL hMem)
                extrn __imp_LocalFree:qword
                                        ; CODE XREF: PerformRemoteExecution+13F↑p
                                        ; PerformRemoteExecution+14F↑p ...
; HANDLE (__stdcall *CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
                extrn CreateRemoteThread:qword
                                        ; CODE XREF: PerformRemoteExecution+1DB↑p
                                        ; DATA XREF: PerformRemoteExecution+1DB↑r
; BOOL (__stdcall *VirtualFreeEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
                extrn VirtualFreeEx:qword
                                        ; CODE XREF: PerformRemoteExecution+203↑p
                                        ; DATA XREF: PerformRemoteExecution+203↑r
; HANDLE (__stdcall *OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
                extrn OpenProcess:qword ; CODE XREF: main+D0↑p
                                        ; DATA XREF: main+D0↑r
; DWORD (__stdcall *WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds)
                extrn WaitForSingleObject:qword
                                        ; CODE XREF: PerformRemoteExecution+1EE↑p
                                        ; DATA XREF: PerformRemoteExecution+1EE↑r
; BOOL (__stdcall *Module32Next)(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
                extrn Module32Next:qword
                                        ; CODE XREF: IsModuleInProcess+5C↑p
                                        ; IsModuleInProcess+9F↑p
                                        ; DATA XREF: ...
; LPVOID (__stdcall *VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
                extrn VirtualAllocEx:qword
                                        ; CODE XREF: PerformRemoteExecution+18B↑p
                                        ; DATA XREF: PerformRemoteExecution+18B↑r
; BOOL (__stdcall *WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
                extrn WriteProcessMemory:qword
                                        ; CODE XREF: PerformRemoteExecution+1B4↑p
                                        ; DATA XREF: PerformRemoteExecution+1B4↑r
; BOOL (__stdcall *GetFileAttributesExW)(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
                extrn GetFileAttributesExW:qword
                                        ; CODE XREF: __std_fs_get_stats+99↑p
                                        ; DATA XREF: __std_fs_get_stats+99↑r
; BOOL (__stdcall *FindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
                extrn FindNextFileW:qword
                                        ; CODE XREF: FindNextFileInfo+4↑p
                                        ; DATA XREF: FindNextFileInfo+4↑r
; HANDLE (__stdcall *FindFirstFileExW)(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
                extrn FindFirstFileExW:qword
                                        ; CODE XREF: __std_fs_directory_iterator_open+4A↑p
                                        ; __std_fs_directory_iterator_open+7F↑p
                                        ; DATA XREF: ...
; BOOL (__stdcall *FindClose)(HANDLE hFindFile)
                extrn FindClose:qword   ; CODE XREF: CloseFileHandleAndCheck+A↑p
                                        ; __std_fs_directory_iterator_open+21↑p
                                        ; DATA XREF: ...
; HANDLE (__stdcall *CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
                extrn CreateFileW:qword ; CODE XREF: __std_fs_open_handle+33↑p
                                        ; DATA XREF: __std_fs_open_handle+33↑r
; DWORD (__stdcall *FormatMessageA)(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments)
                extrn FormatMessageA:qword
                                        ; CODE XREF: __std_system_error_allocate_message+26↑p
                                        ; DATA XREF: __std_system_error_allocate_message+26↑r
; BOOL (__stdcall *AreFileApisANSI)()
                extrn AreFileApisANSI:qword
                                        ; CODE XREF: __std_fs_code_page+13↑p
                                        ; DATA XREF: __std_fs_code_page+13↑r
; DWORD (__stdcall *GetLastError)()
                extrn GetLastError:qword
                                        ; CODE XREF: __std_fs_convert_narrow_to_wide+2A↑p
                                        ; __std_fs_convert_wide_to_narrow+B3↑p ...
; BOOL (__stdcall *GetFileInformationByHandleEx)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize)
                extrn GetFileInformationByHandleEx:qword
                                        ; CODE XREF: __std_fs_get_stats+147↑p
                                        ; __std_fs_get_stats+1A1↑p ...
; HMODULE (__stdcall *GetModuleHandleW)(LPCWSTR lpModuleName)
                extrn GetModuleHandleW:qword
                                        ; CODE XREF: __scrt_is_managed_app+6↑p
                                        ; DATA XREF: __scrt_is_managed_app+6↑r
; int (__stdcall *MultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
                extrn MultiByteToWideChar:qword
                                        ; CODE XREF: __std_fs_convert_narrow_to_wide+1C↑p
                                        ; DATA XREF: __std_fs_convert_narrow_to_wide+1C↑r
; int (__stdcall *WideCharToMultiByte)(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
                extrn WideCharToMultiByte:qword
                                        ; CODE XREF: __std_fs_convert_wide_to_narrow+5B↑p
                                        ; __std_fs_convert_wide_to_narrow+A5↑p ...
; void (__stdcall *RtlCaptureContext)(PCONTEXT ContextRecord)
                extrn RtlCaptureContext:qword
                                        ; CODE XREF: capture_previous_context+B↑p
                                        ; __scrt_fastfail+49↑p
                                        ; DATA XREF: ...
; BOOL (__stdcall *IsDebuggerPresent)()
                extrn IsDebuggerPresent:qword
                                        ; CODE XREF: __scrt_fastfail+F8↑p
                                        ; DATA XREF: __scrt_fastfail+F8↑r
; void (__stdcall *InitializeSListHead)(PSLIST_HEADER ListHead)
                extrn InitializeSListHead:qword
                                        ; DATA XREF: sub_140006380+7↑r
; void (__stdcall *GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
                extrn GetSystemTimeAsFileTime:qword
                                        ; CODE XREF: __security_init_cookie+2C↑p
                                        ; DATA XREF: __security_init_cookie+2C↑r
; DWORD (__stdcall *GetCurrentThreadId)()
                extrn GetCurrentThreadId:qword
                                        ; CODE XREF: __security_init_cookie+3A↑p
                                        ; DATA XREF: __security_init_cookie+3A↑r
; DWORD (__stdcall *GetCurrentProcessId)()
                extrn GetCurrentProcessId:qword
                                        ; CODE XREF: __security_init_cookie+46↑p
                                        ; DATA XREF: __security_init_cookie+46↑r
; BOOL (__stdcall *QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount)
                extrn QueryPerformanceCounter:qword
                                        ; CODE XREF: __security_init_cookie+56↑p
                                        ; DATA XREF: __security_init_cookie+56↑r
; BOOL (__stdcall *IsProcessorFeaturePresent)(DWORD ProcessorFeature)
                extrn IsProcessorFeaturePresent:qword
                                        ; CODE XREF: __report_gsfailure+E↑p
                                        ; __scrt_fastfail+1C↑p
                                        ; DATA XREF: ...
; BOOL (__stdcall *TerminateProcess)(HANDLE hProcess, UINT uExitCode)
                extrn TerminateProcess:qword
                                        ; DATA XREF: __raise_securityfailure+2D↑r
; HANDLE (__stdcall *GetCurrentProcess)()
                extrn GetCurrentProcess:qword
                                        ; CODE XREF: __raise_securityfailure+1A↑p
                                        ; DATA XREF: __raise_securityfailure+1A↑r
; LPTOP_LEVEL_EXCEPTION_FILTER (__stdcall *SetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
                extrn SetUnhandledExceptionFilter:qword
                                        ; CODE XREF: __raise_securityfailure+B↑p
                                        ; __scrt_fastfail+119↑p
                                        ; DATA XREF: ...
; LONG (__stdcall *UnhandledExceptionFilter)(struct _EXCEPTION_POINTERS *ExceptionInfo)
                extrn UnhandledExceptionFilter:qword
                                        ; CODE XREF: __raise_securityfailure+14↑p
                                        ; __scrt_fastfail+124↑p
                                        ; DATA XREF: ...
; PEXCEPTION_ROUTINE (__stdcall *RtlVirtualUnwind)(ULONG HandlerType, ULONG64 ImageBase, ULONG64 ControlPc, PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord, PVOID *HandlerData, PULONG64 EstablisherFrame, PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
                extrn RtlVirtualUnwind:qword
                                        ; CODE XREF: capture_previous_context+5C↑p
                                        ; __scrt_fastfail+A4↑p
                                        ; DATA XREF: ...
; PRUNTIME_FUNCTION (__stdcall *RtlLookupFunctionEntry)(ULONG64 ControlPc, PULONG64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable)
                extrn RtlLookupFunctionEntry:qword
                                        ; CODE XREF: capture_previous_context+25↑p
                                        ; __scrt_fastfail+63↑p
                                        ; DATA XREF: ...

;
; Imports from MSVCP140.dll
;
; int std::_Winerror_map(int)
                extrn ?_Winerror_map@std@@YAHH@Z:qword
                                        ; CODE XREF: sub_140001860+33↑p
                                        ; DATA XREF: sub_140001860+33↑r ...
; void std::_Xout_of_range(char const *)
                extrn ?_Xout_of_range@std@@YAXPEBD@Z:qword
                                        ; CODE XREF: HandleInvalidStringPosition+B↑p
                                        ; DATA XREF: HandleInvalidStringPosition+B↑r
; void std::_Xlength_error(char const *)
                extrn ?_Xlength_error@std@@YAXPEBD@Z:qword
                                        ; CODE XREF: ThrowStringLengthExceededException+B↑p
                                        ; DATA XREF: ThrowStringLengthExceededException+B↑r
; char const * std::_Syserror_map(int)
                extrn ?_Syserror_map@std@@YAPEBDH@Z:qword
                                        ; CODE XREF: sub_1400016E0+3B↑p
                                        ; DATA XREF: sub_1400016E0+3B↑r

;
; Imports from VCRUNTIME140.dll
;
; void *(__cdecl *memset)(void *, int Val, size_t Size)
                extrn __imp_memset:qword ; DATA XREF: memset↑r
                                        ; .rdata:0000000140009134↓o
; void (__stdcall __noreturn *_CxxThrowException)(void *pExceptionObject, _ThrowInfo *pThrowInfo)
                extrn __imp__CxxThrowException:qword
                                        ; DATA XREF: _CxxThrowException↑r
; EXCEPTION_DISPOSITION (__cdecl *__C_specific_handler)(struct _EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, struct _CONTEXT *ContextRecord, struct _DISPATCHER_CONTEXT *DispatcherContext)
                extrn __imp___C_specific_handler:qword
                                        ; DATA XREF: __C_specific_handler↑r
; void *(__cdecl *memmove)(void *, const void *Src, size_t Size)
                extrn __imp_memmove:qword ; DATA XREF: memmove↑r
; __int64 __fastcall _std_exception_copy(_QWORD)
                extrn __std_exception_copy:qword
                                        ; CODE XREF: sub_140001070+24↑p
                                        ; sub_140001190+24↑p ...
                extrn __std_exception_destroy:qword
                                        ; CODE XREF: sub_1400010D0+1D↑p
                                        ; sub_1400014C0+1D↑p ...
; void *(__cdecl *memcpy)(void *, const void *Src, size_t Size)
                extrn __imp_memcpy:qword ; DATA XREF: memcpy↑r
                extrn __imp___current_exception:qword
                                        ; DATA XREF: __current_exception↑r
                extrn __imp___current_exception_context:qword
                                        ; DATA XREF: __current_exception_context↑r
                extrn __imp___std_terminate:qword
                                        ; DATA XREF: ConvertAndCopyWideToNarrow:__std_terminate↑r

;
; Imports from VCRUNTIME140_1.dll
;
                extrn __imp___CxxFrameHandler4:qword
                                        ; DATA XREF: __CxxFrameHandler4↑r
                                        ; .rdata:0000000140009120↓o

;
; Imports from api-ms-win-crt-heap-l1-1-0.dll
;
; int (__cdecl *_set_new_mode)(int NewMode)
                extrn __imp__set_new_mode:qword
                                        ; DATA XREF: _set_new_mode↑r
                                        ; .rdata:0000000140009148↓o
; void (__cdecl *free)(void *Block)
                extrn __imp_free:qword  ; DATA XREF: free↑r
; int (__cdecl *_callnewh)(size_t Size)
                extrn __imp__callnewh:qword
                                        ; DATA XREF: _callnewh↑r
; void *(__cdecl *malloc)(size_t Size)
                extrn __imp_malloc:qword ; DATA XREF: malloc↑r

;
; Imports from api-ms-win-crt-locale-l1-1-0.dll
;
; unsigned int (__cdecl *__lc_codepage_func)()
                extrn ___lc_codepage_func:qword
                                        ; CODE XREF: __std_fs_code_page+4↑p
                                        ; DATA XREF: __std_fs_code_page+4↑r ...
; int (__cdecl *_configthreadlocale)(int Flag)
                extrn __imp__configthreadlocale:qword
                                        ; DATA XREF: _configthreadlocale↑r

;
; Imports from api-ms-win-crt-math-l1-1-0.dll
;
; void (__cdecl *__setusermatherr)(_UserMathErrorFunctionPointer UserMathErrorFunction)
                extrn __imp___setusermatherr:qword
                                        ; DATA XREF: __setusermatherr↑r
                                        ; .rdata:0000000140009198↓o

;
; Imports from api-ms-win-crt-runtime-l1-1-0.dll
;
; __int64 terminate(void)
                extrn __imp_terminate:qword
                                        ; CODE XREF: CloseFileHandleAndCheck+14↑p
                                        ; __std_fs_directory_iterator_open+2B↑p ...
; int (__cdecl *_crt_atexit)(_PVFV Function)
                extrn __imp__crt_atexit:qword
                                        ; DATA XREF: _crt_atexit↑r
; int (__cdecl *_register_onexit_function)(_onexit_table_t *Table, _onexit_t Function)
                extrn __imp__register_onexit_function:qword
                                        ; DATA XREF: _register_onexit_function↑r
; int (__cdecl *_initialize_onexit_table)(_onexit_table_t *Table)
                extrn __imp__initialize_onexit_table:qword
                                        ; DATA XREF: _initialize_onexit_table↑r
; int (__cdecl *_seh_filter_exe)(unsigned int ExceptionNum, struct _EXCEPTION_POINTERS *ExceptionPtr)
                extrn __imp__seh_filter_exe:qword
                                        ; DATA XREF: _seh_filter_exe↑r
; void (__cdecl __noreturn *invalid_parameter_noinfo_noreturn)()
                extrn _invalid_parameter_noinfo_noreturn:qword
                                        ; CODE XREF: HandleExceptionAndCopyData+C1↑p
                                        ; HandleExceptionAndCopyData+182↑p ...
; void (__cdecl *_c_exit)()
                extrn __imp__c_exit:qword ; DATA XREF: _c_exit↑r
; void (__cdecl *_cexit)()
                extrn __imp__cexit:qword ; DATA XREF: _cexit↑r
; wchar_t ***(__cdecl *__p___wargv)()
                extrn __imp___p___wargv:qword
                                        ; DATA XREF: __p___wargv↑r
; int *(__cdecl *__p___argc)()
                extrn __imp___p___argc:qword
                                        ; DATA XREF: __p___argc↑r
; void (__cdecl *_set_app_type)(_crt_app_type Type)
                extrn __imp__set_app_type:qword
                                        ; DATA XREF: _set_app_type↑r
; void (__cdecl __noreturn *_exit)(int Code)
                extrn __imp__exit:qword ; DATA XREF: _exit↑r
; void (__cdecl __noreturn *exit)(int Code)
                extrn __imp_exit:qword  ; DATA XREF: exit↑r
; int (__cdecl *_initterm_e)(_PIFV *First, _PIFV *Last)
                extrn __imp__initterm_e:qword
                                        ; DATA XREF: _initterm_e↑r
; void (__cdecl *_initterm)(_PVFV *First, _PVFV *Last)
                extrn __imp__initterm:qword
                                        ; DATA XREF: _initterm↑r
; wchar_t **(__cdecl *_get_initial_wide_environment)()
                extrn __imp__get_initial_wide_environment:qword
                                        ; DATA XREF: _get_initial_wide_environment↑r
; int (__cdecl *_initialize_wide_environment)()
                extrn __imp__initialize_wide_environment:qword
                                        ; DATA XREF: _initialize_wide_environment↑r
; errno_t (__cdecl *_configure_wide_argv)(_crt_argv_mode mode)
                extrn __imp__configure_wide_argv:qword
                                        ; DATA XREF: _configure_wide_argv↑r
; void (__cdecl *_register_thread_local_exe_atexit_callback)(_tls_callback_type Callback)
                extrn __imp__register_thread_local_exe_atexit_callback:qword
                                        ; DATA XREF: _register_thread_local_exe_atexit_callback↑r

;
; Imports from api-ms-win-crt-stdio-l1-1-0.dll
;
; FILE *(__cdecl *_acrt_iob_func)(unsigned int Ix)
                extrn __acrt_iob_func:qword
                                        ; CODE XREF: PrintFormattedOutputToStdout+24↑p
                                        ; DATA XREF: PrintFormattedOutputToStdout+24↑r ...
; int *(__cdecl *__p__commode)()
                extrn __imp___p__commode:qword
                                        ; DATA XREF: __p__commode↑r
; int (__cdecl *_stdio_common_vfprintf)(unsigned __int64 Options, FILE *Stream, const char *Format, _locale_t Locale, va_list ArgList)
                extrn __stdio_common_vfprintf:qword
                                        ; CODE XREF: PrintFormattedOutputToStdout+45↑p
                                        ; DATA XREF: PrintFormattedOutputToStdout+45↑r
; errno_t (__cdecl *_set_fmode)(int Mode)
                extrn __imp__set_fmode:qword
                                        ; DATA XREF: _set_fmode↑r

;
; Imports from api-ms-win-crt-string-l1-1-0.dll
;
; int (__cdecl *strcmp)(const char *Str1, const char *Str2)
                extrn __imp_strcmp:qword ; DATA XREF: strcmp↑r
                                        ; .rdata:00000001400091AC↓o


; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read
_rdata          segment para public 'DATA' use64
                assume cs:_rdata
                ;org 140007318h
__guard_check_icall_fptr dq offset _guard_check_icall_nop
                                        ; DATA XREF: .rdata:00000001400078D0↓o
__guard_xfg_check_icall_fptr dq offset _guard_check_icall_nop
                                        ; DATA XREF: .rdata:0000000140007978↓o
__guard_dispatch_icall_fptr dq offset _guard_dispatch_icall_nop
                                        ; DATA XREF: __scrt_common_main_seh(void)+C2↑r
                                        ; sub_1400065F4+22↑r ...
__guard_xfg_dispatch_icall_fptr dq offset _guard_xfg_dispatch_icall_nop
                                        ; DATA XREF: .rdata:0000000140007980↓o
__guard_xfg_table_dispatch_icall_fptr dq offset _guard_xfg_dispatch_icall_nop
                                        ; DATA XREF: .rdata:0000000140007988↓o
__castguard_check_failure_os_handled_fptr db    0
                                        ; DATA XREF: .rdata:0000000140007990↓o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
off_140007348   dq offset memcpy        ; DATA XREF: .rdata:0000000140007998↓o
; const _PVFV qword_140007350
qword_140007350 dq 0                    ; DATA XREF: __scrt_common_main_seh(void)+75↑o
                dq offset ?pre_cpp_initialization@@YAXXZ ; pre_cpp_initialization(void)
; const _PVFV qword_140007360
qword_140007360 dq 0                    ; DATA XREF: __scrt_common_main_seh(void):loc_140005D1A↑o
; const _PIFV First
First           dq 0                    ; DATA XREF: __scrt_common_main_seh(void)+54↑o
                dq offset ?pre_c_initialization@@YAHXZ ; pre_c_initialization(void)
                dq offset ?post_pgo_initialization@@YAHXZ ; post_pgo_initialization(void)
; const _PIFV Last
Last            dq 0                    ; DATA XREF: __scrt_common_main_seh(void)+4D↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_1400073B0   db    1                 ; DATA XREF: __std_system_error_allocate_message+3F↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    1
                db    1
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                dq offset unk_140007A00
off_1400074B8   dq offset sub_140005B9C ; DATA XREF: sub_140005B9C+6↑o
                                        ; .data:000000014000A058↓o ...
; const struct _EXCEPTION_POINTERS ExceptionInfo
ExceptionInfo   _EXCEPTION_POINTERS <offset dword_14000A2D0, offset ContextRecord>
                                        ; DATA XREF: __report_gsfailure+C1↑o
                dq offset unk_140007A78
off_1400074D8   dq offset sub_1400010D0 ; DATA XREF: sub_140001070+C↑o
                                        ; sub_1400010D0+A↑o ...
                dq offset sub_1400010B0
                dq offset unk_140007E30
off_1400074F0   dq offset sub_1400010D0 ; DATA XREF: sub_1400011D0+2A↑o
                                        ; CreateBadAllocationException+10↑o
                dq offset sub_1400010B0
aBadAllocation  db 'bad allocation',0   ; DATA XREF: CreateBadAllocationException+5↑o
                align 10h
                dq offset unk_140007F18
off_140007518   dq offset sub_1400010D0 ; DATA XREF: InitializeBadArrayLengthException+13↑o
                                        ; sub_140001190+2A↑o
                dq offset sub_1400010B0
                align 10h
xmmword_140007530 xmmword 0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFh
                                        ; DATA XREF: __scrt_initialize_onexit_tables:loc_140006143↑r
aUnknownExcepti db 'Unknown exception',0
                                        ; DATA XREF: sub_1400010B0+4↑o
                                        ; HandleAndCopyExceptionData+64↑o ...
                align 8
aBadArrayNewLen db 'bad array new length',0
                                        ; DATA XREF: InitializeBadArrayLengthException↑o
                align 10h
aStringTooLong  db 'string too long',0  ; DATA XREF: ThrowStringLengthExceededException+4↑o
asc_140007580   db ': ',0               ; DATA XREF: HandleExceptionAndCopyData+52↑o
staticData      db    0                 ; DATA XREF: ProcessAndCopyData_0+31↑o
                db    0
                db    0
                db    0
                db    0
aGeneric        db 'generic',0          ; DATA XREF: sub_1400016D0↑o
aSuccess        db 'success',0          ; DATA XREF: sub_1400016E0+2F↑o
aSystem         db 'system',0           ; DATA XREF: sub_1400017A0↑o
                align 20h
asc_1400075A0   db ': "',0              ; DATA XREF: sub_140002510+127↑o
asc_1400075A4   db '", "',0             ; DATA XREF: sub_140002510+15A↑o
                align 10h
aDirectoryEntry db 'directory_entry::status',0
                                        ; DATA XREF: ProcessDirectory+508↑o
word_1400075C8  dw 2Ah                  ; DATA XREF: OpenAndIterateDirectory+4C↑o
                                        ; OpenAndIterateDirectory+73↑r
                align 10h
aDirectoryItera_0 db 'directory_iterator::directory_iterator',0
                                        ; DATA XREF: ProcessDirectory+4F7↑o
                align 8
aDirectoryItera db 'directory_iterator::operator++',0
                                        ; DATA XREF: HandleAndThrowException+19↑o
                align 8
; const WCHAR StringSid
StringSid:                              ; DATA XREF: PerformRemoteExecution+95↑o
                text "UTF-16LE", 'S-1-15-2-1',0
                align 10h
; const char Str2[]
Str2            db 'SoTGame.exe',0      ; DATA XREF: main:loc_1400039B0↑o
                align 20h
aGameProcessNot db 'Game process not found',0Ah,0
                                        ; DATA XREF: main:loc_1400039F0↑o
aCanTGetProcess db 'Can',27h,'t get process handle',0Ah,0
                                        ; DATA XREF: main+E1↑o
                align 4
aDll            db '.dll',0             ; DATA XREF: ProcessDirectory:loc_1400032C0↑o
                align 20h
aCanTFindDynami db 'Can',27h,'t find dynamic library in the current folder',0Ah,0
                                        ; DATA XREF: main+1D4↑o
                align 8
aSHasBeenLoaded db '%s has been loaded to process already',0Ah,0
                                        ; DATA XREF: main+363↑o
                align 20h
aInjectionHasFa db 'Injection has failed or module has unloaded already',0Ah,0
                                        ; DATA XREF: main+404↑o
                align 8
aSuccessfullyIn db 'Successfully injected!',0Ah,0
                                        ; DATA XREF: main:loc_140003D57↑o
aInvalidStringP db 'invalid string position',0
                                        ; DATA XREF: HandleInvalidStringPosition+4↑o
                dq offset unk_140008020
off_140007750   dq offset sub_140002780 ; DATA XREF: HandleAndCopyExceptionData+25↑o
                                        ; HandleAndPrepareException+29↑o ...
                dq offset sub_140002500
                dq offset unk_140007C18
off_140007768   dq offset ??_G_Iostream_error_category2@std@@UEAAPEAXI@Z
                                        ; DATA XREF: .data:staticMemoryLocation↓o
                                        ; std::_Iostream_error_category2::`scalar deleting destructor'(uint)
                dq offset sub_1400016D0
                dq offset sub_1400016E0
                dq offset ?default_error_condition@error_category@std@@UEBA?AVerror_condition@2@H@Z ; std::error_category::default_error_condition(int)
                dq offset ?equivalent@error_category@std@@UEBA_NAEBVerror_code@2@H@Z ; std::error_category::equivalent(std::error_code const &,int)
                dq offset sub_140001280
aUnknownError   db 'unknown error',0    ; DATA XREF: sub_1400017B0+54↑o
                align 8
                dq offset unk_140007B78
off_1400077B0   dq offset sub_1400010D0 ; DATA XREF: sub_140001230+2A↑o
                                        ; HandleExceptionAndCopyData+146↑o
                dq offset sub_1400010B0
                dq offset unk_140007BC8
off_1400077C8   dq offset sub_1400014C0 ; DATA XREF: HandleExceptionAndCopyData:loc_14000148E↑o
                                        ; sub_140001610+2E↑o ...
                dq offset sub_1400010B0
                dq offset unk_140007AB8
off_1400077E0   dq offset sub_1400052A0 ; DATA XREF: ProcessFiles+A8↑o
                                        ; sub_140005310+6↑o
                dq offset sub_140005280
                dq offset sub_140005310
                dq offset UserMathErrorFunction
                dq offset unk_140007BA0
off_140007808   dq offset ??_G_Iostream_error_category2@std@@UEAAPEAXI@Z
                                        ; DATA XREF: .data:off_14000A048↓o
                                        ; std::_Iostream_error_category2::`scalar deleting destructor'(uint)
                dq offset sub_1400017A0
                dq offset sub_1400017B0
                dq offset sub_140001860
                dq offset ?equivalent@error_category@std@@UEBA_NAEBVerror_code@2@H@Z ; std::error_category::equivalent(std::error_code const &,int)
                dq offset sub_140001280
                dq offset unk_140007CC8
staticDataMarker dq offset sub_1400014C0
                                        ; DATA XREF: ProcessAndCopyData_0:loc_1400015AE↑o
                                        ; sub_140001610+38↑o
                dq offset sub_1400010B0
xmmword_140007850 xmmword 70000000000000000h
                                        ; DATA XREF: HandleAndPrepareException+6B↑r
                                        ; main+1B1↑r ...
_load_config_used dd 140h               ; Size
                dd 0                    ; Time stamp
                dw 2 dup(0)             ; Version: 0.0
                dd 0                    ; GlobalFlagsClear
                dd 0                    ; GlobalFlagsSet
                dd 0                    ; CriticalSectionDefaultTimeout
                dq 0                    ; DeCommitFreeBlockThreshold
                dq 0                    ; DeCommitTotalFreeThreshold
                dq 0                    ; LockPrefixTable
                dq 0                    ; MaximumAllocationSize
                dq 0                    ; VirtualMemoryThreshold
                dq 0                    ; ProcessAffinityMask
                dd 0                    ; ProcessHeapFlags
                dw 0                    ; CSDVersion
                dw 0                    ; Reserved1
                dq 0                    ; EditList
                dq offset __security_cookie ; SecurityCookie
                dq 0                    ; SEHandlerTable
                dq 0                    ; SEHandlerCount
                dq offset __guard_check_icall_fptr ; GuardCFCheckFunctionPointer
                dq offset __guard_dispatch_icall_fptr ; GuardCFDispatchFunctionPointer
                dq 0                    ; GuardCFFunctionTable
                dq 0                    ; GuardCFFunctionCount
                dd 100h                 ; GuardFlags
                dw 0                    ; CodeIntegrity.Flags
                dw 0                    ; CodeIntegrity.Catalog
                dd 0                    ; CodeIntegrity.CatalogOffset
                dd 0                    ; CodeIntegrity.Reserved
                dq 0                    ; GuardAddressTakenIatEntryTable
                dq 0                    ; GuardAddressTakenIatEntryCount
                dq 0                    ; GuardLongJumpTargetTable
                dq 0                    ; GuardLongJumpTargetCount
                dq 0                    ; DynamicValueRelocTable
                dq 0                    ; CHPEMetadataPointer
                dq 0                    ; GuardRFFailureRoutine
                dq 0                    ; GuardRFFailureRoutineFunctionPointer
                dd 0                    ; DynamicValueRelocTableOffset
                dw 0                    ; DynamicValueRelocTableSection
                dw 0                    ; Reserved2
                dq 0                    ; GuardRFVerifyStackPointerFunctionPointer
                dd 0                    ; HotPatchTableOffset
                dd 0                    ; Reserved3
                dq 0                    ; EnclaveConfigurationPointer
                dq offset __volatile_metadata ; VolatileMetadataPointer
                dq 0                    ; GuardEHContinuationTable
                dq 0                    ; GuardEHContinuationCount
                dq offset __guard_xfg_check_icall_fptr ; GuardXFGCheckFunctionPointer
                dq offset __guard_xfg_dispatch_icall_fptr ; GuardXFGDispatchFunctionPointer
                dq offset __guard_xfg_table_dispatch_icall_fptr ; GuardXFGTableDispatchFunctionPointer
                dq offset __castguard_check_failure_os_handled_fptr ; CastGuardOsDeterminedFailureMode
                dq offset off_140007348
; Debug Directory entries
                dd 0                    ; Characteristics
                dd 6442CE23h            ; TimeDateStamp: Fri Apr 21 17:55:47 2023
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 0Dh                  ; Type: IMAGE_DEBUG_TYPE_POGO
                dd 2D0h                 ; SizeOfData
                dd rva aGctl            ; AddressOfRawData
                dd 72A8h                ; PointerToRawData
                dd 0                    ; Characteristics
                dd 6442CE23h            ; TimeDateStamp: Fri Apr 21 17:55:47 2023
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 0Eh                  ; Type: IMAGE_DEBUG_TYPE_ILTCG
                dd 0                    ; SizeOfData
                dd 0                    ; AddressOfRawData
                dd 0                    ; PointerToRawData
                align 40h
unk_140007A00   db    1                 ; DATA XREF: .rdata:00000001400074B0↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  90h
                db 0A1h
                db    0
                db    0
                db  28h ; (
                db  7Ah ; z
                db    0
                db    0
                db    0
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db  40h ; @
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  50h ; P
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  90h
                db 0A1h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  28h ; (
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007A78   db    1                 ; DATA XREF: .rdata:00000001400074D0↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  30h ; 0
                db 0A1h
                db    0
                db    0
                db 0C0h
                db  7Dh ; }
                db    0
                db    0
                db  78h ; x
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  7Bh ; {
                db    0
                db    0
                db 0F0h
                db  7Bh ; {
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007AB8   db    1                 ; DATA XREF: .rdata:00000001400077D8↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  80h
                db 0A2h
                db    0
                db    0
                db  58h ; X
                db  7Dh ; }
                db    0
                db    0
                db 0B8h
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  50h ; P
                db  7Fh ; 
                db    0
                db    0
                db  18h
                db  7Dh ; }
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  80h
                db 0A2h
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  58h ; X
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  50h ; P
                db  7Bh ; {
                db    0
                db    0
                db 0F0h
                db  7Dh ; }
                db    0
                db    0
                db  58h ; X
                db  7Ch ; |
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0A8h
                db 0A0h
                db    0
                db    0
                db    3
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  78h ; x
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007B78   db    1                 ; DATA XREF: .rdata:00000001400077A8↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A0h
                db    0
                db    0
                db 0E0h
                db  7Fh ; 
                db    0
                db    0
                db  78h ; x
                db  7Bh ; {
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007BA0   db    1                 ; DATA XREF: .rdata:0000000140007800↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0E0h
                db 0A1h
                db    0
                db    0
                db  70h ; p
                db  7Eh ; ~
                db    0
                db    0
                db 0A0h
                db  7Bh ; {
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007BC8   db    1                 ; DATA XREF: .rdata:00000001400077C0↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    8
                db 0A1h
                db    0
                db    0
                db  40h ; @
                db  7Dh ; }
                db    0
                db    0
                db 0C8h
                db  7Bh ; {
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  50h ; P
                db 0A2h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db 0B8h
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007C18   db    1                 ; DATA XREF: .rdata:0000000140007760↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  18h
                db 0A2h
                db    0
                db    0
                db  98h
                db  7Dh ; }
                db    0
                db    0
                db  18h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  18h
                db  7Dh ; }
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A0h
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db 0E0h
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0F0h
                db  7Dh ; }
                db    0
                db    0
                db  58h ; X
                db  7Ch ; |
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  30h ; 0
                db 0A1h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db 0C0h
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007CC8   db    1                 ; DATA XREF: .rdata:0000000140007838↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0A8h
                db 0A0h
                db    0
                db    0
                db  78h ; x
                db  7Fh ; 
                db    0
                db    0
                db 0C8h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  18h
                db 0A2h
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  98h
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  80h
                db 0A0h
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db 0A0h
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    3
                db    0
                db    0
                db    0
                db  80h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db 0A0h
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0B8h
                db  7Fh ; 
                db    0
                db    0
                db 0F8h
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db 0D8h
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0F8h
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db  88h
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0F0h
                db  7Ch ; |
                db    0
                db    0
                db 0F8h
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    8
                db 0A1h
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  40h ; @
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db 0B0h
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007E30   db    1                 ; DATA XREF: .rdata:00000001400074E8↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  80h
                db 0A0h
                db    0
                db    0
                db 0A0h
                db  7Eh ; ~
                db    0
                db    0
                db  30h ; 0
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    5
                db    0
                db    0
                db    0
                db 0D0h
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db  70h ; p
                db  7Dh ; }
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    3
                db    0
                db    0
                db    0
                db 0E0h
                db  7Ah ; z
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db  40h ; @
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db  40h ; @
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  90h
                db  7Fh ; 
                db    0
                db    0
                db  50h ; P
                db  7Bh ; {
                db    0
                db    0
                db 0F0h
                db  7Dh ; }
                db    0
                db    0
                db  58h ; X
                db  7Ch ; |
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db  7Ch ; |
                db    0
                db    0
                db 0A0h
                db  7Ch ; |
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140007F18   db    1                 ; DATA XREF: .rdata:0000000140007510↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A1h
                db    0
                db    0
                db  88h
                db  7Eh ; ~
                db    0
                db    0
                db  18h
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0F0h
                db  7Bh ; {
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A1h
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  88h
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  28h ; (
                db  7Bh ; {
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0D0h
                db 0A0h
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  58h ; X
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0E0h
                db 0A1h
                db    0
                db    0
                db    1
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  70h ; p
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db    0
                db  7Fh ; 
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0B0h
                db 0A1h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  18h
                db  7Eh ; ~
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_140008020   db    1                 ; DATA XREF: .rdata:0000000140007748↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0D0h
                db 0A0h
                db    0
                db    0
                db  58h ; X
                db  7Eh ; ~
                db    0
                db    0
                db  20h
                db  80h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
__volatile_metadata db  18h             ; DATA XREF: .rdata:0000000140007960↑o
                db    0
                db    0
                db    0
                db    2
                db  80h
                db    2
                db  80h
                db  5Ch ; \
                db  80h
                db    0
                db    0
                db  2Ch ; ,
                db    0
                db    0
                db    0
                db  88h
                db  80h
                db    0
                db    0
                db  20h
                db    0
                db    0
                db    0
                db  17h
                db  5Fh ; _
                db    0
                db    0
                db  93h
                db  5Fh ; _
                db    0
                db    0
                db 0A8h
                db  5Fh ; _
                db    0
                db    0
                db  81h
                db  60h ; `
                db    0
                db    0
                db  97h
                db  60h ; `
                db    0
                db    0
                db  37h ; 7
                db  62h ; b
                db    0
                db    0
                db  8Ah
                db  64h ; d
                db    0
                db    0
                db 0BCh
                db  64h ; d
                db    0
                db    0
                db  9Fh
                db  67h ; g
                db    0
                db    0
                db 0A4h
                db  67h ; g
                db    0
                db    0
                db 0EEh
                db  67h ; g
                db    0
                db    0
                db  78h ; x
                db  54h ; T
                db    0
                db    0
                db 0A8h
                db    6
                db    0
                db    0
                db  50h ; P
                db  5Bh ; [
                db    0
                db    0
                db 0E0h
                db  0Ch
                db    0
                db    0
                db 0F8h
                db  68h ; h
                db    0
                db    0
                db  7Fh ; 
                db    0
                db    0
                db    0
                db  65h ; e
                db  6Ch ; l
                db    0
                db    0
                db  36h ; 6
                db    0
                db    0
                db    0
; Debug information (IMAGE_DEBUG_TYPE_POGO)
aGctl           db 'GCTL',0             ; DATA XREF: .rdata:00000001400079B4↑o
                db  10h
                db    0
                db    0
                db  90h
                db  59h ; Y
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  6Dh ; m
                db  6Eh ; n
                db    0
                db    0
                db    0
                db    0
                db  90h
                db  69h ; i
                db    0
                db    0
                db  40h ; @
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  6Dh ; m
                db  6Eh ; n
                db  24h ; $
                db  30h ; 0
                db  30h ; 0
                db    0
                db 0D0h
                db  69h ; i
                db    0
                db    0
                db 0CBh
                db    2
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  78h ; x
                db    0
                db    0
                db  70h ; p
                db    0
                db    0
                db  18h
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  35h ; 5
                db    0
                db    0
                db    0
                db    0
                db  18h
                db  73h ; s
                db    0
                db    0
                db  38h ; 8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  30h ; 0
                db  30h ; 0
                db  63h ; c
                db  66h ; f
                db  67h ; g
                db    0
                db    0
                db  50h ; P
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db  60h ; `
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  68h ; h
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  70h ; p
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db  78h ; x
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  41h ; A
                db  43h ; C
                db    0
                db    0
                db    0
                db  80h
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  88h
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  50h ; P
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  90h
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  50h ; P
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  98h
                db  73h ; s
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  54h ; T
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db 0A0h
                db  73h ; s
                db    0
                db    0
                db  10h
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  54h ; T
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db 0B0h
                db  73h ; s
                db    0
                db    0
                db  50h ; P
                db    6
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db    0
                db  7Ah ; z
                db    0
                db    0
                db  44h ; D
                db    6
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  72h ; r
                db    0
                db    0
                db    0
                db    0
                db  44h ; D
                db  80h
                db    0
                db    0
                db  64h ; d
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  76h ; v
                db  6Fh ; o
                db  6Ch ; l
                db  74h ; t
                db  6Dh ; m
                db  64h ; d
                db    0
                db    0
                db    0
                db 0A8h
                db  80h
                db    0
                db    0
                db 0D0h
                db    2
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  7Ah ; z
                db  7Ah ; z
                db  7Ah ; z
                db  64h ; d
                db  62h ; b
                db  67h ; g
                db    0
                db    0
                db    0
                db  78h ; x
                db  83h
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  49h ; I
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  80h
                db  83h
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  49h ; I
                db  5Ah ; Z
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  88h
                db  83h
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  54h ; T
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  90h
                db  83h
                db    0
                db    0
                db    8
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  54h ; T
                db  5Ah ; Z
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  98h
                db  83h
                db    0
                db    0
                db  18h
                db  0Bh
                db    0
                db    0
                db  2Eh ; .
                db  78h ; x
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db 0B0h
                db  8Eh
                db    0
                db    0
                db  24h ; $
                db    2
                db    0
                db    0
                db  2Eh ; .
                db  78h ; x
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  78h ; x
                db    0
                db    0
                db    0
                db    0
                db 0D4h
                db  90h
                db    0
                db    0
                db 0DCh
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  32h ; 2
                db    0
                db    0
                db    0
                db    0
                db 0B0h
                db  91h
                db    0
                db    0
                db  18h
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  33h ; 3
                db    0
                db    0
                db    0
                db    0
                db 0C8h
                db  91h
                db    0
                db    0
                db  18h
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  34h ; 4
                db    0
                db    0
                db    0
                db    0
                db 0E0h
                db  94h
                db    0
                db    0
                db  18h
                db    8
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  36h ; 6
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0A0h
                db    0
                db    0
                db  58h ; X
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A0h
                db    0
                db    0
                db  38h ; 8
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  72h ; r
                db    0
                db  90h
                db 0A1h
                db    0
                db    0
                db  40h ; @
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  72h ; r
                db  73h ; s
                db    0
                db    0
                db    0
                db    0
                db 0D0h
                db 0A2h
                db    0
                db    0
                db 0F8h
                db    5
                db    0
                db    0
                db  2Eh ; .
                db  62h ; b
                db  73h ; s
                db  73h ; s
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0B0h
                db    0
                db    0
                db  2Ch ; ,
                db    7
                db    0
                db    0
                db  2Eh ; .
                db  70h ; p
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db    0
                db 0C0h
                db    0
                db    0
                db  60h ; `
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  73h ; s
                db  72h ; r
                db  63h ; c
                db  24h ; $
                db  30h ; 0
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  60h ; `
                db 0C0h
                db    0
                db    0
                db  80h
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  73h ; s
                db  72h ; r
                db  63h ; c
                db  24h ; $
                db  30h ; 0
                db  32h ; 2
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
; void (*qword_140008380[2])(void)
qword_140008380 dq 2 dup(0)             ; DATA XREF: sub_1400065F4+A↑o
                                        ; sub_1400065F4+11↑o
; void (*qword_140008390)(void)
qword_140008390 dq 0                    ; DATA XREF: sub_140006630+A↑o
                                        ; sub_140006630+11↑o
stru_140008398  UNWIND_INFO_HDR <1, 1Ah, 3, 0>
                                        ; DATA XREF: .pdata:ExceptionDir↓o
                UNWIND_CODE <1Ah, 62h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <16h, 70h>  ; UWOP_PUSH_NONVOL
                UNWIND_CODE <15h, 30h>  ; UWOP_PUSH_NONVOL
                align 4
stru_1400083A4  UNWIND_INFO_HDR <1, 6, 2, 0>
                                        ; DATA XREF: .rdata:000000014000881C↓o
                                        ; .rdata:000000014000882C↓o ...
                UNWIND_CODE <6, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_1400083AC  UNWIND_INFO_HDR <1, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B018↓o
                                        ; .pdata:000000014000B078↓o ...
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <0Ah, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
stru_1400083B8  UNWIND_INFO_HDR <1, 4, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B024↓o
                                        ; .pdata:000000014000B4F8↓o ...
                UNWIND_CODE <4, 82h>    ; UWOP_ALLOC_SMALL
                align 4
stru_1400083C0  UNWIND_INFO_HDR <1, 4, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B048↓o
                                        ; .pdata:000000014000B300↓o ...
                UNWIND_CODE <4, 42h>    ; UWOP_ALLOC_SMALL
                align 4
stru_1400083C8  UNWIND_INFO_HDR <1, 6, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B060↓o
                UNWIND_CODE <6, 52h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_1400083D0  UNWIND_INFO_HDR <19h, 21h, 7, 0>
                                        ; DATA XREF: .pdata:000000014000B06C↓o
                UNWIND_CODE <13h, 1>    ; UWOP_ALLOC_LARGE
                dw 14h
                UNWIND_CODE <7, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <4, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 30h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 50h>    ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck_EH4
                dd rva byte_1400083F0
                db  92h
                db    0
                db    0
                db    0
byte_1400083F0  db 28h                  ; DATA XREF: .rdata:00000001400083E8↑o
                                        ; FuncInfo4
                dd rva byte_1400083F9   ; unwind map
                dd rva byte_14000840C   ; ip2state map
byte_1400083F9  db 8                    ; DATA XREF: .rdata:00000001400083F1↑o
                                        ; num unwind entries: 4
                db 0Ch                  ; funclet type: 2
                dd rva sub_140003F70    ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
                db 32h                  ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 0E0h                 ; frame offset of object ptr to be destructed
                db 66h                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 88h                  ; funclet type: 0
byte_14000840C  db 0Ah                  ; DATA XREF: .rdata:00000001400083F5↑o
                                        ; num_ip2state entries: 5
                db 6Ah                  ; ea 0x140001335
                db 0                    ; state -1
                db 4Eh                  ; ea 0x14000135C
                db 2                    ; state 0
                db 30h                  ; ea 0x140001374
                db 4                    ; state 1
                db 36h                  ; ea 0x14000138F
                db 2                    ; state 0
                db 69h, 4               ; ea 0x1400014A9
                db 0                    ; state -1
stru_140008418  UNWIND_INFO_HDR <11h, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B084↓o
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Eh
                UNWIND_CODE <0Ah, 92h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_14000842C
byte_14000842C  db 28h                  ; DATA XREF: .rdata:0000000140008428↑o
                                        ; FuncInfo4
                dd rva byte_140008435   ; unwind map
                dd rva byte_140008441   ; ip2state map
byte_140008435  db 4                    ; DATA XREF: .rdata:000000014000842D↑o
                                        ; num unwind entries: 2
                db 0Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 32h                  ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
byte_140008441  db 4                    ; DATA XREF: .rdata:0000000140008431↑o
                                        ; num_ip2state entries: 2
                db 7Ah                  ; ea 0x14000154D
                db 0                    ; state -1
                db 36h                  ; ea 0x140001568
                db 4                    ; state 1
                db    0
                db    0
stru_140008448  UNWIND_INFO_HDR <1, 4, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B090↓o
                                        ; .pdata:000000014000B0E4↓o
                UNWIND_CODE <4, 0E2h>   ; UWOP_ALLOC_SMALL
                align 4
stru_140008450  UNWIND_INFO_HDR <11h, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B0B4↓o
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0Ah, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_140008464
byte_140008464  db 28h                  ; DATA XREF: .rdata:0000000140008460↑o
                                        ; FuncInfo4
                dd rva byte_14000846D   ; unwind map
                dd rva byte_140008473   ; ip2state map
byte_14000846D  db 2                    ; DATA XREF: .rdata:0000000140008465↑o
                                        ; .rdata:00000001400085AD↓o ...
                                        ; num unwind entries: 1
                db 0Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
byte_140008473  db 2                    ; DATA XREF: .rdata:0000000140008469↑o
                                        ; num_ip2state entries: 1
                db 76h                  ; ea 0x14000171B
                db 0                    ; state -1
                db    0
                db    0
stru_140008478  UNWIND_INFO_HDR <19h, 19h, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B0CC↓o
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <0Ah, 72h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
                dd rva __GSHandlerCheck_EH4
                dd rva byte_140008490
                db  3Ah ; :
                db    0
                db    0
                db    0
byte_140008490  db 28h                  ; DATA XREF: .rdata:0000000140008488↑o
                                        ; FuncInfo4
                dd rva byte_140008499   ; unwind map
                dd rva byte_1400084A5   ; ip2state map
byte_140008499  db 4                    ; DATA XREF: .rdata:0000000140008491↑o
                                        ; num unwind entries: 2
                db 0Ah                  ; funclet type: 1
                dd rva sub_1400016C0    ; funclet
                db 50h                  ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
byte_1400084A5  db 4                    ; DATA XREF: .rdata:0000000140008495↑o
                                        ; num_ip2state entries: 2
                db 0EEh                 ; ea 0x140001827
                db 2                    ; state 0
                db 36h                  ; ea 0x140001842
                db 0                    ; state -1
                db    0
                db    0
stru_1400084AC  UNWIND_INFO_HDR <19h, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B0D8↓o
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <0Ah, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_1400084C0
byte_1400084C0  db 60h                  ; DATA XREF: .rdata:00000001400084BC↑o
                                        ; FuncInfo4
                dd rva byte_1400084C5   ; ip2state map
byte_1400084C5  db 2                    ; DATA XREF: .rdata:00000001400084C1↑o
                                        ; num_ip2state entries: 1
                db 66h                  ; ea 0x140001893
                db 0                    ; state -1
stru_1400084C8  UNWIND_INFO_HDR <11h, 0Fh, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B0F0↓o
                UNWIND_CODE <0Fh, 72h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 0F0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <9, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 0C0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <4, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 50h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_1400084E4
byte_1400084E4  db 28h                  ; DATA XREF: .rdata:00000001400084E0↑o
                                        ; FuncInfo4
                dd rva byte_1400084ED   ; unwind map
                dd rva byte_1400084F8   ; ip2state map
byte_1400084ED  db 4                    ; DATA XREF: .rdata:00000001400084E5↑o
                                        ; num unwind entries: 2
                db 0Eh                  ; funclet type: 3
                dd rva loc_140006A10    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
byte_1400084F8  db 2                    ; DATA XREF: .rdata:00000001400084E9↑o
                                        ; num_ip2state entries: 1
                db 0A1h, 3              ; ea 0x140001A38
                db 2                    ; state 0
stru_1400084FC  UNWIND_INFO_HDR <1, 6, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B6E4↓o
                                        ; .pdata:000000014000B6F0↓o ...
                UNWIND_CODE <6, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 50h>    ; UWOP_PUSH_NONVOL
stru_140008504  UNWIND_INFO_HDR <1, 8, 4, 0>
                                        ; DATA XREF: .rdata:0000000140008528↓o
                                        ; .rdata:0000000140008538↓o ...
                UNWIND_CODE <8, 0B2h>   ; UWOP_ALLOC_SMALL
                UNWIND_CODE <4, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_140008510  UNWIND_INFO_HDR <21h, 23h, 0Ah, 0>
                                        ; DATA XREF: .pdata:000000014000B108↓o
                UNWIND_CODE <23h, 0F4h> ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <1Bh, 0E4h> ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <16h, 0D4h> ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <11h, 0C4h> ; UWOP_SAVE_NONVOL
                dw 0Bh
                UNWIND_CODE <8, 54h>    ; UWOP_SAVE_NONVOL
                dw 12h
                RUNTIME_FUNCTION <rva ProcessAndCopyData, rva loc_140001C2C, \
                                  rva stru_140008504>
stru_140008534  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B114↓o
                RUNTIME_FUNCTION <rva ProcessAndCopyData, rva loc_140001C2C, \
                                  rva stru_140008504>
stru_140008544  UNWIND_INFO_HDR <21h, 0, 0Ah, 0>
                                        ; DATA XREF: .pdata:000000014000B120↓o
                                        ; .pdata:000000014000B12C↓o
                UNWIND_CODE <0, 0F4h>   ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0, 0E4h>   ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <0, 0D4h>   ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <0, 0C4h>   ; UWOP_SAVE_NONVOL
                dw 0Bh
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 12h
                RUNTIME_FUNCTION <rva ProcessAndCopyData, rva loc_140001C2C, \
                                  rva stru_140008504>
stru_140008568  UNWIND_INFO_HDR <19h, 6, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B138↓o
                UNWIND_CODE <6, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 70h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_140008578
byte_140008578  db 60h                  ; DATA XREF: .rdata:0000000140008574↑o
                                        ; FuncInfo4
                dd rva byte_14000857D   ; ip2state map
byte_14000857D  db 2                    ; DATA XREF: .rdata:0000000140008579↑o
                                        ; num_ip2state entries: 1
                db 5Dh, 2               ; ea 0x140001EE7
                db 0                    ; state -1
                db    0
                db    0
                db    0
stru_140008584  UNWIND_INFO_HDR <1, 0Ch, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B144↓o
                UNWIND_CODE <0Ch, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <0Ch, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <8, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 50h>    ; UWOP_PUSH_NONVOL
stru_140008594  UNWIND_INFO_HDR <11h, 0Fh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B150↓o
                UNWIND_CODE <0Fh, 64h>  ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0Fh, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_1400085AC
byte_1400085AC  db 28h                  ; DATA XREF: .rdata:00000001400085A8↑o
                                        ; FuncInfo4
                dd rva byte_14000846D   ; unwind map
                dd rva byte_1400085B5   ; ip2state map
byte_1400085B5  db 2                    ; DATA XREF: .rdata:00000001400085B1↑o
                                        ; num_ip2state entries: 1
                db 7Dh, 4               ; ea 0x14000221F
                db 0                    ; state -1
                db    0
                db    0
                db    0
stru_1400085BC  UNWIND_INFO_HDR <1, 6, 2, 0>
                                        ; DATA XREF: .rdata:00000001400085D0↓o
                                        ; .rdata:00000001400085E0↓o ...
                UNWIND_CODE <6, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 70h>    ; UWOP_PUSH_NONVOL
stru_1400085C4  UNWIND_INFO_HDR <21h, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B168↓o
                UNWIND_CODE <0Ah, 64h>  ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <5, 34h>    ; UWOP_SAVE_NONVOL
                dw 6
                RUNTIME_FUNCTION <rva CopyAndResizeString, rva loc_140002265, \
                                  rva stru_1400085BC>
stru_1400085DC  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B174↓o
                RUNTIME_FUNCTION <rva CopyAndResizeString, rva loc_140002265, \
                                  rva stru_1400085BC>
stru_1400085EC  UNWIND_INFO_HDR <11h, 6, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B18C↓o
                UNWIND_CODE <6, 72h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_1400085FC
byte_1400085FC  db 28h                  ; DATA XREF: .rdata:00000001400085F8↑o
                                        ; FuncInfo4
                dd rva byte_140008605   ; unwind map
                dd rva byte_140008625   ; ip2state map
byte_140008605  db 0Ch                  ; DATA XREF: .rdata:00000001400085FD↑o
                                        ; num unwind entries: 6
                db 0Ch                  ; funclet type: 2
                dd rva loc_140001120    ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 5Eh                  ; funclet type: 3
                dd rva loc_140006A4C    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 56h                  ; funclet type: 3
                dd rva loc_140006A5C    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
byte_140008625  db 4                    ; DATA XREF: .rdata:0000000140008601↑o
                                        ; num_ip2state entries: 2
                db 3Eh                  ; ea 0x14000234F
                db 0                    ; state -1
                db 0F6h                 ; ea 0x1400023CA
                db 0Ah                  ; state 4
                db    0
                db    0
stru_14000862C  UNWIND_INFO_HDR <11h, 7, 3, 0>
                                        ; DATA XREF: .pdata:000000014000B198↓o
                UNWIND_CODE <7, 0C2h>   ; UWOP_ALLOC_SMALL
                UNWIND_CODE <3, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
                dd rva __CxxFrameHandler4
                dd rva byte_140008640
byte_140008640  db 28h                  ; DATA XREF: .rdata:000000014000863C↑o
                                        ; FuncInfo4
                dd rva byte_140008649   ; unwind map
                dd rva byte_14000866A   ; ip2state map
byte_140008649  db 0Ch                  ; DATA XREF: .rdata:0000000140008641↑o
                                        ; num unwind entries: 6
                db 0Ch                  ; funclet type: 2
                dd rva loc_140001120    ; funclet
                db 0A0h                 ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva ?dtor$3@?0???0_Locinfo@std@@QEAA@PEBD@Z@4HA ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 56h                  ; funclet type: 3
                dd rva ?dtor$5@?0???0_Locinfo@std@@QEAA@PEBD@Z@4HA ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 52h                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 60h                  ; frame offset of object ptr to be destructed
byte_14000866A  db 6                    ; DATA XREF: .rdata:0000000140008645↑o
                                        ; num_ip2state entries: 3
                db 46h                  ; ea 0x140002403
                db 0                    ; state -1
                db 2Eh                  ; ea 0x14000241A
                db 2                    ; state 0
                db 41h, 2               ; ea 0x1400024AA
                db 0Ch                  ; state 5
                db    0
                db    0
stru_140008674  UNWIND_INFO_HDR <19h, 2Ch, 0Bh, 0>
                                        ; DATA XREF: .pdata:000000014000B1A4↓o
                UNWIND_CODE <1Eh, 64h>  ; UWOP_SAVE_NONVOL
                dw 1Bh
                UNWIND_CODE <1Eh, 34h>  ; UWOP_SAVE_NONVOL
                dw 1Ah
                UNWIND_CODE <1Eh, 1>    ; UWOP_ALLOC_LARGE
                dw 12h
                UNWIND_CODE <12h, 0F0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <10h, 0E0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Eh, 0C0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Ch, 70h>  ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Bh, 50h>  ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck_EH4
                dd rva byte_14000869C
                db  82h
                db    0
                db    0
                db    0
byte_14000869C  db 28h                  ; DATA XREF: .rdata:0000000140008694↑o
                                        ; FuncInfo4
                dd rva byte_1400086A5   ; unwind map
                dd rva byte_1400086BC   ; ip2state map
byte_1400086A5  db 8                    ; DATA XREF: .rdata:000000014000869D↑o
                                        ; num unwind entries: 4
                db 0Eh                  ; funclet type: 3
                dd rva loc_140006AB0    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 52h                  ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 0C0h                 ; frame offset of object ptr to be destructed
                db 32h                  ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 80h                  ; frame offset of object ptr to be destructed
byte_1400086BC  db 0Ah                  ; DATA XREF: .rdata:00000001400086A1↑o
                                        ; num_ip2state entries: 5
                db 45h, 2               ; ea 0x1400025A1
                db 2                    ; state 0
                db 66h                  ; ea 0x1400025D4
                db 6                    ; state 2
                db 6Ah                  ; ea 0x140002609
                db 8                    ; state 3
                db 0FDh, 2              ; ea 0x1400026C8
                db 6                    ; state 2
                db 59h, 2               ; ea 0x14000275E
                db 2                    ; state 0
                db    0
                db    0
stru_1400086CC  UNWIND_INFO_HDR <1, 0Fh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B1B0↓o
                UNWIND_CODE <0Fh, 64h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <0Fh, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
stru_1400086DC  UNWIND_INFO_HDR <1, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B1BC↓o
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <0Ah, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
stru_1400086E8  UNWIND_INFO_HDR <11h, 7, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B1C8↓o
                UNWIND_CODE <7, 1>      ; UWOP_ALLOC_LARGE
                dw 1Fh
                dd rva __CxxFrameHandler4
                dd rva byte_1400086F8
byte_1400086F8  db 28h                  ; DATA XREF: .rdata:00000001400086F4↑o
                                        ; FuncInfo4
                dd rva byte_140008701   ; unwind map
                dd rva byte_140008708   ; ip2state map
byte_140008701  db 2                    ; DATA XREF: .rdata:00000001400086F9↑o
                                        ; .rdata:000000014000875D↓o
                                        ; num unwind entries: 1
                db 0Ah                  ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 80h                  ; frame offset of object ptr to be destructed
byte_140008708  db 4                    ; DATA XREF: .rdata:00000001400086FD↑o
                                        ; num_ip2state entries: 2
                db 4Ah                  ; ea 0x140002A25
                db 0                    ; state -1
                db 3Eh                  ; ea 0x140002A44
                db 2                    ; state 0
                db    0
                db    0
                db    0
stru_140008710  UNWIND_INFO_HDR <11h, 0Fh, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B1D4↓o
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <0Fh, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_140008724
byte_140008724  db 28h                  ; DATA XREF: .rdata:0000000140008720↑o
                                        ; FuncInfo4
                dd rva byte_14000872D   ; unwind map
                dd rva byte_14000873E   ; ip2state map
byte_14000872D  db 6                    ; DATA XREF: .rdata:0000000140008725↑o
                                        ; num unwind entries: 3
                db 0Ch                  ; funclet type: 2
                dd rva loc_140001120    ; funclet
                db 60h                  ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva loc_140006B0C    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva ?dtor$5@?0???0_Locinfo@std@@QEAA@PEBD@Z@4HA_0 ; funclet
byte_14000873E  db 6                    ; DATA XREF: .rdata:0000000140008729↑o
                                        ; num_ip2state entries: 3
                db 0AEh                 ; ea 0x140002AB7
                db 2                    ; state 0
                db 1Ch                  ; ea 0x140002AC5
                db 4                    ; state 1
                db 1Ch                  ; ea 0x140002AD3
                db 6                    ; state 2
                db    0
                db    0
                db    0
stru_140008748  UNWIND_INFO_HDR <11h, 9, 3, 0>
                                        ; DATA XREF: .pdata:000000014000B1E0↓o
                UNWIND_CODE <9, 1>      ; UWOP_ALLOC_LARGE
                dw 1Eh
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
                dd rva __CxxFrameHandler4
                dd rva byte_14000875C
byte_14000875C  db 28h                  ; DATA XREF: .rdata:0000000140008758↑o
                                        ; FuncInfo4
                dd rva byte_140008701   ; unwind map
                dd rva byte_140008765   ; ip2state map
byte_140008765  db 4                    ; DATA XREF: .rdata:0000000140008761↑o
                                        ; num_ip2state entries: 2
                db 52h                  ; ea 0x140002B19
                db 0                    ; state -1
                db 44h                  ; ea 0x140002B3B
                db 2                    ; state 0
                db    0
                db    0
stru_14000876C  UNWIND_INFO_HDR <19h, 15h, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B1EC↓o
                UNWIND_CODE <6, 92h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                dd rva __GSHandlerCheck
                dd 40h
stru_14000877C  UNWIND_INFO_HDR <11h, 0Bh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B1F8↓o
                UNWIND_CODE <0Bh, 72h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <7, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <4, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 50h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_140008794
byte_140008794  db 28h                  ; DATA XREF: .rdata:0000000140008790↑o
                                        ; FuncInfo4
                dd rva byte_14000879D   ; unwind map
                dd rva byte_1400087A9   ; ip2state map
byte_14000879D  db 4                    ; DATA XREF: .rdata:0000000140008795↑o
                                        ; .rdata:00000001400087C9↓o
                                        ; num unwind entries: 2
                db 0Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 32h                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
byte_1400087A9  db 2                    ; DATA XREF: .rdata:0000000140008799↑o
                                        ; num_ip2state entries: 1
                db 1Dh, 2               ; ea 0x140002D57
                db 4                    ; state 1
                db    0
                db    0
                db    0
stru_1400087B0  UNWIND_INFO_HDR <11h, 0Fh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B204↓o
                UNWIND_CODE <0Fh, 64h>  ; UWOP_SAVE_NONVOL
                dw 0Eh
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Dh
                UNWIND_CODE <0Fh, 92h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_1400087C8
byte_1400087C8  db 28h                  ; DATA XREF: .rdata:00000001400087C4↑o
                                        ; FuncInfo4
                dd rva byte_14000879D   ; unwind map
                dd rva byte_1400087D1   ; ip2state map
byte_1400087D1  db 4                    ; DATA XREF: .rdata:00000001400087CD↑o
                                        ; num_ip2state entries: 2
                db 0A1h, 2              ; ea 0x140002ED8
                db 0                    ; state -1
                db 2Ch                  ; ea 0x140002EEE
                db 4                    ; state 1
                db    0
stru_1400087D8  UNWIND_INFO_HDR <11h, 0Ch, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B210↓o
                UNWIND_CODE <0Ch, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Ch
                UNWIND_CODE <0Ch, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <8, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 50h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_1400087F0
byte_1400087F0  db 28h                  ; DATA XREF: .rdata:00000001400087EC↑o
                                        ; FuncInfo4
                dd rva byte_1400087F9   ; unwind map
                dd rva byte_140008810   ; ip2state map
byte_1400087F9  db 0Ah                  ; DATA XREF: .rdata:00000001400087F1↑o
                                        ; num unwind entries: 5
                db 0Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 34h                  ; funclet type: 2
                dd rva sub_140003040    ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva loc_140006B4C    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 50h                  ; funclet type: 0
byte_140008810  db 2                    ; DATA XREF: .rdata:00000001400087F5↑o
                                        ; num_ip2state entries: 1
                db 1Dh, 3               ; ea 0x140003017
                db 6                    ; state 2
stru_140008814  UNWIND_INFO_HDR <21h, 5, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B234↓o
                UNWIND_CODE <5, 74h>    ; UWOP_SAVE_NONVOL
                dw 6
                RUNTIME_FUNCTION <rva sub_1400030B0, rva loc_1400030BF, \
                                  rva stru_1400083A4>
stru_140008828  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B240↓o
                RUNTIME_FUNCTION <rva sub_1400030B0, rva loc_1400030BF, \
                                  rva stru_1400083A4>
stru_140008838  UNWIND_INFO_HDR <19h, 24h, 7, 0>
                                        ; DATA XREF: .pdata:000000014000B24C↓o
                UNWIND_CODE <12h, 64h>  ; UWOP_SAVE_NONVOL
                dw 52h
                UNWIND_CODE <12h, 34h>  ; UWOP_SAVE_NONVOL
                dw 51h
                UNWIND_CODE <12h, 1>    ; UWOP_ALLOC_LARGE
                dw 4Eh
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck
                dd 260h
stru_140008854  UNWIND_INFO_HDR <19h, 30h, 0Bh, 0>
                                        ; DATA XREF: .pdata:000000014000B258↓o
                UNWIND_CODE <1Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 79h
                UNWIND_CODE <1Fh, 1>    ; UWOP_ALLOC_LARGE
                dw 70h
                UNWIND_CODE <10h, 0F0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Eh, 0E0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Ch, 0D0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Ah, 0C0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <8, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 50h>    ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck_EH4
                dd rva byte_14000887C
                db  72h ; r
                db    3
                db    0
                db    0
byte_14000887C  db 28h                  ; DATA XREF: .rdata:0000000140008874↑o
                                        ; FuncInfo4
                dd rva byte_140008885   ; unwind map
                dd rva byte_1400088AF   ; ip2state map
byte_140008885  db 0Ch                  ; DATA XREF: .rdata:000000014000887D↑o
                                        ; num unwind entries: 6
                db 0Ah                  ; funclet type: 1
                dd rva sub_1400030B0    ; funclet
                db 81h, 3               ; frame offset of object ptr to be destructed
                db 42h                  ; funclet type: 1
                dd rva sub_1400030B0    ; funclet
                db 81h, 3               ; frame offset of object ptr to be destructed
                db 3Ah                  ; funclet type: 1
                dd rva sub_1400030B0    ; funclet
                db 41h, 3               ; frame offset of object ptr to be destructed
                db 3Ah                  ; funclet type: 1
                dd rva sub_1400030B0    ; funclet
                db 41h, 4               ; frame offset of object ptr to be destructed
                db 3Ah                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 0C1h, 3              ; frame offset of object ptr to be destructed
                db 3Ah                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 70h                  ; frame offset of object ptr to be destructed
byte_1400088AF  db 14h                  ; DATA XREF: .rdata:0000000140008881↑o
                                        ; num_ip2state entries: 10
                db 90h                  ; ea 0x140003228
                db 2                    ; state 0
                db 89h, 3               ; ea 0x14000330A
                db 8                    ; state 3
                db 4Ah                  ; ea 0x14000332F
                db 0Ah                  ; state 4
                db 1Ch                  ; ea 0x14000333D
                db 0Ch                  ; state 5
                db 0C5h, 5              ; ea 0x1400034AE
                db 8                    ; state 3
                db 0F1h, 2              ; ea 0x14000356A
                db 0Ah                  ; state 4
                db 1, 5                 ; ea 0x1400036AA
                db 0                    ; state -1
                db 44h                  ; ea 0x1400036CC
                db 8                    ; state 3
                db 24h                  ; ea 0x1400036DE
                db 2                    ; state 0
                db 22h                  ; ea 0x1400036EF
                db 8                    ; state 3
stru_1400088C8  UNWIND_INFO_HDR <19h, 25h, 9, 0>
                                        ; DATA XREF: .pdata:000000014000B264↓o
                UNWIND_CODE <13h, 34h>  ; UWOP_SAVE_NONVOL
                dw 1Ch
                UNWIND_CODE <13h, 1>    ; UWOP_ALLOC_LARGE
                dw 14h
                UNWIND_CODE <0Ch, 0F0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Ah, 0E0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <8, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 50h>    ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck
                dd 90h
stru_1400088E8  UNWIND_INFO_HDR <19h, 35h, 0Bh, 0>
                                        ; DATA XREF: .pdata:000000014000B270↓o
                UNWIND_CODE <24h, 0E4h> ; UWOP_SAVE_NONVOL
                dw 47h
                UNWIND_CODE <24h, 74h>  ; UWOP_SAVE_NONVOL
                dw 46h
                UNWIND_CODE <24h, 64h>  ; UWOP_SAVE_NONVOL
                dw 45h
                UNWIND_CODE <24h, 34h>  ; UWOP_SAVE_NONVOL
                dw 44h
                UNWIND_CODE <24h, 1>    ; UWOP_ALLOC_LARGE
                dw 42h
                UNWIND_CODE <15h, 50h>  ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck_EH4
                dd rva byte_140008910
                db    2
                db    2
                db    0
                db    0
byte_140008910  db 28h                  ; DATA XREF: .rdata:0000000140008908↑o
                                        ; FuncInfo4
                dd rva byte_140008919   ; unwind map
                dd rva byte_140008956   ; ip2state map
byte_140008919  db 14h                  ; DATA XREF: .rdata:0000000140008911↑o
                                        ; num unwind entries: 10
                db 0Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 32h                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
                db 32h                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 0A1h, 2              ; frame offset of object ptr to be destructed
                db 9Ah                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 0A1h, 2              ; frame offset of object ptr to be destructed
                db 3Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 62h                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 21h, 2               ; frame offset of object ptr to be destructed
                db 3Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
                db 62h                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 40h                  ; frame offset of object ptr to be destructed
                db 32h                  ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 0D0h                 ; frame offset of object ptr to be destructed
                db 0C2h                 ; funclet type: 1
                dd rva sub_140003F70    ; funclet
                db 0D0h                 ; frame offset of object ptr to be destructed
byte_140008956  db 0Eh                  ; DATA XREF: .rdata:0000000140008915↑o
                                        ; num_ip2state entries: 7
                db 2Dh, 5               ; ea 0x140003A8B
                db 0                    ; state -1
                db 2Eh                  ; ea 0x140003AA2
                db 4                    ; state 1
                db 0D2h                 ; ea 0x140003B0B
                db 0Ch                  ; state 5
                db 49h, 3               ; ea 0x140003BDD
                db 10h                  ; state 7
                db 84h                  ; ea 0x140003C1F
                db 14h                  ; state 9
                db 1Dh, 5               ; ea 0x140003D66
                db 0Ch                  ; state 5
                db 0D5h, 3              ; ea 0x140003E5B
                db 0                    ; state -1
                db    0
                db    0
                db    0
stru_14000896C  UNWIND_INFO_HDR <1, 2Eh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B27C↓o
                UNWIND_CODE <2Eh, 64h>  ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <8, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <4, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 50h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_14000897C  UNWIND_INFO_HDR <11h, 6, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B294↓o
                UNWIND_CODE <6, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_14000898C
byte_14000898C  db 28h                  ; DATA XREF: .rdata:0000000140008988↑o
                                        ; FuncInfo4
                dd rva byte_14000846D   ; unwind map
                dd rva byte_140008995   ; ip2state map
byte_140008995  db 2                    ; DATA XREF: .rdata:0000000140008991↑o
                                        ; num_ip2state entries: 1
                db 56h                  ; ea 0x140003FFB
                db 0                    ; state -1
stru_140008998  UNWIND_INFO_HDR <1, 2Eh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B2A0↓o
                UNWIND_CODE <2Eh, 74h>  ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <8, 32h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <4, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 50h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_1400089A8  UNWIND_INFO_HDR <1, 0Ch, 6, 0>
                                        ; DATA XREF: .rdata:00000001400089C0↓o
                                        ; .rdata:00000001400089D4↓o ...
                UNWIND_CODE <0Ch, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <8, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <4, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 50h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_1400089B8  UNWIND_INFO_HDR <21h, 5, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B2B8↓o
                UNWIND_CODE <5, 64h>    ; UWOP_SAVE_NONVOL
                dw 0Dh
                RUNTIME_FUNCTION <rva ResizeAndCopyData, rva loc_14000416B, \
                                  rva stru_1400089A8>
stru_1400089CC  UNWIND_INFO_HDR <21h, 0, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B2C4↓o
                UNWIND_CODE <0, 64h>    ; UWOP_SAVE_NONVOL
                dw 0Dh
                RUNTIME_FUNCTION <rva ResizeAndCopyData, rva loc_14000416B, \
                                  rva stru_1400089A8>
stru_1400089E0  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B2D0↓o
                RUNTIME_FUNCTION <rva ResizeAndCopyData, rva loc_14000416B, \
                                  rva stru_1400089A8>
stru_1400089F0  UNWIND_INFO_HDR <1, 0Ah, 4, 0>
                                        ; DATA XREF: .rdata:0000000140008A04↓o
                                        ; .rdata:0000000140008A14↓o ...
                UNWIND_CODE <0Ah, 64h>  ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <0Ah, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
stru_1400089FC  UNWIND_INFO_HDR <21h, 5, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B2E8↓o
                UNWIND_CODE <5, 34h>    ; UWOP_SAVE_NONVOL
                dw 8
                RUNTIME_FUNCTION <rva CopyDataToMemoryBlock, rva loc_140004263, \
                                  rva stru_1400089F0>
stru_140008A10  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B2F4↓o
                RUNTIME_FUNCTION <rva CopyDataToMemoryBlock, rva loc_140004263, \
                                  rva stru_1400089F0>
stru_140008A20  UNWIND_INFO_HDR <11h, 0Fh, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B30C↓o
                                        ; .pdata:000000014000B4D4↓o
                UNWIND_CODE <0Fh, 72h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 0F0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <9, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 0C0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <4, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 50h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                dd rva __CxxFrameHandler4
                dd rva byte_140008A3C
byte_140008A3C  db 28h                  ; DATA XREF: .rdata:0000000140008A38↑o
                                        ; FuncInfo4
                dd rva byte_140008A45   ; unwind map
                dd rva byte_140008A50   ; ip2state map
byte_140008A45  db 4                    ; DATA XREF: .rdata:0000000140008A3D↑o
                                        ; num unwind entries: 2
                db 0Eh                  ; funclet type: 3
                dd rva loc_140006BF0    ; funclet
                db 2Eh                  ; funclet type: 3
                dd rva __std_terminate  ; funclet
byte_140008A50  db 2                    ; DATA XREF: .rdata:0000000140008A41↑o
                                        ; num_ip2state entries: 1
                db 89h, 3               ; ea 0x1400043C2
                db 2                    ; state 0
stru_140008A54  UNWIND_INFO_HDR <19h, 22h, 7, 0>
                                        ; DATA XREF: .pdata:000000014000B318↓o
                UNWIND_CODE <10h, 34h>  ; UWOP_SAVE_NONVOL
                dw 5Eh
                UNWIND_CODE <10h, 1>    ; UWOP_ALLOC_LARGE
                dw 58h
                UNWIND_CODE <9, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 60h>    ; UWOP_PUSH_NONVOL
                align 4
                dd rva __GSHandlerCheck_EH4
                dd rva byte_140008A74
                db 0B2h
                db    2
                db    0
                db    0
byte_140008A74  db 28h                  ; DATA XREF: .rdata:0000000140008A6C↑o
                                        ; FuncInfo4
                dd rva byte_140008A7D   ; unwind map
                dd rva byte_140008A94   ; ip2state map
byte_140008A7D  db 8                    ; DATA XREF: .rdata:0000000140008A75↑o
                                        ; num unwind entries: 4
                db 0Ah                  ; funclet type: 1
                dd rva unknown_libname_1 ; funclet
                db 60h                  ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva loc_140006C2C    ; funclet
                db 62h                  ; funclet type: 1
                dd rva ResetFileHandleData ; funclet
                db 60h                  ; frame offset of object ptr to be destructed
                db 36h                  ; funclet type: 3
                dd rva unknown_libname_4 ; funclet
byte_140008A94  db 0Ah                  ; DATA XREF: .rdata:0000000140008A79↑o
                                        ; num_ip2state entries: 5
                db 58h                  ; ea 0x14000444C
                db 0                    ; state -1
                db 46h                  ; ea 0x14000446F
                db 4                    ; state 1
                db 70h                  ; ea 0x1400044A7
                db 6                    ; state 2
                db 6Eh                  ; ea 0x1400044DE
                db 8                    ; state 3
                db 81h, 2               ; ea 0x14000457E
                db 0                    ; state -1
stru_140008AA0  UNWIND_INFO_HDR <1, 0Bh, 5, 0>
                                        ; DATA XREF: .rdata:0000000140008AC4↓o
                                        ; .rdata:0000000140008AD4↓o ...
                UNWIND_CODE <0Bh, 42h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <7, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008AB0  UNWIND_INFO_HDR <21h, 51h, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B330↓o
                UNWIND_CODE <51h, 0D4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <49h, 74h>  ; UWOP_SAVE_NONVOL
                dw 0Ch
                UNWIND_CODE <0Eh, 0C4h> ; UWOP_SAVE_NONVOL
                dw 0Dh
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Bh
                RUNTIME_FUNCTION <rva ModifyAndCopyData, rva loc_1400045D0, \
                                  rva stru_140008AA0>
stru_140008AD0  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B33C↓o
                RUNTIME_FUNCTION <rva ModifyAndCopyData, rva loc_1400045D0, \
                                  rva stru_140008AA0>
stru_140008AE0  UNWIND_INFO_HDR <21h, 0, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B348↓o
                UNWIND_CODE <0, 0D4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 0C4h>   ; UWOP_SAVE_NONVOL
                dw 0Dh
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 0Ch
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Bh
                RUNTIME_FUNCTION <rva ModifyAndCopyData, rva loc_1400045D0, \
                                  rva stru_140008AA0>
stru_140008B00  UNWIND_INFO_HDR <1, 0Bh, 5, 0>
                                        ; DATA XREF: .rdata:0000000140008B24↓o
                                        ; .rdata:0000000140008B34↓o ...
                UNWIND_CODE <0Bh, 82h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <7, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 0D0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008B10  UNWIND_INFO_HDR <21h, 54h, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B360↓o
                UNWIND_CODE <54h, 0C4h> ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <4Ch, 74h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <11h, 0E4h> ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <8, 54h>    ; UWOP_SAVE_NONVOL
                dw 10h
                RUNTIME_FUNCTION <rva ModifyAndCopyData_0, rva loc_140004778, \
                                  rva stru_140008B00>
stru_140008B30  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B36C↓o
                RUNTIME_FUNCTION <rva ModifyAndCopyData_0, rva loc_140004778, \
                                  rva stru_140008B00>
stru_140008B40  UNWIND_INFO_HDR <21h, 0, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B378↓o
                UNWIND_CODE <0, 0E4h>   ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <0, 0C4h>   ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 10h
                RUNTIME_FUNCTION <rva ModifyAndCopyData_0, rva loc_140004778, \
                                  rva stru_140008B00>
stru_140008B60  UNWIND_INFO_HDR <1, 9, 4, 0>
                                        ; DATA XREF: .rdata:0000000140008B7C↓o
                                        ; .rdata:0000000140008B98↓o ...
                UNWIND_CODE <9, 52h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <5, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_140008B6C  UNWIND_INFO_HDR <21h, 45h, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B390↓o
                UNWIND_CODE <45h, 74h>  ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0Eh, 0F4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Ch
                RUNTIME_FUNCTION <rva sub_140004910, rva loc_140004939, \
                                  rva stru_140008B60>
stru_140008B88  UNWIND_INFO_HDR <21h, 0, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B39C↓o
                UNWIND_CODE <0, 0F4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Ch
                RUNTIME_FUNCTION <rva sub_140004910, rva loc_140004939, \
                                  rva stru_140008B60>
stru_140008BA4  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B3A8↓o
                RUNTIME_FUNCTION <rva sub_140004910, rva loc_140004939, \
                                  rva stru_140008B60>
stru_140008BB4  UNWIND_INFO_HDR <1, 0Bh, 5, 0>
                                        ; DATA XREF: .rdata:0000000140008BD4↓o
                                        ; .rdata:0000000140008BF0↓o ...
                UNWIND_CODE <0Bh, 62h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <7, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008BC4  UNWIND_INFO_HDR <21h, 41h, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B3C0↓o
                UNWIND_CODE <41h, 0C4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <39h, 74h>  ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 6
                RUNTIME_FUNCTION <rva AllocateAndCopyStringToStruct, \
                                  rva loc_140004A8B, rva stru_140008BB4>
stru_140008BE0  UNWIND_INFO_HDR <21h, 0, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B3CC↓o
                                        ; .pdata:000000014000B3E4↓o
                UNWIND_CODE <0, 0C4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 6
                RUNTIME_FUNCTION <rva AllocateAndCopyStringToStruct, \
                                  rva loc_140004A8B, rva stru_140008BB4>
stru_140008BFC  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B3D8↓o
                RUNTIME_FUNCTION <rva AllocateAndCopyStringToStruct, \
                                  rva loc_140004A8B, rva stru_140008BB4>
stru_140008C0C  UNWIND_INFO_HDR <1, 0Ch, 5, 0>
                                        ; DATA XREF: .rdata:0000000140008C30↓o
                                        ; .rdata:0000000140008C40↓o ...
                UNWIND_CODE <0Ch, 62h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <8, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <6, 0E0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <4, 0C0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 70h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008C1C  UNWIND_INFO_HDR <21h, 51h, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B3FC↓o
                UNWIND_CODE <51h, 0D4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <49h, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Eh
                UNWIND_CODE <0Eh, 64h>  ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 6
                RUNTIME_FUNCTION <rva ExtendAndCopyString_0, rva loc_140004BEF, \
                                  rva stru_140008C0C>
stru_140008C3C  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B408↓o
                RUNTIME_FUNCTION <rva ExtendAndCopyString_0, rva loc_140004BEF, \
                                  rva stru_140008C0C>
stru_140008C4C  UNWIND_INFO_HDR <21h, 0, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B414↓o
                UNWIND_CODE <0, 0D4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 64h>    ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <0, 34h>    ; UWOP_SAVE_NONVOL
                dw 0Eh
                RUNTIME_FUNCTION <rva ExtendAndCopyString_0, rva loc_140004BEF, \
                                  rva stru_140008C0C>
stru_140008C6C  UNWIND_INFO_HDR <21h, 45h, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B42C↓o
                UNWIND_CODE <45h, 74h>  ; UWOP_SAVE_NONVOL
                dw 0Ch
                UNWIND_CODE <0Eh, 0C4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Bh
                RUNTIME_FUNCTION <rva ExtendAndCopyStringWithChar, rva loc_140004DB0, \
                                  rva stru_140008AA0>
stru_140008C88  UNWIND_INFO_HDR <21h, 0, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B438↓o
                UNWIND_CODE <0, 0C4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 0Ch
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Bh
                RUNTIME_FUNCTION <rva ExtendAndCopyStringWithChar, rva loc_140004DB0, \
                                  rva stru_140008AA0>
stru_140008CA4  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B444↓o
                RUNTIME_FUNCTION <rva ExtendAndCopyStringWithChar, rva loc_140004DB0, \
                                  rva stru_140008AA0>
stru_140008CB4  UNWIND_INFO_HDR <1, 0Bh, 5, 0>
                                        ; DATA XREF: .rdata:0000000140008CD8↓o
                                        ; .rdata:0000000140008CF8↓o ...
                UNWIND_CODE <0Bh, 62h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <7, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 0C0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008CC4  UNWIND_INFO_HDR <21h, 4Eh, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B45C↓o
                UNWIND_CODE <4Eh, 0E4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <45h, 74h>  ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <11h, 0D4h> ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Eh
                RUNTIME_FUNCTION <rva ExtendAndCopyString, rva loc_140004F1E, \
                                  rva stru_140008CB4>
stru_140008CE4  UNWIND_INFO_HDR <21h, 0, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B468↓o
                UNWIND_CODE <0, 0E4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 0D4h>   ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Eh
                RUNTIME_FUNCTION <rva ExtendAndCopyString, rva loc_140004F1E, \
                                  rva stru_140008CB4>
stru_140008D04  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B474↓o
                RUNTIME_FUNCTION <rva ExtendAndCopyString, rva loc_140004F1E, \
                                  rva stru_140008CB4>
stru_140008D14  UNWIND_INFO_HDR <1, 0Dh, 6, 0>
                                        ; DATA XREF: .rdata:0000000140008D34↓o
                                        ; .rdata:0000000140008D50↓o ...
                UNWIND_CODE <0Dh, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <9, 0F0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <7, 0D0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <5, 0C0h>   ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_140008D24  UNWIND_INFO_HDR <21h, 45h, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B48C↓o
                UNWIND_CODE <45h, 74h>  ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <11h, 0E4h> ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <5, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Eh
                RUNTIME_FUNCTION <rva ResizeAndCopyMemoryBlock, rva loc_1400050B8, \
                                  rva stru_140008D14>
stru_140008D40  UNWIND_INFO_HDR <21h, 0, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B498↓o
                UNWIND_CODE <0, 0E4h>   ; UWOP_SAVE_NONVOL
                dw 4
                UNWIND_CODE <0, 74h>    ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0, 54h>    ; UWOP_SAVE_NONVOL
                dw 0Eh
                RUNTIME_FUNCTION <rva ResizeAndCopyMemoryBlock, rva loc_1400050B8, \
                                  rva stru_140008D14>
stru_140008D5C  UNWIND_INFO_HDR <21h, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B4A4↓o
                RUNTIME_FUNCTION <rva ResizeAndCopyMemoryBlock, rva loc_1400050B8, \
                                  rva stru_140008D14>
stru_140008D6C  UNWIND_INFO_HDR <1, 6, 2, 0>
                                        ; DATA XREF: .pdata:000000014000B4E0↓o
                UNWIND_CODE <6, 72h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_140008D74  UNWIND_INFO_HDR <1, 0Ah, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B54C↓o
                UNWIND_CODE <0Ah, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Ah
                UNWIND_CODE <0Ah, 72h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 70h>    ; UWOP_PUSH_NONVOL
stru_140008D80  UNWIND_INFO_HDR <1, 0Fh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B534↓o
                UNWIND_CODE <0Fh, 64h>  ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0Fh, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
stru_140008D90  UNWIND_INFO_HDR <19h, 23h, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B540↓o
                UNWIND_CODE <15h, 64h>  ; UWOP_SAVE_NONVOL
                dw 13h
                UNWIND_CODE <15h, 34h>  ; UWOP_SAVE_NONVOL
                dw 12h
                UNWIND_CODE <15h, 0B2h> ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Eh, 0E0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Ch, 70h>  ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Bh, 50h>  ; UWOP_PUSH_NONVOL
                dd rva __GSHandlerCheck
                dd 50h
stru_140008DAC  UNWIND_INFO_HDR <1, 14h, 8, 0>
                                        ; DATA XREF: .pdata:000000014000B504↓o
                UNWIND_CODE <14h, 64h>  ; UWOP_SAVE_NONVOL
                dw 10h
                UNWIND_CODE <14h, 54h>  ; UWOP_SAVE_NONVOL
                dw 0Fh
                UNWIND_CODE <14h, 92h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <10h, 0F0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Eh, 0E0h> ; UWOP_PUSH_NONVOL
                UNWIND_CODE <0Ch, 70h>  ; UWOP_PUSH_NONVOL
stru_140008DC0  UNWIND_INFO_HDR <1, 19h, 0Ah, 0>
                                        ; DATA XREF: .pdata:000000014000B510↓o
                UNWIND_CODE <19h, 74h>  ; UWOP_SAVE_NONVOL
                dw 0Fh
                UNWIND_CODE <19h, 64h>  ; UWOP_SAVE_NONVOL
                dw 0Eh
                UNWIND_CODE <19h, 54h>  ; UWOP_SAVE_NONVOL
                dw 0Dh
                UNWIND_CODE <19h, 34h>  ; UWOP_SAVE_NONVOL
                dw 0Ch
                UNWIND_CODE <19h, 92h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <15h, 0E0h> ; UWOP_PUSH_NONVOL
stru_140008DD8  UNWIND_INFO_HDR <1, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B558↓o
stru_140008DDC  UNWIND_INFO_HDR <9, 0Fh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B5A0↓o
                UNWIND_CODE <0Fh, 64h>  ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <0Fh, 52h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
                dd rva __C_specific_handler
                dd 2
                C_SCOPE_TABLE <rva loc_140005CD5, rva $LN18, \ ; int `__scrt_common_main_seh(void)'::`1'::filt$0
                               rva ?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA, \
                               rva $LN18>
                C_SCOPE_TABLE <rva loc_140005E0E, rva loc_140005E20, \ ; int `__scrt_common_main_seh(void)'::`1'::filt$0
                               rva ?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA, \
                               rva $LN18>
stru_140008E14  UNWIND_INFO_HDR <1, 2, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B5C4↓o
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008E1C  UNWIND_INFO_HDR <1, 9, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B5DC↓o
                UNWIND_CODE <9, 62h>    ; UWOP_ALLOC_SMALL
                align 4
stru_140008E24  UNWIND_INFO_HDR <1, 8, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B5E8↓o
                UNWIND_CODE <8, 72h>    ; UWOP_ALLOC_SMALL
                UNWIND_CODE <4, 70h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <3, 60h>    ; UWOP_PUSH_NONVOL
                UNWIND_CODE <2, 30h>    ; UWOP_PUSH_NONVOL
stru_140008E30  UNWIND_INFO_HDR <9, 4, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B624↓o
                UNWIND_CODE <4, 22h>    ; UWOP_ALLOC_SMALL
                align 4
                dd rva __C_specific_handler
                dd 1
                C_SCOPE_TABLE <rva loc_14000618F, rva loc_140006219, \
                               rva __scrt_is_nonwritable_in_current_image$filt$0, \
                               rva loc_140006219>
stru_140008E50  UNWIND_INFO_HDR <1, 2, 1, 0>
                                        ; DATA XREF: .pdata:000000014000B720↓o
                UNWIND_CODE <2, 50h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008E58  UNWIND_INFO_HDR <1, 0Dh, 4, 0>
                                        ; DATA XREF: .pdata:000000014000B660↓o
                UNWIND_CODE <0Dh, 34h>  ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <0Dh, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <6, 50h>    ; UWOP_PUSH_NONVOL
stru_140008E64  UNWIND_INFO_HDR <1, 15h, 5, 0>
                                        ; DATA XREF: .pdata:000000014000B678↓o
                UNWIND_CODE <15h, 34h>  ; UWOP_SAVE_NONVOL
                dw 0BAh
                UNWIND_CODE <15h, 1>    ; UWOP_ALLOC_LARGE
                dw 0B8h
                UNWIND_CODE <6, 50h>    ; UWOP_PUSH_NONVOL
                align 4
stru_140008E74  UNWIND_INFO_HDR <1, 0Fh, 6, 0>
                                        ; DATA XREF: .pdata:000000014000B6B4↓o
                UNWIND_CODE <0Fh, 64h>  ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <0Fh, 34h>  ; UWOP_SAVE_NONVOL
                dw 5
                UNWIND_CODE <0Fh, 12h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <0Bh, 70h>  ; UWOP_PUSH_NONVOL
                align 8
stru_140008E88  UNWIND_INFO_HDR <1, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B6CC↓o
                align 10h
stru_140008E90  UNWIND_INFO_HDR <1, 0, 0, 0>
                                        ; DATA XREF: .pdata:000000014000B6D8↓o
stru_140008E94  UNWIND_INFO_HDR <1, 19h, 0Ah, 0>
                                        ; DATA XREF: .pdata:000000014000B6C0↓o
                UNWIND_CODE <19h, 74h>  ; UWOP_SAVE_NONVOL
                dw 9
                UNWIND_CODE <19h, 64h>  ; UWOP_SAVE_NONVOL
                dw 8
                UNWIND_CODE <19h, 54h>  ; UWOP_SAVE_NONVOL
                dw 7
                UNWIND_CODE <19h, 34h>  ; UWOP_SAVE_NONVOL
                dw 6
                UNWIND_CODE <19h, 32h>  ; UWOP_ALLOC_SMALL
                UNWIND_CODE <15h, 0E0h> ; UWOP_PUSH_NONVOL
                align 10h
; const _ThrowInfo stru_140008EB0
stru_140008EB0  _ThrowInfo <0, 1120h, 0, 8ED0h>
                                        ; DATA XREF: ThrowBadAllocationException+E↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    2
                db    0
                db    0
                db    0
                db  10h
                db  90h
                db    0
                db    0
                db  90h
                db  90h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
; const _ThrowInfo exceptionTypeInfo
exceptionTypeInfo _ThrowInfo <0, 1120h, 0, 8F98h>
                                        ; DATA XREF: ThrowException+25↑o
                                        ; ThrowErrorAndException+27↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0D0h
                db 0A0h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  88h
                db    0
                db    0
                db    0
                db  60h ; `
                db  2Ah ; *
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    3
                db    0
                db    0
                db    0
                db 0C0h
                db  8Fh
                db    0
                db    0
                db  10h
                db  90h
                db    0
                db    0
                db  90h
                db  90h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0A8h
                db 0A0h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  28h ; (
                db    0
                db    0
                db    0
                db  10h
                db  16h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
; const _ThrowInfo stru_140008F78
stru_140008F78  _ThrowInfo <0, 28D0h, 0, 9060h>
                                        ; DATA XREF: HandleAndThrowException+49↑o
                                        ; HandleAndThrowCustomException+50↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  50h ; P
                db  8Fh
                db    0
                db    0
                db  38h ; 8
                db  90h
                db    0
                db    0
                db 0E8h
                db  8Fh
                db    0
                db    0
                db  90h
                db  90h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A1h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  18h
                db    0
                db    0
                db    0
                db  90h
                db  11h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db 0A0h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  18h
                db    0
                db    0
                db    0
                db  30h ; 0
                db  12h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  10h
                db    0
                db    0
                db    0
                db  80h
                db 0A0h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  18h
                db    0
                db    0
                db    0
                db 0D0h
                db  11h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    8
                db 0A1h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  28h ; (
                db    0
                db    0
                db    0
                db  70h ; p
                db  16h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    5
                db    0
                db    0
                db    0
                db    8
                db  8Fh
                db    0
                db    0
                db  50h ; P
                db  8Fh
                db    0
                db    0
                db  38h ; 8
                db  90h
                db    0
                db    0
                db 0E8h
                db  8Fh
                db    0
                db    0
                db  90h
                db  90h
                db  30h ; 0
                db 0A1h
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
                db    0
                db    0
                db    0
                db    0
                db  18h
                db    0
                db    0
                db    0
                db  70h ; p
                db  10h
; const _ThrowInfo pThrowInfo
pThrowInfo      _ThrowInfo <0, 1120h, 0, 8F30h>
                                        ; DATA XREF: ThrowBadArrayLengthException+E↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
__IMPORT_DESCRIPTOR_KERNEL32 dd rva off_1400091F0 ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aKernel32Dll     ; DLL Name
                dd rva Process32Next    ; Import Address Table
__IMPORT_DESCRIPTOR_ADVAPI32 dd rva off_1400091C8 ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aAdvapi32Dll     ; DLL Name
                dd rva SetNamedSecurityInfoW ; Import Address Table
__IMPORT_DESCRIPTOR_MSVCP140 dd rva off_140009328 ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aMsvcp140Dll     ; DLL Name
                dd rva ?_Winerror_map@std@@YAHH@Z ; Import Address Table
__IMPORT_DESCRIPTOR_VCRUNTIME140_1 dd rva off_1400093A8 ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aVcruntime1401D  ; DLL Name
                dd rva __imp___CxxFrameHandler4 ; Import Address Table
__IMPORT_DESCRIPTOR_VCRUNTIME140 dd rva off_140009350 ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aVcruntime140Dl  ; DLL Name
                dd rva __imp_memset     ; Import Address Table
                dd rva off_1400093B8    ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtHea  ; DLL Name
                dd rva __imp__set_new_mode ; Import Address Table
                dd rva off_1400094A8    ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtStd  ; DLL Name
                dd rva __acrt_iob_func  ; Import Address Table
                dd rva off_140009408    ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtRun  ; DLL Name
                dd rva __imp_terminate  ; Import Address Table
                dd rva off_1400093E0    ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtLoc  ; DLL Name
                dd rva ___lc_codepage_func ; Import Address Table
                dd rva off_1400093F8    ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtMat  ; DLL Name
                dd rva __imp___setusermatherr ; Import Address Table
                dd rva off_1400094D0    ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtStr  ; DLL Name
                dd rva __imp_strcmp     ; Import Address Table
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
;
; Import names for ADVAPI32.dll
;
off_1400091C8   dq rva word_1400095F8   ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_ADVAPI32↑o
                dq rva word_1400095E0
                dq rva word_1400095C6
                dq rva word_140009610
                dq 0
;
; Import names for KERNEL32.dll
;
off_1400091F0   dq rva word_140009546   ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_KERNEL32↑o
                dq rva word_140009556
                dq rva word_140009564
                dq rva word_14000952A
                dq rva word_140009586
                dq rva word_140009592
                dq rva word_1400095A8
                dq rva word_14000951C
                dq rva word_140009506
                dq rva word_1400094F6
                dq rva word_140009574
                dq rva word_1400094E0
                dq rva word_140009AD4
                dq rva word_140009AC4
                dq rva word_140009AB0
                dq rva word_140009AA4
                dq rva word_140009A96
                dq rva word_140009A84
                dq rva word_140009AEC
                dq rva word_140009AFE
                dq rva word_140009B0E
                dq rva word_140009CA4
                dq rva word_140009B2E
                dq rva word_140009B44
                dq rva word_140009B5A
                dq rva word_140009C90
                dq rva word_140009C7A
                dq rva word_140009C60
                dq rva word_140009C4A
                dq rva word_140009C34
                dq rva word_140009C1A
                dq rva word_140009BFE
                dq rva word_140009BEA
                dq rva word_140009BD6
                dq rva word_140009BB8
                dq rva word_140009B9C
                dq rva word_140009B88
                dq rva word_140009B6E
                dq 0
;
; Import names for MSVCP140.dll
;
off_140009328   dq rva word_140009654   ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_MSVCP140↑o
                dq rva word_140009632
                dq rva word_140009672
                dq rva word_140009694
                dq 0
;
; Import names for VCRUNTIME140.dll
;
off_140009350   dq rva word_14000977E   ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_VCRUNTIME140↑o
                dq rva word_140009734
                dq rva word_14000971C
                dq rva word_140009CC2
                dq rva word_1400096F2
                dq rva word_1400096D8
                dq rva word_140009CB8
                dq rva word_14000974A
                dq rva word_140009760
                dq rva word_14000970A
                dq 0
;
; Import names for VCRUNTIME140_1.dll
;
off_1400093A8   dq rva word_1400096C2   ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_VCRUNTIME140_1↑o
                dq 0
;
; Import names for api-ms-win-crt-heap-l1-1-0.dll
;
off_1400093B8   dq rva word_14000997A   ; DATA XREF: .rdata:0000000140009138↑o
                dq rva word_140009822
                dq rva word_140009834
                dq rva word_14000982A
                dq 0
;
; Import names for api-ms-win-crt-locale-l1-1-0.dll
;
off_1400093E0   dq rva word_140009800   ; DATA XREF: .rdata:0000000140009174↑o
                dq rva word_140009964
                dq 0
;
; Import names for api-ms-win-crt-math-l1-1-0.dll
;
off_1400093F8   dq rva word_140009862   ; DATA XREF: .rdata:0000000140009188↑o
                dq 0
;
; Import names for api-ms-win-crt-runtime-l1-1-0.dll
;
off_140009408   dq rva word_140009816   ; DATA XREF: .rdata:0000000140009160↑o
                dq rva word_1400099D2
                dq rva word_1400099B6
                dq rva word_14000999A
                dq rva word_140009840
                dq rva word_1400097DA
                dq rva word_14000992C
                dq rva word_140009922
                dq rva word_140009914
                dq rva word_140009906
                dq rva word_140009852
                dq rva word_1400098F0
                dq rva word_1400098E8
                dq rva word_1400098DA
                dq rva word_1400098CE
                dq rva word_1400098AE
                dq rva word_14000988E
                dq rva word_140009876
                dq rva word_140009936
                dq 0
;
; Import names for api-ms-win-crt-stdio-l1-1-0.dll
;
off_1400094A8   dq rva word_1400097AE   ; DATA XREF: .rdata:000000014000914C↑o
                dq rva word_14000998A
                dq rva word_1400097C0
                dq rva word_1400098F8
                dq 0
;
; Import names for api-ms-win-crt-string-l1-1-0.dll
;
off_1400094D0   dq rva word_140009CCC   ; DATA XREF: .rdata:000000014000919C↑o
                dq 0
word_1400094E0  dw 654h                 ; DATA XREF: .rdata:0000000140009248↑o
                db 'WriteProcessMemory',0
                align 2
word_1400094F6  dw 407h                 ; DATA XREF: .rdata:0000000140009238↑o
                db 'Module32Next',0
                align 2
word_140009506  dw 610h                 ; DATA XREF: .rdata:0000000140009230↑o
                db 'WaitForSingleObject',0
word_14000951C  dw 42Eh                 ; DATA XREF: .rdata:0000000140009228↑o
                db 'OpenProcess',0
word_14000952A  dw 10Ch                 ; DATA XREF: .rdata:0000000140009208↑o
                db 'CreateToolhelp32Snapshot',0
                align 2
word_140009546  dw 44Fh                 ; DATA XREF: .rdata:off_1400091F0↑o
                db 'Process32Next',0
word_140009556  dw 94h                  ; DATA XREF: .rdata:00000001400091F8↑o
                db 'CloseHandle',0
word_140009564  dw 3E7h                 ; DATA XREF: .rdata:0000000140009200↑o
                db 'LoadLibraryW',0
                align 4
word_140009574  dw 600h                 ; DATA XREF: .rdata:0000000140009240↑o
                db 'VirtualAllocEx',0
                align 2
word_140009586  dw 3F2h                 ; DATA XREF: .rdata:0000000140009210↑o
                db 'LocalFree',0
word_140009592  dw 0F8h                 ; DATA XREF: .rdata:0000000140009218↑o
                db 'CreateRemoteThread',0
                align 8
word_1400095A8  dw 603h                 ; DATA XREF: .rdata:0000000140009220↑o
                db 'VirtualFreeEx',0
aKernel32Dll    db 'KERNEL32.dll',0     ; DATA XREF: .rdata:00000001400090E0↑o
                align 2
word_1400095C6  dw 83h                  ; DATA XREF: .rdata:00000001400091D8↑o
                db 'ConvertStringSidToSidW',0
                align 20h
word_1400095E0  dw 142h                 ; DATA XREF: .rdata:00000001400091D0↑o
                db 'GetNamedSecurityInfoW',0
word_1400095F8  dw 2D9h                 ; DATA XREF: .rdata:off_1400091C8↑o
                db 'SetNamedSecurityInfoW',0
word_140009610  dw 2CEh                 ; DATA XREF: .rdata:00000001400091E0↑o
                db 'SetEntriesInAclW',0
                align 4
aAdvapi32Dll    db 'ADVAPI32.dll',0     ; DATA XREF: .rdata:00000001400090F4↑o
                align 2
word_140009632  dw 28Fh                 ; DATA XREF: .rdata:0000000140009330↑o
                db '?_Xout_of_range@std@@YAXPEBD@Z',0
                align 4
word_140009654  dw 285h                 ; DATA XREF: .rdata:off_140009328↑o
                db '?_Winerror_map@std@@YAHH@Z',0
                align 2
word_140009672  dw 28Eh                 ; DATA XREF: .rdata:0000000140009338↑o
                db '?_Xlength_error@std@@YAXPEBD@Z',0
                align 4
word_140009694  dw 273h                 ; DATA XREF: .rdata:0000000140009340↑o
                db '?_Syserror_map@std@@YAPEBDH@Z',0
aMsvcp140Dll    db 'MSVCP140.dll',0     ; DATA XREF: .rdata:0000000140009108↑o
                align 2
word_1400096C2  dw 0                    ; DATA XREF: .rdata:off_1400093A8↑o
                db '__CxxFrameHandler4',0
                align 8
word_1400096D8  dw 22h                  ; DATA XREF: .rdata:0000000140009378↑o
                db '__std_exception_destroy',0
word_1400096F2  dw 21h                  ; DATA XREF: .rdata:0000000140009370↑o
                db '__std_exception_copy',0
                align 2
word_14000970A  dw 23h                  ; DATA XREF: .rdata:0000000140009398↑o
                db '__std_terminate',0
word_14000971C  dw 8                    ; DATA XREF: .rdata:0000000140009360↑o
                db '__C_specific_handler',0
                align 4
word_140009734  dw 1                    ; DATA XREF: .rdata:0000000140009358↑o
                db '_CxxThrowException',0
                align 2
word_14000974A  dw 1Bh                  ; DATA XREF: .rdata:0000000140009388↑o
                db '__current_exception',0
word_140009760  dw 1Ch                  ; DATA XREF: .rdata:0000000140009390↑o
                db '__current_exception_context',0
word_14000977E  dw 3Eh                  ; DATA XREF: .rdata:off_140009350↑o
                db 'memset',0
                align 8
aVcruntime1401D db 'VCRUNTIME140_1.dll',0
                                        ; DATA XREF: .rdata:000000014000911C↑o
                align 4
aVcruntime140Dl db 'VCRUNTIME140.dll',0 ; DATA XREF: .rdata:0000000140009130↑o
                align 2
word_1400097AE  dw 0                    ; DATA XREF: .rdata:off_1400094A8↑o
                db '__acrt_iob_func',0
word_1400097C0  dw 3                    ; DATA XREF: .rdata:00000001400094B8↑o
                db '__stdio_common_vfprintf',0
word_1400097DA  dw 39h                  ; DATA XREF: .rdata:0000000140009430↑o
                db '_invalid_parameter_noinfo_noreturn',0
                align 20h
word_140009800  dw 0                    ; DATA XREF: .rdata:off_1400093E0↑o
                db '___lc_codepage_func',0
word_140009816  dw 67h                  ; DATA XREF: .rdata:off_140009408↑o
                db 'terminate',0
word_140009822  dw 18h                  ; DATA XREF: .rdata:00000001400093C0↑o
                db 'free',0
                align 2
word_14000982A  dw 19h                  ; DATA XREF: .rdata:00000001400093D0↑o
                db 'malloc',0
                align 4
word_140009834  dw 8                    ; DATA XREF: .rdata:00000001400093C8↑o
                db '_callnewh',0
word_140009840  dw 40h                  ; DATA XREF: .rdata:0000000140009428↑o
                db '_seh_filter_exe',0
word_140009852  dw 42h                  ; DATA XREF: .rdata:0000000140009458↑o
                db '_set_app_type',0
word_140009862  dw 9                    ; DATA XREF: .rdata:off_1400093F8↑o
                db '__setusermatherr',0
                align 2
word_140009876  dw 19h                  ; DATA XREF: .rdata:0000000140009490↑o
                db '_configure_wide_argv',0
                align 2
word_14000988E  dw 35h                  ; DATA XREF: .rdata:0000000140009488↑o
                db '_initialize_wide_environment',0
                align 2
word_1400098AE  dw 29h                  ; DATA XREF: .rdata:0000000140009480↑o
                db '_get_initial_wide_environment',0
word_1400098CE  dw 36h                  ; DATA XREF: .rdata:0000000140009478↑o
                db '_initterm',0
word_1400098DA  dw 37h                  ; DATA XREF: .rdata:0000000140009470↑o
                db '_initterm_e',0
word_1400098E8  dw 55h                  ; DATA XREF: .rdata:0000000140009468↑o
                db 'exit',0
                align 10h
word_1400098F0  dw 23h                  ; DATA XREF: .rdata:0000000140009460↑o
                db '_exit',0
word_1400098F8  dw 54h                  ; DATA XREF: .rdata:00000001400094C0↑o
                db '_set_fmode',0
                align 2
word_140009906  dw 4                    ; DATA XREF: .rdata:0000000140009450↑o
                db '__p___argc',0
                align 4
word_140009914  dw 6                    ; DATA XREF: .rdata:0000000140009448↑o
                db '__p___wargv',0
word_140009922  dw 16h                  ; DATA XREF: .rdata:0000000140009440↑o
                db '_cexit',0
                align 4
word_14000992C  dw 15h                  ; DATA XREF: .rdata:0000000140009438↑o
                db '_c_exit',0
word_140009936  dw 3Dh                  ; DATA XREF: .rdata:0000000140009498↑o
                db '_register_thread_local_exe_atexit_callback',0
                align 4
word_140009964  dw 8                    ; DATA XREF: .rdata:00000001400093E8↑o
                db '_configthreadlocale',0
word_14000997A  dw 16h                  ; DATA XREF: .rdata:off_1400093B8↑o
                db '_set_new_mode',0
word_14000998A  dw 1                    ; DATA XREF: .rdata:00000001400094B0↑o
                db '__p__commode',0
                align 2
word_14000999A  dw 34h                  ; DATA XREF: .rdata:0000000140009420↑o
                db '_initialize_onexit_table',0
                align 2
word_1400099B6  dw 3Ch                  ; DATA XREF: .rdata:0000000140009418↑o
                db '_register_onexit_function',0
word_1400099D2  dw 1Eh                  ; DATA XREF: .rdata:0000000140009410↑o
                db '_crt_atexit',0
aApiMsWinCrtHea db 'api-ms-win-crt-heap-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:0000000140009144↑o
                align 20h
aApiMsWinCrtStd db 'api-ms-win-crt-stdio-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:0000000140009158↑o
aApiMsWinCrtRun db 'api-ms-win-crt-runtime-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:000000014000916C↑o
aApiMsWinCrtLoc db 'api-ms-win-crt-locale-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:0000000140009180↑o
                align 4
aApiMsWinCrtMat db 'api-ms-win-crt-math-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:0000000140009194↑o
                align 4
word_140009A84  dw 1C0h                 ; DATA XREF: .rdata:0000000140009278↑o
                db 'FormatMessageA',0
                align 2
word_140009A96  dw 0DAh                 ; DATA XREF: .rdata:0000000140009270↑o
                db 'CreateFileW',0
word_140009AA4  dw 18Fh                 ; DATA XREF: .rdata:0000000140009268↑o
                db 'FindClose',0
word_140009AB0  dw 195h                 ; DATA XREF: .rdata:0000000140009260↑o
                db 'FindFirstFileExW',0
                align 4
word_140009AC4  dw 1A6h                 ; DATA XREF: .rdata:0000000140009258↑o
                db 'FindNextFileW',0
word_140009AD4  dw 25Eh                 ; DATA XREF: .rdata:0000000140009250↑o
                db 'GetFileAttributesExW',0
                align 4
word_140009AEC  dw 24h                  ; DATA XREF: .rdata:0000000140009280↑o
                db 'AreFileApisANSI',0
word_140009AFE  dw 27Dh                 ; DATA XREF: .rdata:0000000140009288↑o
                db 'GetLastError',0
                align 2
word_140009B0E  dw 264h                 ; DATA XREF: .rdata:0000000140009290↑o
                db 'GetFileInformationByHandleEx',0
                align 2
word_140009B2E  dw 412h                 ; DATA XREF: .rdata:00000001400092A0↑o
                db 'MultiByteToWideChar',0
word_140009B44  dw 637h                 ; DATA XREF: .rdata:00000001400092A8↑o
                db 'WideCharToMultiByte',0
word_140009B5A  dw 4F5h                 ; DATA XREF: .rdata:00000001400092B0↑o
                db 'RtlCaptureContext',0
word_140009B6E  dw 4FDh                 ; DATA XREF: .rdata:0000000140009318↑o
                db 'RtlLookupFunctionEntry',0
                align 8
word_140009B88  dw 504h                 ; DATA XREF: .rdata:0000000140009310↑o
                db 'RtlVirtualUnwind',0
                align 4
word_140009B9C  dw 5E6h                 ; DATA XREF: .rdata:0000000140009308↑o
                db 'UnhandledExceptionFilter',0
                align 8
word_140009BB8  dw 5A4h                 ; DATA XREF: .rdata:0000000140009300↑o
                db 'SetUnhandledExceptionFilter',0
word_140009BD6  dw 232h                 ; DATA XREF: .rdata:00000001400092F8↑o
                db 'GetCurrentProcess',0
word_140009BEA  dw 5C4h                 ; DATA XREF: .rdata:00000001400092F0↑o
                db 'TerminateProcess',0
                align 2
word_140009BFE  dw 3A8h                 ; DATA XREF: .rdata:00000001400092E8↑o
                db 'IsProcessorFeaturePresent',0
word_140009C1A  dw 470h                 ; DATA XREF: .rdata:00000001400092E0↑o
                db 'QueryPerformanceCounter',0
word_140009C34  dw 233h                 ; DATA XREF: .rdata:00000001400092D8↑o
                db 'GetCurrentProcessId',0
word_140009C4A  dw 237h                 ; DATA XREF: .rdata:00000001400092D0↑o
                db 'GetCurrentThreadId',0
                align 20h
word_140009C60  dw 30Ah                 ; DATA XREF: .rdata:00000001400092C8↑o
                db 'GetSystemTimeAsFileTime',0
word_140009C7A  dw 38Ah                 ; DATA XREF: .rdata:00000001400092C0↑o
                db 'InitializeSListHead',0
word_140009C90  dw 3A0h                 ; DATA XREF: .rdata:00000001400092B8↑o
                db 'IsDebuggerPresent',0
word_140009CA4  dw 295h                 ; DATA XREF: .rdata:0000000140009298↑o
                db 'GetModuleHandleW',0
                align 8
word_140009CB8  dw 3Ch                  ; DATA XREF: .rdata:0000000140009380↑o
                db 'memcpy',0
                align 2
word_140009CC2  dw 3Dh                  ; DATA XREF: .rdata:0000000140009368↑o
                db 'memmove',0
word_140009CCC  dw 86h                  ; DATA XREF: .rdata:off_1400094D0↑o
                db 'strcmp',0
                align 2
aApiMsWinCrtStr db 'api-ms-win-crt-string-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00000001400091A8↑o
                align 400h
_rdata          ends

; Section 3. (virtual address 0000A000)
; Virtual size                  : 000008C8 (   2248.)
; Section size in file          : 00000400 (   1024.)
; Offset to raw data for section: 00009000
; Flags C0000040: Data Readable Writable
; Alignment     : default
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read/Write
_data           segment para public 'DATA' use64
                assume cs:_data
                ;org 14000A000h
; uintptr_t _security_cookie
__security_cookie dq 2B992DDFA232h      ; DATA XREF: HandleExceptionAndCopyData+13↑r
                                        ; sub_1400017B0+A↑r ...
qword_14000A008 dq 0FFFFD466D2205DCDh   ; DATA XREF: __report_gsfailure+B5↑r
                                        ; __security_init_cookie+9F↑w
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
dword_14000A014 dd 1                    ; DATA XREF: __scrt_is_user_matherr_present+2↑r
dword_14000A018 dd 1                    ; DATA XREF: __isa_available_init:loc_14000675A↑w
                                        ; __isa_available_init+109↑w ...
dword_14000A01C dd 2                    ; DATA XREF: __isa_available_init+F8↑w
                                        ; __isa_available_init+115↑w ...
qword_14000A020 dq 80000h               ; DATA XREF: __isa_available_init+66↑w
qword_14000A028 dq 2000000h             ; DATA XREF: __isa_available_init+59↑w
dword_14000A030 dd 1                    ; DATA XREF: __scrt_is_ucrt_dll_in_use+2↑r
                align 8
staticMemoryLocation dq offset off_140007768
                                        ; DATA XREF: InitializeMemoryBlock↑o
                                        ; sub_140001860+18↑o ...
                db    3
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
off_14000A048   dq offset off_140007808 ; DATA XREF: sub_140001860+3F↑o
                                        ; std::make_error_code(std::io_errc)↑o
                db    7
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                dq offset off_1400074B8
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  3Fh ; ?
                db  41h ; A
                db  56h ; V
                db  72h ; r
                db  75h ; u
                db  6Eh ; n
                db  74h ; t
                db  69h ; i
                db  6Dh ; m
                db  65h ; e
                db  5Fh ; _
                db  65h ; e
                db  72h ; r
                db  72h ; r
                db  6Fh ; o
                db  72h ; r
                db  40h ; @
                db  73h ; s
                db  74h ; t
                db  64h ; d
                db  40h ; @
                db  40h ; @
                db    0
                dq offset off_1400074B8
                align 10h
aAvbadAllocStd  db '.?AVbad_alloc@std@@',0
                align 8
                dq offset off_1400074B8
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  3Fh ; ?
                db  41h ; A
                db  56h ; V
                db  73h ; s
                db  79h ; y
                db  73h ; s
                db  74h ; t
                db  65h ; e
                db  6Dh ; m
                db  5Fh ; _
                db  65h ; e
                db  72h ; r
                db  72h ; r
                db  6Fh ; o
                db  72h ; r
                db  40h ; @
                db  73h ; s
                db  74h ; t
                db  64h ; d
                db  40h ; @
                db  40h ; @
                db    0
                db    0
                dq offset off_1400074B8
                align 20h
aAvfilesystemEr db '.?AVfilesystem_error@filesystem@std@@',0
                align 8
                dq offset off_1400074B8
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  3Fh ; ?
                db  41h ; A
                db  56h ; V
                db  5Fh ; _
                db  53h ; S
                db  79h ; y
                db  73h ; s
                db  74h ; t
                db  65h ; e
                db  6Dh ; m
                db  5Fh ; _
                db  65h ; e
                db  72h ; r
                db  72h ; r
                db  6Fh ; o
                db  72h ; r
                db  40h ; @
                db  73h ; s
                db  74h ; t
                db  64h ; d
                db  40h ; @
                db  40h ; @
                db    0
                dq offset off_1400074B8
                align 20h
aAvexceptionStd db '.?AVexception@std@@',0
                align 8
                dq offset off_1400074B8
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  3Fh ; ?
                db  41h ; A
                db  56h ; V
                db  62h ; b
                db  61h ; a
                db  64h ; d
                db  5Fh ; _
                db  61h ; a
                db  72h ; r
                db  72h ; r
                db  61h ; a
                db  79h ; y
                db  5Fh ; _
                db  6Eh ; n
                db  65h ; e
                db  77h ; w
                db  5Fh ; _
                db  6Ch ; l
                db  65h ; e
                db  6Eh ; n
                db  67h ; g
                db  74h ; t
                db  68h ; h
                db  40h ; @
                db  73h ; s
                db  74h ; t
                db  64h ; d
                db  40h ; @
                db  40h ; @
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                dq offset off_1400074B8
                align 20h
aAvtypeInfo     db '.?AVtype_info@@',0
                dq offset off_1400074B8
                align 20h
aAverrorCategor db '.?AVerror_category@std@@',0
                align 20h
                dq offset off_1400074B8
                align 10h
aAvSystemErrorC db '.?AV_System_error_category@std@@',0
                align 8
                dq offset off_1400074B8
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  3Fh ; ?
                db  41h ; A
                db  56h ; V
                db  5Fh ; _
                db  47h ; G
                db  65h ; e
                db  6Eh ; n
                db  65h ; e
                db  72h ; r
                db  69h ; i
                db  63h ; c
                db  5Fh ; _
                db  65h ; e
                db  72h ; r
                db  72h ; r
                db  6Fh ; o
                db  72h ; r
                db  5Fh ; _
                db  63h ; c
                db  61h ; a
                db  74h ; t
                db  65h ; e
                db  67h ; g
                db  6Fh ; o
                db  72h ; r
                db  79h ; y
                db  40h ; @
                db  73h ; s
                db  74h ; t
                db  64h ; d
                db  40h ; @
                db  40h ; @
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                dq offset off_1400074B8
                align 20h
aAvRefCountBase db '.?AV_Ref_count_base@std@@',0
                align 20h
                dq offset off_1400074B8
                align 10h
aAvRefCountObj2 db '.?AV?$_Ref_count_obj2@U_Dir_enum_impl@filesystem@std@@@std@@',0
                align 10h
dword_14000A2D0 dd 0                    ; DATA XREF: __report_gsfailure+61↑w
                                        ; .rdata:ExceptionInfo↑o
dword_14000A2D4 dd 0                    ; DATA XREF: __report_gsfailure+6B↑w
                align 20h
qword_14000A2E0 dq 0                    ; DATA XREF: __report_gsfailure+4E↑w
dword_14000A2E8 dd 0                    ; DATA XREF: __report_gsfailure+75↑w
                align 10h
unk_14000A2F0   db    0                 ; DATA XREF: __report_gsfailure+88↑o
; struct _CONTEXT ContextRecord
ContextRecord   _CONTEXT <?>            ; DATA XREF: __report_gsfailure:loc_140005F0B↑o
                                        ; .rdata:ExceptionInfo↑o
dword_14000A840 dd ?                    ; DATA XREF: __scrt_common_main_seh(void)+30↑r
                                        ; __scrt_common_main_seh(void)+43↑w ...
                align 8
qword_14000A848 dq ?                    ; DATA XREF: __scrt_acquire_startup_lock+23↑w
                                        ; __scrt_release_startup_lock+17↑w
byte_14000A850  db ?                    ; DATA XREF: __scrt_initialize_crt+6↑r
                                        ; __scrt_initialize_crt+17↑w ...
byte_14000A851  db ?                    ; DATA XREF: __scrt_initialize_onexit_tables+6↑r
                                        ; __scrt_initialize_onexit_tables:loc_14000616D↑w
                align 8
; _onexit_table_t Table
Table           _onexit_table_t <?>     ; DATA XREF: __scrt_initialize_onexit_tables+23↑o
                                        ; __scrt_initialize_onexit_tables+53↑w ...
; _onexit_table_t stru_14000A870
stru_14000A870  _onexit_table_t <?>     ; DATA XREF: __scrt_initialize_onexit_tables+33↑o
                                        ; __scrt_initialize_onexit_tables+62↑w
                align 10h
; union _SLIST_HEADER stru_14000A890
stru_14000A890  _SLIST_HEADER <?>       ; DATA XREF: sub_140006380↑o
unk_14000A8A0   db    ? ;               ; DATA XREF: sub_140006398↑o
dword_14000A8A8 dd ?                    ; DATA XREF: sub_1400063D8↑w
dword_14000A8AC dd ?                    ; DATA XREF: __isa_available_init:loc_14000670C↑r
                                        ; __isa_available_init+AB↑w ...
unk_14000A8B0   db    ? ;               ; DATA XREF: get_unknown_string↑o
unk_14000A8B8   db    ? ;               ; DATA XREF: sub_1400063D0↑o
unk_14000A8C0   db    ? ;               ; DATA XREF: sub_1400063C8↑o
_data           ends

; Section 4. (virtual address 0000B000)
; Virtual size                  : 0000072C (   1836.)
; Section size in file          : 00000800 (   2048.)
; Offset to raw data for section: 00009400
; Flags 40000040: Data Readable
; Alignment     : default
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read
_pdata          segment para public 'DATA' use64
                assume cs:_pdata
                ;org 14000B000h
ExceptionDir    RUNTIME_FUNCTION <rva PrintFormattedOutputToStdout, \
                                  rva algn_140001062, rva stru_140008398>
                RUNTIME_FUNCTION <rva sub_140001070, rva algn_1400010A3, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_1400010D0, rva algn_140001113, \
                                  rva stru_1400083AC>
                RUNTIME_FUNCTION <rva ThrowBadArrayLengthException, rva sub_140001190,\
                                  rva stru_1400083B8>
                RUNTIME_FUNCTION <rva sub_140001190, rva algn_1400011CD, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_1400011D0, rva algn_14000120D, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva ThrowStringLengthExceededException, \
                                  rva algn_140001222, rva stru_1400083C0>
                RUNTIME_FUNCTION <rva sub_140001230, rva algn_14000126D, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_140001280, rva algn_1400012BF, \
                                  rva stru_1400083C8>
                RUNTIME_FUNCTION <rva HandleExceptionAndCopyData, rva algn_1400014BC, \
                                  rva stru_1400083D0>
                RUNTIME_FUNCTION <rva sub_1400014C0, rva algn_140001503, \
                                  rva stru_1400083AC>
                RUNTIME_FUNCTION <rva ProcessAndCopyData_0, rva algn_1400015C6, \
                                  rva stru_140008418>
                RUNTIME_FUNCTION <rva ThrowException, rva algn_140001607, \
                                  rva stru_140008448>
                RUNTIME_FUNCTION <rva sub_140001610, rva algn_140001668, \
                                  rva stru_1400083AC>
                RUNTIME_FUNCTION <rva sub_140001670, rva algn_1400016BE, \
                                  rva stru_1400083AC>
                RUNTIME_FUNCTION <rva sub_1400016E0, rva algn_140001763, \
                                  rva stru_140008450>
                RUNTIME_FUNCTION <rva ??_G_Iostream_error_category2@std@@UEAAPEAXI@Z, \ ; std::_Iostream_error_category2::`scalar deleting destructor'(uint)
                                  rva algn_140001791, rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_1400017B0, rva algn_140001852, \
                                  rva stru_140008478>
                RUNTIME_FUNCTION <rva sub_140001860, rva algn_1400018D3, \
                                  rva stru_1400084AC>
                RUNTIME_FUNCTION <rva ThrowErrorAndException, rva algn_140001949, \
                                  rva stru_140008448>
                RUNTIME_FUNCTION <rva ExtendAndCopyString_1, rva algn_140001A8C, \
                                  rva stru_1400084C8>
                RUNTIME_FUNCTION <rva ProcessAndCopyData, rva loc_140001C2C, \
                                  rva stru_140008504>
                RUNTIME_FUNCTION <rva loc_140001C2C, rva loc_140001D06, \
                                  rva stru_140008510>
                RUNTIME_FUNCTION <rva loc_140001D06, rva loc_140001D29, \
                                  rva stru_140008534>
                RUNTIME_FUNCTION <rva loc_140001D29, rva loc_140001E49, \
                                  rva stru_140008544>
                RUNTIME_FUNCTION <rva loc_140001E49, rva algn_140001E4F, \
                                  rva stru_140008544>
                RUNTIME_FUNCTION <rva ProcessContent, rva algn_140001EED, \
                                  rva stru_140008568>
                RUNTIME_FUNCTION <rva ComparePaths, rva algn_1400020F4, \
                                  rva stru_140008584>
                RUNTIME_FUNCTION <rva CreatePathFromSegments, rva algn_140002237, \
                                  rva stru_140008594>
                RUNTIME_FUNCTION <rva CopyAndResizeString, rva loc_140002265, \
                                  rva stru_1400085BC>
                RUNTIME_FUNCTION <rva loc_140002265, rva loc_1400022A7, \
                                  rva stru_1400085C4>
                RUNTIME_FUNCTION <rva loc_1400022A7, rva algn_1400022BE, \
                                  rva stru_1400085DC>
                RUNTIME_FUNCTION <rva unknown_libname_1, rva algn_140002322, \ ; Microsoft VisualC v14 64bit runtime
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva HandleAndCopyExceptionData, rva algn_1400023D9, \
                                  rva stru_1400085EC>
                RUNTIME_FUNCTION <rva HandleAndPrepareException, rva sub_140002500, \
                                  rva stru_14000862C>
                RUNTIME_FUNCTION <rva sub_140002510, rva sub_140002780, \
                                  rva stru_140008674>
                RUNTIME_FUNCTION <rva sub_140002780, rva algn_1400028C4, \
                                  rva stru_1400086CC>
                RUNTIME_FUNCTION <rva sub_1400028D0, rva algn_1400029F2, \
                                  rva stru_1400086DC>
                RUNTIME_FUNCTION <rva HandleAndThrowException, rva algn_140002A5B, \
                                  rva stru_1400086E8>
                RUNTIME_FUNCTION <rva sub_140002A60, rva algn_140002AE7, \
                                  rva stru_140008710>
                RUNTIME_FUNCTION <rva HandleAndThrowCustomException, \
                                  rva algn_140002B52, rva stru_140008748>
                RUNTIME_FUNCTION <rva GetFileAttributes, rva algn_140002CC1, \
                                  rva stru_14000876C>
                RUNTIME_FUNCTION <rva OpenAndIterateDirectory, rva algn_140002E26, \
                                  rva stru_14000877C>
                RUNTIME_FUNCTION <rva ProcessAndUpdateData, rva algn_140002F49, \
                                  rva stru_1400087B0>
                RUNTIME_FUNCTION <rva ProcessAndUpdate, rva loc_140003034, \
                                  rva stru_1400087D8>
                RUNTIME_FUNCTION <rva sub_140003040, rva algn_1400030A4, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_1400030B0, rva loc_1400030BF, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva loc_1400030BF, rva loc_1400030F5, \
                                  rva stru_140008814>
                RUNTIME_FUNCTION <rva loc_1400030F5, rva algn_1400030FB, \
                                  rva stru_140008828>
                RUNTIME_FUNCTION <rva IsModuleInProcess, rva ProcessDirectory, \
                                  rva stru_140008838>
                RUNTIME_FUNCTION <rva ProcessDirectory, rva algn_1400036F5, \
                                  rva stru_140008854>
                RUNTIME_FUNCTION <rva PerformRemoteExecution, rva algn_140003938, \
                                  rva stru_1400088C8>
                RUNTIME_FUNCTION <rva main, rva algn_140003E7D, rva stru_1400088E8>
                RUNTIME_FUNCTION <rva CopyAndResizeArray, rva algn_140003F67, \
                                  rva stru_14000896C>
                RUNTIME_FUNCTION <rva sub_140003F70, rva algn_140003FCF, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva InitializeAndCopyByteArray, rva algn_140004009, \
                                  rva stru_14000897C>
                RUNTIME_FUNCTION <rva sub_140004010, rva algn_1400040DE, \
                                  rva stru_140008998>
                RUNTIME_FUNCTION <rva ResizeAndCopyData, rva loc_14000416B, \
                                  rva stru_1400089A8>
                RUNTIME_FUNCTION <rva loc_14000416B, rva loc_14000422A, \
                                  rva stru_1400089B8>
                RUNTIME_FUNCTION <rva loc_14000422A, rva loc_140004237, \
                                  rva stru_1400089CC>
                RUNTIME_FUNCTION <rva loc_140004237, rva algn_14000423D, \
                                  rva stru_1400089E0>
                RUNTIME_FUNCTION <rva CopyDataToMemoryBlock, rva loc_140004263, \
                                  rva stru_1400089F0>
                RUNTIME_FUNCTION <rva loc_140004263, rva loc_1400042A2, \
                                  rva stru_1400089FC>
                RUNTIME_FUNCTION <rva loc_1400042A2, rva HandleInvalidStringPosition, \
                                  rva stru_140008A10>
                RUNTIME_FUNCTION <rva HandleInvalidStringPosition, rva algn_1400042D2,\
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva sub_1400042E0, rva algn_140004416, \
                                  rva stru_140008A20>
                RUNTIME_FUNCTION <rva ProcessFiles, rva algn_140004597, \
                                  rva stru_140008A54>
                RUNTIME_FUNCTION <rva ModifyAndCopyData, rva loc_1400045D0, \
                                  rva stru_140008AA0>
                RUNTIME_FUNCTION <rva loc_1400045D0, rva loc_140004729, \
                                  rva stru_140008AB0>
                RUNTIME_FUNCTION <rva loc_140004729, rva loc_14000472F, \
                                  rva stru_140008AD0>
                RUNTIME_FUNCTION <rva loc_14000472F, rva algn_140004735, \
                                  rva stru_140008AE0>
                RUNTIME_FUNCTION <rva ModifyAndCopyData_0, rva loc_140004778, \
                                  rva stru_140008B00>
                RUNTIME_FUNCTION <rva loc_140004778, rva loc_1400048F9, \
                                  rva stru_140008B10>
                RUNTIME_FUNCTION <rva loc_1400048F9, rva loc_1400048FF, \
                                  rva stru_140008B30>
                RUNTIME_FUNCTION <rva loc_1400048FF, rva algn_140004905, \
                                  rva stru_140008B40>
                RUNTIME_FUNCTION <rva sub_140004910, rva loc_140004939, \
                                  rva stru_140008B60>
                RUNTIME_FUNCTION <rva loc_140004939, rva loc_140004A4B, \
                                  rva stru_140008B6C>
                RUNTIME_FUNCTION <rva loc_140004A4B, rva loc_140004A51, \
                                  rva stru_140008B88>
                RUNTIME_FUNCTION <rva loc_140004A51, rva algn_140004A57, \
                                  rva stru_140008BA4>
                RUNTIME_FUNCTION <rva AllocateAndCopyStringToStruct, \
                                  rva loc_140004A8B, rva stru_140008BB4>
                RUNTIME_FUNCTION <rva loc_140004A8B, rva loc_140004BAB, \
                                  rva stru_140008BC4>
                RUNTIME_FUNCTION <rva loc_140004BAB, rva loc_140004BB2, \
                                  rva stru_140008BE0>
                RUNTIME_FUNCTION <rva loc_140004BB2, rva loc_140004BB8, \
                                  rva stru_140008BFC>
                RUNTIME_FUNCTION <rva loc_140004BB8, rva algn_140004BBE, \
                                  rva stru_140008BE0>
                RUNTIME_FUNCTION <rva ExtendAndCopyString_0, rva loc_140004BEF, \
                                  rva stru_140008C0C>
                RUNTIME_FUNCTION <rva loc_140004BEF, rva loc_140004D6A, \
                                  rva stru_140008C1C>
                RUNTIME_FUNCTION <rva loc_140004D6A, rva loc_140004D70, \
                                  rva stru_140008C3C>
                RUNTIME_FUNCTION <rva loc_140004D70, rva algn_140004D76, \
                                  rva stru_140008C4C>
                RUNTIME_FUNCTION <rva ExtendAndCopyStringWithChar, rva loc_140004DB0, \
                                  rva stru_140008AA0>
                RUNTIME_FUNCTION <rva loc_140004DB0, rva loc_140004ED7, \
                                  rva stru_140008C6C>
                RUNTIME_FUNCTION <rva loc_140004ED7, rva loc_140004EDD, \
                                  rva stru_140008C88>
                RUNTIME_FUNCTION <rva loc_140004EDD, rva algn_140004EE3, \
                                  rva stru_140008CA4>
                RUNTIME_FUNCTION <rva ExtendAndCopyString, rva loc_140004F1E, \
                                  rva stru_140008CB4>
                RUNTIME_FUNCTION <rva loc_140004F1E, rva loc_14000506B, \
                                  rva stru_140008CC4>
                RUNTIME_FUNCTION <rva loc_14000506B, rva loc_140005071, \
                                  rva stru_140008CE4>
                RUNTIME_FUNCTION <rva loc_140005071, rva algn_140005077, \
                                  rva stru_140008D04>
                RUNTIME_FUNCTION <rva ResizeAndCopyMemoryBlock, rva loc_1400050B8, \
                                  rva stru_140008D14>
                RUNTIME_FUNCTION <rva loc_1400050B8, rva loc_1400051FB, \
                                  rva stru_140008D24>
                RUNTIME_FUNCTION <rva loc_1400051FB, rva loc_140005201, \
                                  rva stru_140008D40>
                RUNTIME_FUNCTION <rva loc_140005201, rva algn_140005207, \
                                  rva stru_140008D5C>
                RUNTIME_FUNCTION <rva ResetFileHandleData, rva algn_14000527B, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_1400052A0, rva algn_14000530D, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva sub_140005310, rva algn_14000533B, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva ConvertAndCopyWideToNarrow, rva algn_140005476, \
                                  rva stru_140008A20>
                RUNTIME_FUNCTION <rva __std_system_error_allocate_message, \
                                  rva algn_1400054D6, rva stru_140008D6C>
                RUNTIME_FUNCTION <rva __std_fs_code_page, rva algn_140005507, \
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __std_fs_convert_narrow_to_wide, \
                                  rva algn_14000554D, rva stru_1400083B8>
                RUNTIME_FUNCTION <rva __std_fs_convert_wide_to_narrow, \
                                  rva algn_140005671, rva stru_140008DAC>
                RUNTIME_FUNCTION <rva __std_fs_convert_wide_to_narrow_replace_chars, \
                                  rva algn_14000573F, rva stru_140008DC0>
                RUNTIME_FUNCTION <rva FindNextFileInfo, rva CloseFileHandleAndCheck, \
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva CloseFileHandleAndCheck, \
                                  rva __std_fs_directory_iterator_open, \
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __std_fs_directory_iterator_open, \
                                  rva __std_fs_get_stats, rva stru_140008D80>
                RUNTIME_FUNCTION <rva __std_fs_get_stats, rva algn_140005ABA, \
                                  rva stru_140008D90>
                RUNTIME_FUNCTION <rva __std_fs_open_handle, rva byte_140005B13, \
                                  rva stru_140008D74>
                RUNTIME_FUNCTION <rva __security_check_cookie, rva algn_140005B4E, \
                                  rva stru_140008DD8>
                RUNTIME_FUNCTION <rva ??2@YAPEAX_K@Z, rva j_free, rva stru_1400083A4> ; operator new(unsigned __int64)
                RUNTIME_FUNCTION <rva sub_140005B9C, rva algn_140005BC7, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva ?pre_c_initialization@@YAHXZ, \ ; pre_c_initialization(void)
                                  rva algn_140005C7E, rva stru_1400083A4>
                RUNTIME_FUNCTION <rva ?post_pgo_initialization@@YAHXZ, \ ; post_pgo_initialization(void)
                                  rva ?pre_cpp_initialization@@YAXXZ, \ ; pre_cpp_initialization(void)
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva ?pre_cpp_initialization@@YAXXZ, \ ; pre_cpp_initialization(void)
                                  rva algn_140005CA9, rva stru_1400083C0>
                RUNTIME_FUNCTION <rva ?__scrt_common_main_seh@@YAHXZ, rva start, \ ; __scrt_common_main_seh(void)
                                  rva stru_140008DDC>
                RUNTIME_FUNCTION <rva start, rva algn_140005E3A, rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __GSHandlerCheck, rva algn_140005E59, \
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __GSHandlerCheckCommon, rva algn_140005EB7, \
                                  rva stru_140008E14>
                RUNTIME_FUNCTION <rva __raise_securityfailure, rva __report_gsfailure,\
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva __report_gsfailure, rva algn_140005FBE, \
                                  rva stru_140008E1C>
                RUNTIME_FUNCTION <rva capture_previous_context, rva algn_140006031, \
                                  rva stru_140008E24>
                RUNTIME_FUNCTION <rva ThrowBadAllocationException, \
                                  rva __scrt_acquire_startup_lock, rva stru_1400083B8>
                RUNTIME_FUNCTION <rva __scrt_acquire_startup_lock, rva algn_1400060AD,\
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __scrt_initialize_crt, rva algn_1400060F9, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva __scrt_initialize_onexit_tables, \
                                  rva algn_140006187, rva stru_1400083A4>
                RUNTIME_FUNCTION <rva __scrt_is_nonwritable_in_current_image, \
                                  rva __scrt_release_startup_lock, rva stru_140008E30>
                RUNTIME_FUNCTION <rva __scrt_release_startup_lock, \
                                  rva __scrt_uninitialize_crt, rva stru_1400083A4>
                RUNTIME_FUNCTION <rva __scrt_uninitialize_crt, rva algn_14000626D, \
                                  rva stru_1400083A4>
                RUNTIME_FUNCTION <rva _onexit, rva algn_1400062AA, rva stru_1400083A4>
                RUNTIME_FUNCTION <rva atexit, rva algn_1400062C3, rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __security_init_cookie, \ ; charNode::raw_length(void)
                                  rva ?raw_length@charNode@@UEBAHXZ, \
                                  rva stru_140008E58>
                RUNTIME_FUNCTION <rva __scrt_initialize_default_local_stdio_options, \
                                  rva algn_1400063BB, rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __scrt_fastfail, rva algn_14000652B, \
                                  rva stru_140008E64>
                RUNTIME_FUNCTION <rva __scrt_is_managed_app, rva algn_140006585, \
                                  rva stru_1400083C0>
                RUNTIME_FUNCTION <rva __scrt_unhandled_exception_filter, \
                                  rva algn_1400065F3, rva stru_1400083AC>
                RUNTIME_FUNCTION <rva sub_1400065F4, rva sub_140006630, \
                                  rva stru_1400083AC>
                RUNTIME_FUNCTION <rva sub_140006630, rva __isa_available_init, \
                                  rva stru_1400083AC>
                RUNTIME_FUNCTION <rva __isa_available_init, \
                                  rva __scrt_is_ucrt_dll_in_use, rva stru_140008E74>
                RUNTIME_FUNCTION <rva __GSHandlerCheck_EH4, rva memcpy, \
                                  rva stru_140008E94>
                RUNTIME_FUNCTION <rva _guard_dispatch_icall_nop, rva algn_1400069A2, \
                                  rva stru_140008E88>
                RUNTIME_FUNCTION <rva _guard_xfg_dispatch_icall_nop, \
                                  rva algn_1400069C6, rva stru_140008E90>
                RUNTIME_FUNCTION <rva loc_140006A10, rva algn_140006A36, \
                                  rva stru_1400084FC>
                RUNTIME_FUNCTION <rva loc_140006AB0, rva unknown_libname_2, \ ; Microsoft VisualC v14 64bit runtime
                                  rva stru_1400084FC>
                RUNTIME_FUNCTION <rva loc_140006BF0, rva algn_140006C16, \
                                  rva stru_1400084FC>
                RUNTIME_FUNCTION <rva unknown_libname_4, \ ; Microsoft VisualC v14 64bit runtime
                                  rva ?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA, \
                                  rva stru_1400084FC>
                RUNTIME_FUNCTION <rva ?filt$0@?0??__scrt_common_main_seh@@YAHXZ@4HA, \ ; int `__scrt_common_main_seh(void)'::`1'::filt$0
                                  rva __scrt_is_nonwritable_in_current_image$filt$0, \
                                  rva stru_1400084FC>
                RUNTIME_FUNCTION <rva __scrt_is_nonwritable_in_current_image$filt$0, \
                                  rva algn_140006C9B, rva stru_140008E50>
                align 1000h
_pdata          ends


                end start
