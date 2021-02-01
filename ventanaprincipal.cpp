#include "ventanaprincipal.h"
#include "ui_ventanaprincipal.h"
#include <windows.h>
#include <vector>
#include <cstdio>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

typedef enum _SYSTEM_INFORMATION_CLASS     //    Q S
{
    SystemBasicInformation,                // 00 Y N
    SystemProcessorInformation,            // 01 Y N
    SystemPerformanceInformation,          // 02 Y N
    SystemTimeOfDayInformation,            // 03 Y N
    SystemNotImplemented1,                 // 04 Y N
    SystemProcessesAndThreadsInformation,  // 05 Y N
    SystemCallCounts,                      // 06 Y N
    SystemConfigurationInformation,        // 07 Y N
    SystemProcessorTimes,                  // 08 Y N
    SystemGlobalFlag,                      // 09 Y Y
    SystemNotImplemented2,                 // 10 Y N
    SystemModuleInformation,               // 11 Y N
    SystemLockInformation,                 // 12 Y N
    SystemNotImplemented3,                 // 13 Y N
    SystemNotImplemented4,                 // 14 Y N
    SystemNotImplemented5,                 // 15 Y N
    SystemHandleInformation,               // 16 Y N
    SystemObjectInformation,               // 17 Y N
    SystemPagefileInformation,             // 18 Y N
    SystemInstructionEmulationCounts,      // 19 Y N
    SystemInvalidInfoClass1,               // 20
    SystemCacheInformation,                // 21 Y Y
    SystemPoolTagInformation,              // 22 Y N
    SystemProcessorStatistics,             // 23 Y N
    SystemDpcInformation,                  // 24 Y Y
    SystemNotImplemented6,                 // 25 Y N
    SystemLoadImage,                       // 26 N Y
    SystemUnloadImage,                     // 27 N Y
    SystemTimeAdjustment,                  // 28 Y Y
    SystemNotImplemented7,                 // 29 Y N
    SystemNotImplemented8,                 // 30 Y N
    SystemNotImplemented9,                 // 31 Y N
    SystemCrashDumpInformation,            // 32 Y N
    SystemExceptionInformation,            // 33 Y N
    SystemCrashDumpStateInformation,       // 34 Y Y/N
    SystemKernelDebuggerInformation,       // 35 Y N
    SystemContextSwitchInformation,        // 36 Y N
    SystemRegistryQuotaInformation,        // 37 Y Y
    SystemLoadAndCallImage,                // 38 N Y
    SystemPrioritySeparation,              // 39 N Y
    SystemNotImplemented10,                // 40 Y N
    SystemNotImplemented11,                // 41 Y N
    SystemInvalidInfoClass2,               // 42
    SystemInvalidInfoClass3,               // 43
    SystemTimeZoneInformation,             // 44 Y N
    SystemLookasideInformation,            // 45 Y N
    SystemSetTimeSlipEvent,                // 46 N Y
    SystemCreateSession,                   // 47 N Y
    SystemDeleteSession,                   // 48 N Y
    SystemInvalidInfoClass4,               // 49
    SystemRangeStartInformation,           // 50 Y N
    SystemVerifierInformation,             // 51 Y Y
    SystemAddVerifier,                     // 52 N Y
    SystemSessionProcessesInformation      // 53 Y N
} SYSTEM_INFORMATION_CLASS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

enum OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
};

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    LPCTSTR Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
    LPCTSTR TypeName;
    ULONG Reserved[22]; //Reserved
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS, 
    IN OUT PVOID, IN ULONG, OUT PULONG OPTIONAL);

typedef NTSTATUS(WINAPI* ZWQUERYOBJECT)(HANDLE,ULONG,PVOID,ULONG,PULONG);

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        __try {
            if (hToken) {
                CloseHandle(hToken);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {};
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        __try {
            if(hToken) {
                CloseHandle(hToken);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {};
        return false;
    }
    return true;
}

VentanaPrincipal::VentanaPrincipal(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::VentanaPrincipal)
{
    ui->setupUi(this);
    if(!EnableDebugPrivilege()) {
        MessageBox(NULL, L"We cannot get the administrator privilege", L"Error", MB_ICONERROR);
        PostQuitMessage(0);
    }
    connect(ui->actionChoose,&QAction::triggered,this,&VentanaPrincipal::Cambiar);
    connect(ui->pushButton,&QAbstractButton::clicked,this,&VentanaPrincipal::busqLock);
    this->setAcceptDrops(true);
}

void VentanaPrincipal::Cambiar() {
    filetoproc = QFileDialog::getOpenFileName(this, "Choose Locked File", ".",
                 "Executable files (*.exe *.dll *.sys);;All files (*)");
    if (filetoproc.isEmpty()) {
        QMessageBox::warning(this, "Warning!", "You have not chosen your file!");
    } else ui->labeldst->setText(filetoproc);
}

char *w2c(const wchar_t *pwszSrc) {
    int nLen = WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, NULL, 0, NULL, NULL);
    char* pszDst = new char[nLen];
    WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, pszDst, nLen, NULL, NULL);
    return pszDst;
}

NTSTATUS Status;

struct QueryStu {
    HANDLE TargetHandle;
    OBJECT_NAME_INFORMATION NameInfo;
    ZWQUERYOBJECT ZwQueryObject;
    QueryStu(HANDLE a, OBJECT_NAME_INFORMATION b, ZWQUERYOBJECT c) : 
        TargetHandle{ a }, NameInfo{ b }, ZwQueryObject{ c } {}
};

void QueryThread(
    QueryStu *pu
) {
    Status = pu->ZwQueryObject(pu->TargetHandle, ObjectNameInformation, &pu->NameInfo, sizeof(pu->NameInfo), NULL);
}

std::vector<QString> queryTodos(LPCTSTR FileName) {
    std::vector<QString> res;
    PSYSTEM_HANDLE_INFORMATION Information;
    OBJECT_NAME_INFORMATION NameInfo;
    OBJECT_TYPE_INFORMATION TypeInfo;
    ULONG ReturnLength;
    LPCTSTR TargetType = L"";
    HINSTANCE ntdll_dll = GetModuleHandle(L"ntdll.dll");
    if (ntdll_dll == NULL) return res;
    NTQUERYSYSTEMINFORMATION ZwQuerySystemInformation = NULL;
    ZWQUERYOBJECT ZwQueryObject = NULL;
    ZwQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(ntdll_dll, "ZwQuerySystemInformation");
    ZwQueryObject = (ZWQUERYOBJECT)GetProcAddress(ntdll_dll, "NtQueryObject");
    if (ZwQuerySystemInformation == NULL
        || ZwQueryObject == NULL) return res;
    else {
        Status = ZwQuerySystemInformation(SystemHandleInformation,
            Information,
            sizeof(SYSTEM_HANDLE_INFORMATION),
            &ReturnLength);
        for (ULONG i = 0; i < Information->NumberOfHandles; i++) {
            if (Information->Handles[i].UniqueProcessId != GetCurrentProcessId()) {
                USHORT ProcessId = Information->Handles[i].UniqueProcessId;
                HANDLE srcHd = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessId);
                if(srcHd == NULL) {
                    res.clear();
                    return res;
                }
                HANDLE TargetHandle;
                DuplicateHandle(srcHd, (HANDLE)Information->Handles[i].HandleValue, GetCurrentProcess(), &TargetHandle,
                                0, FALSE, DUPLICATE_SAME_ACCESS);
                Status = ZwQueryObject(TargetHandle, ObjectTypeInformation, &TypeInfo, sizeof(TypeInfo), NULL);
                lstrcpy((LPWSTR)TargetType, L"File");
                if(lstrcmp(TypeInfo.TypeName, TargetType) != 0) continue;
                QueryStu pv = QueryStu(TargetHandle, NameInfo, ZwQueryObject);
                HANDLE ThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)QueryThread, &pv, 0, NULL);
                if (ThreadHandle == NULL) {
                    res.clear();
                    return res;
                } else {
                    WaitForSingleObject(ThreadHandle, 1000); //Wait for 1 second before the thread exits.
                    TerminateThread(ThreadHandle, 0);
                    CloseHandle(ThreadHandle);
                }
                if (lstrcmp(NameInfo.Name, FileName) == 0) {
                    QString strfmt;
                    strfmt.asprintf("Found an file occupied by process(%u), Handle value=%d, ProcName=%s", ProcessId, Information->Handles[i].HandleValue, w2c(NameInfo.Name));
                    res.push_back(strfmt);
                }
                if (!NT_SUCCESS(Status)) {
                    res.clear();
                    return res;
                }
            }
        }
    }
    if(res.empty()) res.push_back("NoProc");
    return res;
}

void VentanaPrincipal::busqLock() {
    if(filetoproc.isEmpty()) {
        QMessageBox::warning(this, "Warning!", "You have not chosen your file!");
        return;
    }
    ui->listWidget->clear();
    std::vector<QString> res = queryTodos(filetoproc.toStdWString().c_str());
    if(res.empty()) {
        QMessageBox::critical(this, "Error!", "Query is unsuccessful!");
    } else {
        for(size_t i = 0;i < res.size();i++) ui->listWidget->addItem(res[i]);
    }
}

VentanaPrincipal::~VentanaPrincipal()
{
    delete ui;
}

