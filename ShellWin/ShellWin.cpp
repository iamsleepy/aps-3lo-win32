// ShellWin.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "ShellWin.h"

#include <cstdio>

// Use process api
#include <Psapi.h>
#include <shellapi.h>

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Mutex name
LPCWSTR myMutexName = L"APSAuthShell";

// Define struct for enumerate windows
struct EnumData {
    DWORD dwProcessId;
    HWND hWnd;
};

// Calling address after adding client id.
TCHAR authAddress[1024];

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);



// Application-defined callback for EnumWindows
BOOL CALLBACK EnumProc(HWND hWnd, LPARAM lParam) {
    // Retrieve storage location for communication data
    EnumData& ed = *(EnumData*)lParam;
    DWORD dwProcessId = 0x0;
    // Query process ID for hWnd
    GetWindowThreadProcessId(hWnd, &dwProcessId);
    // Apply filter - if you want to implement additional restrictions,
    // this is the place to do so.
    if (ed.dwProcessId == dwProcessId) {
        // Found a window matching the process ID
        ed.hWnd = hWnd;
        // Report success
        SetLastError(ERROR_SUCCESS);
        // Stop enumeration
        return FALSE;
    }
    // Continue enumeration
    return TRUE;
}

HWND FindWindowFromProcessId(DWORD dwProcessId) {
    EnumData ed = { dwProcessId };
    if (!EnumWindows(EnumProc, (LPARAM)&ed) &&
        (GetLastError() == ERROR_SUCCESS)) {
        return ed.hWnd;
    }
    return NULL;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Create a mutex for singleton.
    HANDLE mutex = CreateMutex(NULL, false, myMutexName);
    if (WaitForSingleObject(mutex, 1) == WAIT_OBJECT_0)
    {
        LPCWSTR clientIdEnvName = L"APS_CLIENT_ID";
        TCHAR clientID[128];
        if (!GetEnvironmentVariable(clientIdEnvName, clientID, 128 * sizeof(TCHAR)))
        {
            MessageBox(0, L"Please add a valid APS_CLIENT_ID in your system environment", L"Error", MB_OK);
            ExitProcess(1);
            return 0;
        };

        // We are using a format here, %% is escaped char for %.
        // If you are going to hardcode your client id, it should be %20. 
        LPCWSTR authAddressFMT = L"https://developer.api.autodesk.com/authentication/v2/authorize?response_type=code"
            L"&client_id=%s"
            L"&redirect_uri=apsshelldemo://oauth"
            L"&scope=data:read%%20data:create%%20data:write";
        swprintf_s(authAddress, 1024, authAddressFMT, clientID);

        // Initialize global strings
        LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
        LoadStringW(hInstance, IDC_SHELLWIN, szWindowClass, MAX_LOADSTRING);
        MyRegisterClass(hInstance);

        // Perform application initialization:
        if (!InitInstance(hInstance, nCmdShow))
        {
            return FALSE;
        }

        HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_SHELLWIN));

        MSG msg;

        // Main message loop:
        while (GetMessage(&msg, nullptr, 0, 0))
        {
            if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }

        return (int)msg.wParam;
    }
    // We are not the existing instance. Sending received parameter to the existing one through WM_COPYDATA.
    else
    {
        // Initializing COPYDATASTRUCT for WM_COPYDATA
        COPYDATASTRUCT* messageStruct =(COPYDATASTRUCT*) HeapAlloc(GetProcessHeap(), 0, sizeof(COPYDATASTRUCT));
        messageStruct->dwData = 0;
        messageStruct->cbData = wcslen(lpCmdLine)*2 + 2;
        messageStruct->lpData = HeapAlloc(GetProcessHeap(), 0, messageStruct->cbData);
        memcpy(messageStruct->lpData, lpCmdLine, messageStruct->cbData);

        // Get fullpath of current process for comparing against other processes.
        TCHAR szCurrentProcessName[MAX_PATH] = TEXT("");
        DWORD currentProcessId = GetCurrentProcessId();
        HANDLE hCurrProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ,
            FALSE, currentProcessId);
        if (NULL != hCurrProcess)
        {
            HMODULE hMod;
            DWORD cbNeeded;

            if (EnumProcessModules(hCurrProcess, &hMod, sizeof(hMod),
                &cbNeeded))
            {
                GetModuleFileNameEx(hCurrProcess, hMod, szCurrentProcessName,
                    sizeof(szCurrentProcessName) / sizeof(TCHAR));
            }
        }
        CloseHandle(hCurrProcess);

        // Find existing instance in all processes.
        DWORD aProcesses[4096], cbNeeded, cProcesses;
        EnumProcesses(aProcesses, cbNeeded, &cbNeeded);
        cProcesses = cbNeeded / sizeof(DWORD);
        
        

        for (size_t i = 0; i < cProcesses; ++i)
        {
            // Skip 0 and current process
            if (!aProcesses[i] || aProcesses[i] == currentProcessId)
                continue;
            DWORD processID = aProcesses[i];
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                PROCESS_VM_READ,
                FALSE, processID);
            if (NULL != hProcess)
            {
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
                    &cbNeeded))
                {
                    GetModuleFileNameEx(hProcess, hMod, szProcessName,
                        sizeof(szProcessName) / sizeof(TCHAR));
                }

                // Let's compare the process full path.
                // If you are calling to a different binary, you can create your own message or construct a user message.
                // If there isn't a window, pipe is another way to do that.
                if (wcscmp(szProcessName, szCurrentProcessName) == 0) {
                    // Find the main window through EnumWindows
                    HWND targetWindow = FindWindowFromProcessId(processID);
                    if (NULL != targetWindow)
                    {
                        SendMessage(targetWindow, WM_COPYDATA, 0, (LPARAM)messageStruct);
                    }
                }

            }
            CloseHandle(hProcess);
        }
        
        HeapFree(GetProcessHeap(), 0, messageStruct->lpData);
        HeapFree(GetProcessHeap(), 0, messageStruct);
        return 0;
    }
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SHELLWIN));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_SHELLWIN);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            case ID_FILE_DOAUTH:
                // Use shell api to open the address, windows will use the default browser.
                ShellExecute(hWnd, L"open", authAddress, 0, 0, 0);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    // Receive the authcode through an application launched with apsshelldemo launcher. 
    case WM_COPYDATA:
	    {
	        PCOPYDATASTRUCT data = (PCOPYDATASTRUCT)lParam;
	        MessageBox(NULL, (LPCWSTR)data->lpData, L"Receiving", MB_OK);
	        break;
	    }
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
