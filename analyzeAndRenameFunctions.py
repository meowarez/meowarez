'''
    To Do:
    - Change function name identification to regex
    - Propogate changes up the function tree
    - Categorize APIs
'''

import idautils
import idc

#globalAnalyzedFuncs = list()

listNetworkAPI = ['InternetOpen', 'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile']
listKeyloggingAPI = ['GetAsyncKeyState', 'SetWindowsHookEx']
listResourceAPI = ['FindResourceA', 'LockResource']
listCreateProcessAPI = ['WinExec', 'ShellExecute', 'CreateProcess']
listProcessEnumAPI = ['CreateToolhelp32Snapshot','Process32First','Process32Next']
listInjectionAPI = ['GetProcAddress', 'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
listFileAPI = ['CreateFile', 'WriteFile']
listCryptAPI = ['CryptAcquireContextW', 'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey', 'CryptDecrypt', 'CryptReleaseContext', 'CryptDestroyHash', 'CryptDestroyKey']
listMutexAPI = ['CreateMutex', 'CreateEvent', 'CreateSemaphore', 'CreateNamedPipe']

dictAPItoCode = {
    # Registry - (c)reate, (d)elete, (e)num, (g)et, (o)pen, (q)uery, (s)set
    'RegCreateKey':'REGc',
    'RegDeleteKey':'REGd',
    'RegDeleteKeyValue':'REGd',
    'RegDeleteValue':'REGd',
    'RegEnumValue':'REGe',
    'RegGetValue':'REGg',
    'RegOpenKey':'REGo',
    'RegQueryValue':'REGq',
    'RegSetKeyValue':'REGs',
    'RegSetValue':'REGs',

    # Process - (c)reate, (e)num, (o)pen, (r)ead, (w)rite
    'CreateProcess':'PROCc',
    'CreateProcessAsUser':'PROCc',
    'CreateProcessWithLogon':'PROCc',
    'CreateProcessWithToken':'PROCc',
    'CreateToolhelp32Snapshot':'PROCc',
    'OpenProcess':'PROCo',
    'Process32First':'PROCe',
    'Process32Next':'PROCe',
    'ReadProcessMemory':'PROCr',
    'ShellExecute':'PROCc',
    'WriteProcessMemory':'PROCw',

    # Networking - (c)onnect, (o)pen, (r)eceive, (s)end
    'HttpOpenRequest':'NETo',
    'HttpReceiveHttpRequest':'NETr',
    'HttpSendRequest':'NETs',
    'InternetConnect':'NETc',
    'InternetOpen':'NETo',
    'InternetOpenURL':'NETo',
    'InternetReadFile':'NET',
    'URLDownloadToFile':'NET',
    'WSARecv':'NETr',
    'WSARecvFrom':'NETr',
    'WSASend':'NETs',
    'WSASendTo':'NETs',
    'WSAStartup':'NET',
    'WinHttpConnect':'NETc',
    'WinHttpOpenRequest':'NETo',
    'WinHttpReadData':'NETr',
    'WinHttpReceiveResponse':'NETr',
    'WinHttpSendRequest':'NETs',
    'WinHttpWriteData':'NET',
    'accept':'NET',
    'bind':'NET',
    'connect':'NET',
    'listen':'NET',
    'recv':'NETr',
    'recvfrom':'NETr',
    'send':'NETs',
    'sendto':'NETs',
    'socket':'NET',

    # File - (c)reate, (d)elete, (e)num, (o)pen, (r)ead, (w)rite
    'CopyFile':'FILE',
    'CreateFile':'FILEc',
    'DeleteFile':'FILEd',
    'FindFirstFile':'FILEe',
    'FindNextFile':'FILEe',
    'MoveFile':'FILE',
    'ReadFile':'FILEe',
    'WriteFile':'FILEw',
    'fgetc':'FILE',
    'fgets':'FILE',
    'fopen':'FILEo',
    'fprintf':'FILE',
    'fputc':'FILEw',
    'fputs':'FILEw',
    'fread':'FILEr',
    'fscan':'FILE',
    'fwrite':'FILEw',

    # Service - (c)reate, (d)elete, (o)pen, (q)uery, (s)tart
    'ChangeServiceConfig':'SVC',
    'CreateService':'SVCc',
    'DeleteService':'SVCd',
    'OpenService':'SVCo',
    'QueryServiceConfig':'SVCq',
    'QueryServiceStatus':'SVCq',
    'StartService':'SVCs',

    # Thread - (c)reate, (o)pen
    'CreateThread':'THRDc',
    'OpenThread':'THRDo',
    'ResumeThread':'THRD',
    'SuspendThread':'THRD'

}

def main():

    # Demangle everything first
    #if it starts with '??'
    #idc.demangle_name('Name', get_inf_attr(INF_LONG_DN))


    '''
    ea = idc.get_screen_ea()

    segStart = idc.get_segm_start(ea)
    segEnd = idc.get_segm_end(ea)
    analyzeFunctions(segStart)
    '''
    ea = idaapi.get_func(here())
    analyzeFunctions(ea.start_ea)

def analyzeFunctions(startEA):
    endEA = idaapi.get_func(startEA).end_ea
    #print('Current: %s at 0x%x' % (idc.get_func_name(startEA), startEA))
    #global globalAnalyzedFuncs

    #print('Current Function: %s at 0x%x' % (idc.get_func_name(startEA), startEA))

    listNonLibFuncs = list()
    dictSubFuncNames = dict()

    # Get a list of subfunctions
    dism_addr = list(idautils.FuncItems(startEA))
    for ea in dism_addr:

        # Check mnenonic for function call
        mnemonic = idc.print_insn_mnem(ea)
        if mnemonic == 'call':
            addrSubFunc = idc.get_operand_value(ea, 0)
            nameSubFunc = idc.print_operand(ea,0).replace('ds:','').replace('cs:','')
            dictSubFuncNames[addrSubFunc] = nameSubFunc
            if nameSubFunc.startswith('sub_'):
                listNonLibFuncs.append(addrSubFunc)

    #print(dictSubFuncNames.values())

    # If current function is not a leaf node
    if len(listNonLibFuncs) > 0:
        print('%s at 0x%x not leaf node' % (idc.get_func_name(startEA), startEA))
        print(['0x%x' % (x) for x in listNonLibFuncs])
        # Analyze each subfunction
        for func in listNonLibFuncs:

            funcInfo = idaapi.get_func(func)
            analyzeFunctions(funcInfo.start_ea)

    # Analyze based on function names
    newFuncName = 'f_' + idc.get_func_name(startEA) + "__"

    for funcName in dictSubFuncNames.values():
        # Change to regex
        if funcName.endswith('A') or funcName.endswith('W'):
            funcName = funcName[:-1]
        if funcName.endswith('Ex'):
            funcName = funcName[:-2]
        newFuncName = newFuncName + dictAPItoCode.get(funcName, "")

    '''
    #listNetworkAPI = ['InternetOpen', 'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile']
    if set(listNetworkAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_0'

    #listKeyloggingAPI = ['GetAsyncKeyState', 'SetWindowsHookEx']
    if set(listKeyloggingAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_1'

    #listResourceAPI = ['FindResourceA', 'LockResource']
    if set(listResourceAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_2'

    #listCreateProcessAPI = ['WinExec', 'ShellExecute', 'CreateProcess']
    if set(listCreateProcessAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_3'

    #listProcessEnumAPI = ['CreateToolhelp32Snapshot','Process32First','Process32Next']
    if set(listProcessEnumAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_4'

    #listInjectionAPI = ['GetProcAddress', 'OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
    if set(listInjectionAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_5'

    #listFileAPI = ['CreateFile', 'WriteFile']
    if set(listFileAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_6'

    #listCryptAPI = ['CryptAcquireContextW', 'CryptCreateHash', 'CryptHashData', 'CryptDeriveKey', 'CryptDecrypt', 'CryptReleaseContext', 'CryptDestroyHash', 'CryptDestroyKey']
    if set(listCryptAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_7'

    #listMutexAPI = ['CreateMutex', 'CreateEvent', 'CreateSemaphore', 'CreateNamedPipe']
    if set(listMutexAPI).issubset(dictSubFuncNames.values()):
        newFuncName = newFuncName + '_8'
    '''

    # Rename
    idc.set_name(startEA, newFuncName, SN_CHECK)

#
#-> def analyzeFunctions(startEA):

main()
