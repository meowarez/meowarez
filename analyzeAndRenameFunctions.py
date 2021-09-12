'''
    IDA Python version of AGDCservices Preview_Function_Capabilities.py
'''

import idautils
import idaapi
import idc

import re
import collections

def main():
    print('{:s}\n{:s}'.format('=' * 100, 'Function_Preview Script Starting'))

    listFunctions = list()

    # Get list of all functions
    for funcEA in idautils.Functions():
        funcName = idc.get_func_name(funcEA)
        if idc.get_func_name(funcEA).startswith('sub_'):
            flags = idc.get_func_flags(funcEA)
            if not (flags & idaapi.FUNC_THUNK):
                listFunctions.append(funcEA)



    # Get parent nodes
    parentNodes = set()
    for funcEA in listFunctions:
        parentNodes.update(CodeRefsTo(funcEA, True))

    # Get leaf nodes
    leafNodes = list()
    for funcEA in listFunctions:
        if funcEA not in parentNodes:
            leafNodes.append(funcEA)


    while True:
        nodesTraversed = set()
        funcRenamedCount = 0
        curNodes = leafNodes[:]

        while True:

            parentNodes = set()
            for curFunc in curNodes:

                oldFuncName = idc.get_func_name(curFunc)
                newFuncName = renameFunction(curFunc)
                idaapi.set_name(curFunc, newFuncName, idaapi.SN_CHECK)
                if oldFuncName != idc.get_func_name(curFunc):
                    funcRenamedCount += 1

                # Track visited
                nodesTraversed.add(curFunc)

                # Get current parents, but only if they're in list of desired functions
                curParentNodes = set(CodeRefsTo(curFunc, True))
                parentNodes.update(curParentNodes & set(listFunctions))

                # Remove visited
                parentNodes = parentNodes - nodesTraversed

            #
            # for currentFunc in listCurrentNodes:

            if len(parentNodes) == 0:
                break

            curNodes = parentNodes.copy()

        #
        # while True


        #
        # TODO: Why does correcting this cause an infinite loop???
        #
        #if funcRenamedCount == 0:
        if funcRenamedCountxxxxxxxxxxxx == 0: 
            break

    #
    # while True

    print('{:s}\n{:s}'.format('Function_Preview Script Completed', '=' * 100))

def renameFunction(funcEA):

    '''
    function will return a string for naming functionality based on desired
    functionality found
    functionality is split into categories.  Each category has a
    single identifier to indicate a generic capability for that category
    e.g. netwCSR = network category, connect, send, and receive capabilities
    '''

    # use ordered dictionary so that categories are always printed
    # in the same order
    categoryNomenclatureDict = collections.OrderedDict()
    categoryNomenclatureDict['netw'] = ['b','c','l','s','r','t','m']
    categoryNomenclatureDict['reg'] = ['h','r','w','d']
    categoryNomenclatureDict['file'] = ['h','r','w','d','c','m','e']
    categoryNomenclatureDict['proc'] = ['h','e','c','t','r','w']
    categoryNomenclatureDict['serv'] = ['h','c','d','s','r','w']
    categoryNomenclatureDict['thread'] = ['c','o','s','r']
    categoryNomenclatureDict['str'] = ['c']



    # for dictionary, list only the basenames, leave off prefixes of '_'
    # and any suffix such as Ex, ExA, etc.  These will be stripped from
    # the functions calleed to account for all variations
    apiPurposeDict = {
        'socket':'netwB',

        #WSAStartup':'netwC',
        'connect':'netwC',
        'InternetOpen':'netwC',
        'InternetConnect':'netwC',
        'InternetOpenURL':'netwC',
        'HttpOpenRequest':'netwC',
        'WinHttpConnect':'netwC',
        'WinHttpOpenRequest':'netwC',

        'bind':'netwL',
        'listen':'netwL',
        'accept':'netwL',

        'send':'netwS',
        'sendto':'netwS',
        'InternetWriteFile':'netwS',
        'HttpSendRequest':'netwS',
        'WSASend':'netwS',
        'WSASendTo':'netwS',
        'WinHttpSendRequest':'netwS',
        'WinHttpWriteData':'netwS',

        'recv':'netwR',
        'recvfrom':'netwR',
        'InternetReadFile':'netwR',
        'HttpReceiveHttpRequest':'netwR',
        'WSARecv':'netwR',
        'WSARecvFrom':'netwR',
        'WinHttpReceiveResponse':'netwR',
        'WinHttpReadData':'netwR',
        'URLDownloadToFile':'netwR',

        'inet_addr':'netwM',
        'htons':'netwM',
        'htonl':'netwM',
        'ntohs':'netwM',
        'ntohl':'netwM',

        # to common due to error conditions
        # basically becomes background noise
        #
        #'closesocket':'netwT',
        #'shutdown':'netwT',


        'RegOpenKey':'regH',

        'RegQueryValue':'regR',
        'RegGetValue':'regR',
        'RegEnumValue':'regR',

        'RegSetValue':'regW',
        'RegSetKeyValue':'regW',

        'RegDeleteValue':'regD',
        'RegDeleteKey':'regD',
        'RegDeleteKeyValue':'regD',

        'RegCreateKey':'regC',

        'CreateFile':'fileH',
        'fopen':'fileH',

        'fscan':'fileR',
        'fgetc':'fileR',
        'fgets':'fileR',
        'fread':'fileR',
        'ReadFile':'fileR',

        'flushfilebuffers':'fileW',
        'fprintf':'fileW',
        'fputc':'fileW',
        'fputs':'fileW',
        'fwrite':'fileW',
        'WriteFile':'fileW',

        'DeleteFile':'fileD',

        'CopyFile':'fileC',

        'MoveFile':'fileM',

        'FindFirstFile':'fileE',
        'FindNextFile':'fileE',

        'strcmp':'strC',
        'strncmp':'strC',
        'stricmp':'strC',
        'wcsicmp':'strC',
        'mbsicmp':'strC',
        'lstrcmp':'strC',
        'lstrcmpi':'strC',

        'OpenService':'servH',

        'QueryServiceStatus':'servR',
        'QueryServiceConfig':'servR',

        'ChangeServiceConfig':'servW',
        'ChangeServiceConfig2':'servW',

        'CreateService':'servC',

        'DeleteService':'servD',

        'StartService':'servS',

        'CreateToolhelp32Snapshot':'procE',
        'Process32First':'procE',
        'Process32Next':'procE',

        'OpenProcess':'procH',

        'CreateProcess':'procC',
        'CreateProcessAsUser':'procC',
        'CreateProcessWithLogon':'procC',
        'CreateProcessWithToken':'procC',
        'ShellExecute':'procC',

        # to common due to error conditions
        # basically becomes background noise
        #
        #'ExitProcess':'procT',
        #'TerminateProcess':'procT',

        'ReadProcessMemory':'procR',

        'WriteProcessMemory':'procW',

        'CreateThread':'threadC',
        'beginthread':'threadC',
        'beginthreadex':'threadC', # EXCEPTION: include ex because it's lowercase and won't be caught by case-sensitive suffix stripper routine later

        'OpenThread':'threadO',

        'SuspendThread':'threadS',

        'ResumeThread':'threadR',

    }

    oldFuncName = idc.get_func_name(funcEA)
    funcXrefTo = len(list(CodeRefsTo(funcEA, True)))

    # Get all calls in current function
    callList = list()
    dism_addr = list(idautils.FuncItems(funcEA))
    for ea in dism_addr:

        # Check mnenonic for function call
        mnemonic = idc.print_insn_mnem(ea)
        if mnemonic == 'call':
            callList.append(ea)

    # Remove recursive calls
    listRecursiveCalls = list()
    for curCall in callList:

        # Check for register calls
        if idc.get_operand_type(curCall, 0):
            continue

        addrSubFunc = idc.get_operand_value(curCall, 0)

        if addrSubFunc == funcEA:
            listRecursiveCalls.append(addrSubFunc)

    callList = list(set(callList) - set(listRecursiveCalls))

    if len(callList) == 0:
        #
        # TODO: Check if thunk
        #
        #return 'f_p__zc_sub_%x__xref_%d' % (funcEA, funcXrefTo)
        return '{:s}zc_{:s}{:s}__xref_{:02d}'.format('f_p__', 'sub_', funcEA, funcXrefTo)

    apiUsed = set()

    for curCall in callList:
        apiName = idc.print_operand(curCall,0)

        pattern = '^(?:ds:|cs:)?(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:@[a-fA-F0-9]+)?$'
        match = re.search(pattern, apiName)
        apiName = match.group('baseName')

        # add current API name to summary set
        apiUsed.add(apiName)

    # map API's called to functionality to use for naming
    implementedApiPurpose = set()
    for entry in apiUsed:
        implementedApiPurpose.add(apiPurposeDict.get(entry))

    # identify functionality from child functions already renamed by this script
    # this will allow api usage to propagate up to the root function
    childFunctionImplementedApiPurpose = dict()
    for curCall in callList:
        if idc.get_operand_type(curCall, 0) == o_near:
            curApiName = idc.print_operand(curCall,0)
            if curApiName.startswith('f_p__'):
                # pull out api capabilities based on naming convention
                for category in categoryNomenclatureDict:
                    pattern = category + '_' + '([a-zA-Z]+)+_?([a-zA-Z]+)?'
                    match = re.search(pattern, curApiName)

                    # if category is found, save into results
                    if match is not None:
                        apiPurpose = set()
                        if match.group(1) is not None: apiPurpose.update(list(match.group(1).lower()))
                        if match.group(2) is not None: apiPurpose.update(list(match.group(2).lower()))
                        if category in childFunctionImplementedApiPurpose:
                            childFunctionImplementedApiPurpose[category].update(apiPurpose)
                        else:
                            childFunctionImplementedApiPurpose[category] = apiPurpose

    #
    # create function name based on API functionality found
    #

    newFuncNamePurpose = ''

    # for each category, loop through all the nomenclature symbols
    # if the symbol is found in the current function, add it to the parent string
    # if the symbol is found in a child function, add it to child string
    for category in categoryNomenclatureDict:

        # build the symbol list for the parent function
        parentStr = ''
        for symbol in categoryNomenclatureDict[category]:
            if (category + symbol.upper()) in implementedApiPurpose:
                parentStr += symbol.upper()


        # build the symbol list for the child functions
        childStr = ''
        if category in childFunctionImplementedApiPurpose:
            for symbol in categoryNomenclatureDict[category]:
                if symbol.lower() in childFunctionImplementedApiPurpose[category]:
                    childStr += symbol.lower()

        # combine the parent / child symbol list into one final string
        if (len(parentStr) > 0) or (len(childStr) > 0):
            newFuncNamePurpose = newFuncNamePurpose + category
            if len(parentStr) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + parentStr
            if len(childStr) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + childStr
            newFuncNamePurpose = newFuncNamePurpose + '__'

    # build the final function name
    if len(newFuncNamePurpose) > 0:
        # targeted functionality found
        finalFuncName = 'f_p__{:s}xref_{:02d}_{:s}'.format(newFuncNamePurpose, funcXrefTo, idc.get_func_name(funcEA))
    else:
        # no targeted functionality identified
        finalFuncName = 'f_p__sub_{:s}__xref_{:02d}'.format(idc.get_func_name(funcEA), funcXrefTo)

    return finalFuncName



if __name__ == '__main__':
    main()
