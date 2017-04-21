#include <QMessageBox>
#include "ModuleMgr.h"
#include "ProcessMgr.h"
#include "DriverWrapper.h"
#include "nt.h"
#include "util.h"
#include <boost/algorithm/string.hpp>

#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"version.lib")

CModuleMgr *m_ModuleMgr = NULL;

Q_DECLARE_METATYPE(std::wstring)
Q_DECLARE_METATYPE(ULONG)
Q_DECLARE_METATYPE(ULONG64)

CUniqueImage::CUniqueImage(ULONG ImageSize, LPCWSTR szImagePath, bool bIs64Bit, bool bIsSystemModule)
{
    m_ImageSize = ImageSize;
    m_ImagePath = QString::fromWCharArray(szImagePath);
    m_FileName = QString::fromWCharArray(ExtractFileName(szImagePath));
    m_bIs64Bit = bIs64Bit;
    m_bIsSystemModule = bIsSystemModule;
    m_bLoadedSymbol = false;
}

CUniqueModule::CUniqueModule(ULONG64 ImageBase, CUniqueImage *Image)
{
    m_ImageBase = ImageBase;
    m_UniqueImage = Image;
}

BOOL CALLBACK EnumSymCallBack(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
    UNREFERENCED_PARAMETER(SymbolSize);

    CFuncList *funcList = (CFuncList *)UserContext;

    if(pSymInfo->Flags & SYMFLAG_PUBLIC_CODE)
    {
        funcList->emplace_back(
              CNamedFunc(std::string(pSymInfo->Name, pSymInfo->NameLen), pSymInfo->Address-pSymInfo->ModBase)
        );
    }

    return TRUE;
}

BOOL EnumPEExport(PUCHAR pBaseAddress, UINT uSize, CFuncList *funcList)
{
    UNREFERENCED_PARAMETER(uSize);

    ULONG uExportSize = 0;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
	    ImageDirectoryEntryToData(pBaseAddress, FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &uExportSize);
    if (IsBadReadPtr(pImageExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)))
	return FALSE;

    DWORD dwNumberOfNames = pImageExportDirectory->NumberOfNames;
    DWORD *pAddressOfFunction = (DWORD*)ImageRvaToVa(ImageNtHeader(pBaseAddress), pBaseAddress, pImageExportDirectory->AddressOfFunctions, NULL);
    DWORD *pAddressOfNames = (DWORD*)ImageRvaToVa(ImageNtHeader(pBaseAddress), pBaseAddress, pImageExportDirectory->AddressOfNames, NULL);
    WORD *pAddressOfNameOrdinals = (WORD*)ImageRvaToVa(ImageNtHeader(pBaseAddress), pBaseAddress, pImageExportDirectory->AddressOfNameOrdinals, NULL);

    if (IsBadReadPtr(pAddressOfNames, sizeof(DWORD) * dwNumberOfNames))
	return FALSE;

    for (size_t i = 0; i < dwNumberOfNames; i++)
    {
	char *strFunction = (char *)ImageRvaToVa(ImageNtHeader(pBaseAddress), pBaseAddress, pAddressOfNames[pAddressOfNameOrdinals[i]], NULL);
	if (!strFunction)
	    break;

	CNamedFunc func(std::string(strFunction), pAddressOfFunction[i]);
	funcList->push_back(func);
    }

    return TRUE;
}

BOOL GetPEInfo(PBYTE pBuf, ULONG uSize, ULONG &ImageSize, bool &bIs64Bit)
{
    PIMAGE_DOS_HEADER   pDosHdr = NULL;
    PIMAGE_NT_HEADERS32 pNTHdr32 = NULL;
    PIMAGE_NT_HEADERS64 pNTHdr64 = NULL;
    PIMAGE_FILE_HEADER  pFileHdr = NULL;

    if (NULL == pBuf || 0 == uSize)
	return FALSE;

    pDosHdr = (PIMAGE_DOS_HEADER)pBuf;
    if (IsBadReadPtr(pDosHdr, sizeof(IMAGE_DOS_HEADER)))
	return FALSE;
    if (IMAGE_DOS_SIGNATURE != pDosHdr->e_magic)
	return FALSE;

    pNTHdr32 = (PIMAGE_NT_HEADERS32)((PBYTE)pDosHdr + pDosHdr->e_lfanew);

    if (IsBadReadPtr(pNTHdr32, sizeof(IMAGE_NT_HEADERS32)))
	return FALSE;
    if (IMAGE_NT_SIGNATURE != pNTHdr32->Signature)
	return FALSE;

    pFileHdr = &pNTHdr32->FileHeader;

    if (IsBadReadPtr(pFileHdr, sizeof(IMAGE_FILE_HEADER)))
	return FALSE;

    if (pFileHdr->Machine == IMAGE_FILE_MACHINE_AMD64)
	bIs64Bit = true;
    else
	bIs64Bit = false;

    if(bIs64Bit)
    {
	pNTHdr64 = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHdr + pDosHdr->e_lfanew);

	if (IsBadReadPtr(pNTHdr64, sizeof(IMAGE_NT_HEADERS64)))
	    return FALSE;

	ImageSize = pNTHdr64->OptionalHeader.SizeOfImage;
    }
    else
    {
	ImageSize = pNTHdr32->OptionalHeader.SizeOfImage;
    }

    return TRUE;
}

//Slow...
void CSymbolWorker::OnQueuedLoadImage(std::wstring ImagePath, bool bUseSymbol, bool bIsSystem)
{
    ULONG ImageSize = 0;
    bool bSuccess = false;
    bool bIs64Bit = false;
    CFuncList *funcList = new CFuncList;

    //Notify the UI...
    m_ModuleMgr->LoadingImageNotify(ImagePath);

    HANDLE hFile = CreateFile(ImagePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        ULONG uSize = GetFileSize(hFile, 0);
        if (0 != uSize)
	{
            //Get PE information from file mapping...
	    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	    if (NULL != hMapping)
	    {
		PBYTE pBuf = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
		if (NULL != pBuf)
		{
		    if (GetPEInfo(pBuf, uSize, ImageSize, bIs64Bit))
		    {
                        bool bSymbolAvailable = false;
                        if(bUseSymbol)
                        {
                            DWORD64 dwBase = SymLoadModule64(GetCurrentProcess(), hFile, NULL, NULL, (DWORD64)NULL, uSize);
                            if(dwBase)
                            {
                               SymEnumSymbols(GetCurrentProcess(), dwBase, 0, EnumSymCallBack, funcList);
                               SymUnloadModule64(GetCurrentProcess(), dwBase);
                            }
                            if(!funcList->empty())
                                bSymbolAvailable = true;
                        }
                        if(!bUseSymbol || !bSymbolAvailable)
                            EnumPEExport(pBuf, uSize, funcList);

                        bSuccess = true;
		    }
		}
		UnmapViewOfFile(pBuf);
	    }
	    CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }

    if(bSuccess)
	QueuedAddImage(ImagePath, ImageSize, bIs64Bit, bIsSystem, funcList);
    else
	QueuedLoadImageComplete(ImagePath, NULL);
}

//Query module info from a worker thread, high CPU usage but quick
void CModuleWorker::OnQueuedGetModuleInfo(CUniqueProcess *up, ULONG64 BaseAddress)
{
    ULONG64 ImageBase;
    ULONG ImageSize;
    BOOLEAN Is64Bit;
    std::wstring ImagePath;
    if(GetImageBaseInfoByAddress(up->m_ProcessId, BaseAddress, &ImageBase, &ImageSize, &Is64Bit) &&
	    GetImagePathByAddress(up->m_ProcessId, ImageBase, ImagePath))
    {
	emit QueuedAddModule(up, ImageBase, ImageSize, ImagePath, Is64Bit ? true : false, false);
    }
}

//Query image file info

CImageFileInfo::CImageFileInfo()
{
    fileSize = 0;
    memset(fileVer, 0, sizeof(fileVer));
}

void CModuleWorker::OnQueuedGetImageFileInfo(std::wstring ImagePath)
{
    CImageFileInfo *fileInfo = NULL;

    HANDLE hFile = CreateFile(ImagePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
	LARGE_INTEGER fileSize;
	fileSize.LowPart = GetFileSize(hFile, (LPDWORD)&fileSize.HighPart);
	if (0 != fileSize.QuadPart)
	{
	    DWORD dwSize = GetFileVersionInfoSize(ImagePath.c_str(), NULL);
	    if (dwSize)
	    {
		LPVOID pBlock = new byte[dwSize];
		if (GetFileVersionInfo(ImagePath.c_str(), 0, dwSize, pBlock))
		{
		    fileInfo = new CImageFileInfo;
		    fileInfo->fileSize = fileSize.QuadPart;

		    TCHAR *pVerValue = NULL;
		    UINT nSize = 0;
		    VS_FIXEDFILEINFO* pVersion = NULL;
		    if (VerQueryValueW(pBlock, L"\\", (void**)&pVersion, &nSize))
		    {
			fileInfo->fileVer[0] = HIWORD(pVersion->dwFileVersionMS);
			fileInfo->fileVer[1] = LOWORD(pVersion->dwFileVersionMS);
			fileInfo->fileVer[2] = HIWORD(pVersion->dwFileVersionLS);
			fileInfo->fileVer[3] = LOWORD(pVersion->dwFileVersionLS);

			fileInfo->proVer[0] = HIWORD(pVersion->dwProductVersionMS);
			fileInfo->proVer[1] = LOWORD(pVersion->dwProductVersionMS);
			fileInfo->proVer[2] = HIWORD(pVersion->dwProductVersionLS);
			fileInfo->proVer[3] = LOWORD(pVersion->dwProductVersionLS);
		    }

		    if (VerQueryValue(pBlock,L"\\VarFileInfo\\Translation", (LPVOID*)&pVerValue, &nSize))
		    {
			BYTE *pTranslate = (BYTE *)pVerValue;
			QString strSubBlock;
			QString strTemp = QString("%1%2%3%4").arg(
				FormatHexString(pTranslate[1], 2),
				FormatHexString(pTranslate[0], 2),
				FormatHexString(pTranslate[3], 2),
				FormatHexString(pTranslate[2], 2));

			strSubBlock = QString("\\StringFileInfo\\%1\\FileDescription").arg(strTemp);
			if (VerQueryValue(pBlock, (LPCWSTR)strSubBlock.utf16(), (LPVOID*)&pVerValue, &nSize))
			    fileInfo->fileDesc = QString::fromUtf16((const ushort *)pVerValue, nSize);

			strSubBlock = QString("\\StringFileInfo\\%1\\ProductName").arg(strTemp);
			if (VerQueryValue(pBlock, (LPCWSTR)strSubBlock.utf16(), (LPVOID*)&pVerValue, &nSize))
			    fileInfo->productName = QString::fromUtf16((const ushort *)pVerValue, nSize);
			strSubBlock = QString("\\StringFileInfo\\%1\\LegalCopyright").arg(strTemp);
			if (VerQueryValue(pBlock, (LPCWSTR)strSubBlock.utf16(), (LPVOID*)&pVerValue, &nSize))
			    fileInfo->copyRights = QString::fromUtf16((const ushort *)pVerValue, nSize);

			strSubBlock = QString("\\StringFileInfo\\%1\\CompanyName").arg(strTemp);
			if (VerQueryValue(pBlock, (LPCWSTR)strSubBlock.utf16(), (LPVOID*)&pVerValue, &nSize))
			    fileInfo->companyName = QString::fromUtf16((const ushort *)pVerValue, nSize);
		    }
		}
		delete pBlock;
	    }
	}
	CloseHandle(hFile);
    }

    if(fileInfo){
	QueuedAddImageFileInfo(ImagePath, fileInfo);
    }
}

//mgr

CModuleMgr::CModuleMgr(QObject *parent) : QObject(parent)
{
    m_ModuleMgr = this;
    m_Image_ntoskrnl = NULL;
    m_Image_win32k = NULL;
    m_Image_win32kFull = NULL;
}

void CModuleMgr::Initialize(void)
{
    WCHAR szSymPath[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, szSymPath);
    wcscat(szSymPath, L"\\symbols");
    CreateDirectory(szSymPath, NULL);

    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    SymInitialize(GetCurrentProcess(), NULL, FALSE);
    QString symSearch = QString("srv*%1*http://msdl.microsoft.com/download/symbols").arg(QString::fromWCharArray(szSymPath));
    QByteArray symSearchBytes = symSearch.toLatin1();
    SymSetSearchPath(GetCurrentProcess(), symSearchBytes.constData());

    qRegisterMetaType<std::wstring>("std::wstring");
    qRegisterMetaType<ULONG>("ULONG");
    qRegisterMetaType<ULONG64>("ULONG64");

    {
    auto worker = new CModuleWorker;
    worker->moveToThread(&m_moduleWorkerThread);
    connect(&m_moduleWorkerThread, SIGNAL(finished()), worker, SLOT(deleteLater()));
    connect(this, &CModuleMgr::QueuedGetModuleInfo, worker, &CModuleWorker::OnQueuedGetModuleInfo, Qt::QueuedConnection);
    connect(this, &CModuleMgr::QueuedGetImageFileInfo, worker, &CModuleWorker::OnQueuedGetImageFileInfo, Qt::QueuedConnection);
    connect(worker, &CModuleWorker::QueuedAddModule, this, &CModuleMgr::OnQueuedAddModule, Qt::QueuedConnection);
    connect(worker, &CModuleWorker::QueuedAddImageFileInfo, this, &CModuleMgr::OnQueuedAddImageFileInfo, Qt::QueuedConnection);
    m_moduleWorkerThread.start();
    }

    {
    auto worker = new CSymbolWorker;
    worker->moveToThread(&m_symbolWorkerThread);
    connect(&m_symbolWorkerThread, SIGNAL(finished()), worker, SLOT(deleteLater()));
    connect(this, &CModuleMgr::QueuedLoadImage, worker, &CSymbolWorker::OnQueuedLoadImage, Qt::QueuedConnection);
    connect(worker, &CSymbolWorker::QueuedAddImage, this, &CModuleMgr::OnQueuedAddImage, Qt::QueuedConnection);
    connect(worker, &CSymbolWorker::QueuedLoadImageComplete, this, &CModuleMgr::OnLoadImageComplete, Qt::QueuedConnection);
    m_symbolWorkerThread.start();
    }
}

void CModuleMgr::Uninitialize(void)
{
    m_moduleWorkerThread.quit();
    m_moduleWorkerThread.wait();

    m_symbolWorkerThread.quit();
    m_symbolWorkerThread.wait();

    SymCleanup(GetCurrentProcess());
}

ULONG CUniqueImage::FindFunctionOffsetByName(std::string &name)
{
    CFuncMap::iterator itor = m_NamedFuncMaps.find(name);
    if(itor != m_NamedFuncMaps.end())
    {
	return itor->second;
    }
    return 0;
}

ULONG CUniqueImage::FindClosestFunction(IN ULONG Offset, OUT std::string &name)
{
    int delta = 0x7fffffff;
    int idx = -1;
    for(int i = 0; i < (int)m_NamedFunctions.size(); ++i)
    {
	int off = Offset - m_NamedFunctions[i].m_offset;
	if(off >= 0 && off < delta)
	{
	    delta = off;
	    idx = i;
	}
    }

    if(idx == -1)
	return 0;

    name = m_NamedFunctions[idx].m_name;
    return m_NamedFunctions[idx].m_offset;
}

ULONG64 CUniqueModule::FindFunctionAddressByName(std::string &name)
{
    ULONG offset = m_UniqueImage->FindFunctionOffsetByName(name);
    if(!offset)
	return NULL;

    return m_ImageBase + offset;
}

ULONG CUniqueModule::FindClosestFunction(IN ULONG Offset, OUT std::string &name)
{
    return m_UniqueImage->FindClosestFunction(Offset, name);
}

CUniqueImage *CModuleMgr::GetImage(std::wstring &ImagePath, ULONG ImageSize, bool bIs64Bit, bool bIsSystem)
{
    CUniqueImage *ui = GetImage(ImagePath);

    if(!ui)
    {
	ui = new CUniqueImage(ImageSize, ImagePath.c_str(), bIs64Bit, bIsSystem);
	std::wstring upperImagePath = boost::to_upper_copy(ImagePath);
        m_ImageMap[upperImagePath] = ui;
    }

    return ui;
}

CUniqueImage *CModuleMgr::GetImage(std::wstring &ImagePath)
{
    CUniqueImage *ui = NULL;

    std::wstring upperImagePath = boost::to_upper_copy(ImagePath);

    CImageMap::iterator itor = m_ImageMap.find(upperImagePath);

    if(itor != m_ImageMap.end())
    {
	ui = itor->second;
    }

    return ui;
}

CImageFileInfo *CModuleMgr::GetImageFileInfo(std::wstring &ImagePath)
{
    CImageFileInfo *fileInfo = NULL;

    std::wstring upperImagePath = boost::to_upper_copy(ImagePath);

    CImageFileInfoMap::iterator itor = m_ImageFileInfoMap.find(upperImagePath);

    if(itor != m_ImageFileInfoMap.end())
    {
	fileInfo = itor->second;
    }

    return fileInfo;
}

void CModuleMgr::OnQueuedAddImage(std::wstring ImagePath, ULONG ImageSize, bool bIs64Bit, bool bIsSystem, CFuncList *funcList)
{
    CUniqueImage *ui = GetImage(ImagePath, ImageSize, bIs64Bit, bIsSystem);
    ui->m_bLoadedSymbol = true;
    ui->m_NamedFunctions = *funcList;
    for(size_t i = 0;i < ui->m_NamedFunctions.size(); ++i)
    {
	ui->m_NamedFuncMaps[ui->m_NamedFunctions[i].m_name] = ui->m_NamedFunctions[i].m_offset;
    }

    delete funcList;

    OnLoadImageComplete(ImagePath, ui);
}

void CModuleMgr::OnLoadImageComplete(std::wstring ImagePath, CUniqueImage *ui)
{
    if(ui) {
	emit UpdateImageNotify(ui);

	if(!m_Image_ntoskrnl && ImagePath == m_Path_ntoskrnl)
	    m_Image_ntoskrnl = ui;
	else if(!m_Image_win32k && ImagePath == m_Path_win32k)
	    m_Image_win32k = ui;
	else if(!m_Image_win32kFull && ImagePath == m_Path_win32kFull)
	    m_Image_win32kFull = ui;
    }

    std::set<std::wstring>::iterator itor = m_LoadImageQueue.find(ImagePath);

    if(itor != m_LoadImageQueue.end()) {
	m_LoadedImageQueue.insert(ImagePath);
	if(m_LoadedImageQueue.size() == m_LoadImageQueue.size()) {
	    LoadAllImageCompleteNotify();
	}
    }
}

void CModuleMgr::LoadImageFromFile(std::wstring &ImagePath, bool bUseSymbol, bool bIsSystem)
{
    std::set<std::wstring>::iterator itor = m_LoadImageQueue.find(ImagePath);

    if(itor != m_LoadImageQueue.end())
	return;

    m_LoadImageQueue.insert(ImagePath);
    QueuedLoadImage(ImagePath, bUseSymbol, bIsSystem);
}

void CModuleMgr::OnQueuedAddModule(CUniqueProcess *up, ULONG64 ImageBase, ULONG ImageSize, std::wstring ImagePath, bool bIs64Bit, bool bIsSystem)
{
    //Already exist, skip
    for(size_t i = 0;i < up->m_ModuleList.size(); ++i)
    {
	if(up->m_ModuleList[i]->m_ImageBase == ImageBase)
	    return;
    }

    CUniqueImage *ui = GetImage(ImagePath, ImageSize, bIs64Bit, bIsSystem);
    if(!ui->m_bLoadedSymbol){
	LoadImageFromFile(ImagePath, true, ui->m_bIsSystemModule);
	ui->m_bLoadedSymbol = true;
    }

    CUniqueModule *um = new CUniqueModule(ImageBase, ui);
    up->m_ModuleList.push_back(um);

    emit UpdateModuleNotify(up, um);
}

void CModuleMgr::OnQueuedAddImageFileInfo(std::wstring ImagePath, CImageFileInfo *info)
{
    CImageFileInfo *oldInfo = GetImageFileInfo(ImagePath);

    std::wstring upperImagePath = boost::to_upper_copy(ImagePath);

    //update
    if(oldInfo)
	delete oldInfo;

    m_ImageFileInfoMap[upperImagePath] = info;

    UpdateImageFileInfoNotify(ImagePath, info);
}
