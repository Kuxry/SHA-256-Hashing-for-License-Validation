#include <WinSock2.h> // 必须放在第一行，避免Winsock.h和Winsock2.h冲突
#include <windows.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <wbemidl.h>
#include <comdef.h>


#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip> // std::hex
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sstream> // std::stringstream

// 确保链接到相应的库
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "IPHLPAPI.lib")

using namespace std;

void handleErrors() {
    unsigned long errCode;
    while ((errCode = ERR_get_error())) {
        char* err = ERR_error_string(errCode, NULL);
        cerr << "OpenSSL error: " << err << endl;
    }
    abort();
}

// 将字节数据转换为16进制字符串的函数
string bytesToHexString(const unsigned char* data, size_t length) {
    stringstream hexString;
    hexString << hex << uppercase << setfill('0');
    for (size_t i = 0; i < length; ++i) {
        hexString << setw(2) << static_cast<int>(data[i]);
    }
    return hexString.str();
}

string GetBiosSerialNumber() {
    string serialNumber = "";

    // 初始化 COM
    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    // 创建 WMI COM 连接
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

    if (SUCCEEDED(hres)) {
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

        if (SUCCEEDED(hres)) {
            // 设置安全级别
            hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
            if (SUCCEEDED(hres)) {
                // 查询
                IEnumWbemClassObject* pEnumerator = NULL;
                hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT SerialNumber FROM Win32_BIOS"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

                if (SUCCEEDED(hres)) {
                    IWbemClassObject* pclsObj = NULL;
                    ULONG uReturn = 0;

                    while (pEnumerator) {
                        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

                        if (0 == uReturn) {
                            break;
                        }

                        VARIANT vtProp;
                        hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
                        serialNumber = _com_util::ConvertBSTRToString(vtProp.bstrVal);

                        VariantClear(&vtProp);
                        pclsObj->Release();
                    }
                    pEnumerator->Release();
                }
            }
            pSvc->Release();
        }
        pLoc->Release();
    }

    // 释放 COM
    CoUninitialize();

    return serialNumber;
}

string GetOperatingSystemSerialNumber() {
    string serialNumber = "";

    // 初始化COM库
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (SUCCEEDED(hr)) {
        // 连接到WMI
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (SUCCEEDED(hr)) {
            // 设置身份验证级别
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

            // 查询操作系统信息
            IEnumWbemClassObject* pEnumerator = NULL;
            hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT SerialNumber FROM Win32_OperatingSystem"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
            if (SUCCEEDED(hr)) {
                // 获取操作系统序列号
                IWbemClassObject* pclsObj = NULL;
                ULONG uReturn = 0;
                while (pEnumerator) {
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (0 == uReturn) {
                        break;
                    }

                    VARIANT vtProp;
                    hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr)) {
                        serialNumber = _bstr_t(vtProp.bstrVal);
                        VariantClear(&vtProp);
                    }
                    pclsObj->Release();
                }
                pEnumerator->Release();
            }
        }
        pLoc->Release();
        pSvc->Release();
    }
    CoUninitialize();

    return serialNumber;
}

string GetHardDiskSerialNumber() {
    string serialNumber = "";

    // 初始化COM库
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (SUCCEEDED(hr)) {
        // 连接到WMI
        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (SUCCEEDED(hr)) {
            // 设置身份验证级别
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

            // 查询硬盘信息
            IEnumWbemClassObject* pEnumerator = NULL;
            hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT SerialNumber, MediaType FROM Win32_DiskDrive WHERE MediaType = 'Fixed hard disk media'"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
            if (SUCCEEDED(hr)) {
                // 获取硬盘序列号
                IWbemClassObject* pclsObj = NULL;
                ULONG uReturn = 0;
                while (pEnumerator) {
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (0 == uReturn) {
                        break;
                    }

                    VARIANT vtProp;
                    // 尝试获取SerialNumber属性
                    hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
                    if (SUCCEEDED(hr)) {
                        serialNumber = static_cast<char*>(_bstr_t(vtProp.bstrVal));
                        VariantClear(&vtProp);
                    }
                    pclsObj->Release();
                }
                pEnumerator->Release();
            }
        }
        pLoc->Release();
        pSvc->Release();
    }
    CoUninitialize();

    return serialNumber;
}



string SHA256HashString(const string& input) {
    // 创建一个保存结果的数组
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // 使用 EVP 来计算哈希
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr) {
        throw runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to initialize EVP Digest");
    }

    if (EVP_DigestUpdate(context, input.c_str(), input.size()) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to update EVP Digest");
    }

    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(context);
        throw runtime_error("Failed to finalize EVP Digest");
    }

    EVP_MD_CTX_free(context);

    // 将哈希值转换为十六进制字符串（大写）
    stringstream ss;
    ss << uppercase; // 设置十六进制输出为大写
    for (unsigned int i = 0; i < lengthOfHash; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

int main() {
    const char* KEYF = "zxjl.bin";
    ifstream fbin(KEYF, ios::binary);
    if (!fbin.is_open()) {
        cerr << "Failed to open file." << endl;
        return 1;
    }

    // opt
    char opt[3];
    fbin.read(opt, 3);
    if (fbin.gcount() < 3) {
        cerr << "File too short." << endl;
        return 1;
    }

    // get keya
    vector<unsigned char> keya(istreambuf_iterator<char>(fbin), {});

    // cal keyb
    vector<unsigned char> keyb;
    int sht = keya.size() - (opt[2] % keya.size());
    for (size_t i = sht; i < keya.size(); ++i) {
        keyb.push_back(keya[i]);
    }
    for (size_t i = 0; i < sht; ++i) {
        keyb.push_back(keya[i]);
    }

    for (size_t i = 0; i < keyb.size(); ++i) {
        keyb[i] = keyb[i] ^ static_cast<unsigned char>(opt[1]);
        keyb[i] = static_cast<unsigned char>((static_cast<int>(keyb[i]) - opt[0]) & 0xFF);
    }

    /*
    //opt
    std::cout << "opt bytes: ";
    for (int i = 0; i < 3; ++i) {
        std::cout << std::hex << (0xFF & static_cast<int>(opt[i])) << " ";
    }
    std::cout << std::dec << std::endl;

    
    // to string
    std::string keybStr(keyb.begin(), keyb.end());

    // print
    std::cout << "Result: " << keybStr << std::endl;
    */

    // Initialize OpenSSL for hashing
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) handleErrors();

    // get info
    string biosSerialNumber = GetBiosSerialNumber();
    string osSerialNumber = GetOperatingSystemSerialNumber();
    string hardDiskSerialNumber = GetHardDiskSerialNumber();

    // combine info
    string combinedInfo = biosSerialNumber + osSerialNumber + hardDiskSerialNumber;
    // sha256
    string hashPrefix = SHA256HashString(combinedInfo);
    cout << "Computer Information:" << hashPrefix << endl;

    //combine info + keyb
    vector<unsigned char> combinedData(hashPrefix.begin(), hashPrefix.end());
    combinedData.insert(combinedData.end(), keyb.begin(), keyb.end());


    // Perform SHA-256 hashing on the combined data
    if (1 != EVP_DigestInit_ex(mdCtx, EVP_sha256(), NULL)) handleErrors();
    if (1 != EVP_DigestUpdate(mdCtx, combinedData.data(), combinedData.size())) handleErrors();

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (1 != EVP_DigestFinal_ex(mdCtx, hash, &lengthOfHash)) handleErrors();

    EVP_MD_CTX_free(mdCtx);


    // Convert and print the final hash in hex format
    string finalHashHex = bytesToHexString(hash, lengthOfHash);
    cout << "Final SHA-256 hash: " << finalHashHex << endl;



    // Read the expected hash from the license file
    ifstream licenseFile("license.txt");
    string expectedHash;
    if (!licenseFile.is_open()) {
        cerr << "Failed to open license file." << endl;
        return 1;
    }
    getline(licenseFile, expectedHash);
    licenseFile.close();

    // Compare the hashes
    if (finalHashHex == expectedHash) {
        cout << "Result：Agree" << endl;
    }
    else {
        cout << "Result：Disagree" << endl;
    }

    system("pause");

    return 0;
}
