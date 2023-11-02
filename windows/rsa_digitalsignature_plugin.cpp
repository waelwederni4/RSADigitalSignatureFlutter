#include "rsa_digitalsignature_plugin.h"
#include <windows.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <VersionHelpers.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter/encodable_value.h>
#include <string>
#include <memory>
#include <sstream>
#include <vector>

namespace rsa_digitalsignature
{

  // static
  void RsaDigitalsignaturePlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarWindows *registrar)
  {
    auto channel =
        std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
            registrar->messenger(), "rsa_digitalsignature",
            &flutter::StandardMethodCodec::GetInstance());

    auto plugin = std::make_unique<RsaDigitalsignaturePlugin>();

    channel->SetMethodCallHandler(
        [plugin_pointer = plugin.get()](const auto &call, auto result)
        {
          plugin_pointer->HandleMethodCall(call, std::move(result));
        });

    registrar->AddPlugin(std::move(plugin));
  }

  RsaDigitalsignaturePlugin::RsaDigitalsignaturePlugin() {}

  RsaDigitalsignaturePlugin::~RsaDigitalsignaturePlugin() {}

  std::string WideStringToNarrowString(const wchar_t *wideStr)
  {
    int len = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    std::string narrowStr(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, &narrowStr[0], len, NULL, NULL);
    return narrowStr;
  }

  void RsaDigitalsignaturePlugin::HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result)
  {
    if (method_call.method_name().compare("getCertifications") == 0)
    {
      std::vector<std::vector<BYTE>> certDerList;
      HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"MY");
      if (hCertStore != NULL)
      {
        PCCERT_CONTEXT pCertContext = NULL;
        pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
        while (pCertContext != NULL)
        {
          BYTE keyUsage[2]; // Assuming 16 bits of key usage flags
          if (CertGetIntendedKeyUsage(X509_ASN_ENCODING, pCertContext->pCertInfo, keyUsage, sizeof(keyUsage)))
          {
            if (keyUsage[0] & CERT_NON_REPUDIATION_KEY_USAGE)
            {
              DWORD size = pCertContext->cbCertEncoded; 
              std::vector<BYTE> certDer(pCertContext->pbCertEncoded, pCertContext->pbCertEncoded + size);
              certDerList.push_back(certDer);
            }
          }
          pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
        }
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
        flutter::EncodableList encodableCertDerList;
        for (const std::vector<BYTE> &certDer : certDerList)
        {
          encodableCertDerList.push_back(flutter::EncodableValue(certDer));
        }
        flutter::EncodableValue res = flutter::EncodableValue(encodableCertDerList);
        result->Success(res);
      }
      else
      {
        result->Error("ProviderOpenError", "Failed to open key storage provider", nullptr);
      }
    }
    if (method_call.method_name().compare("signWithprivatekey") == 0)
    {
      const flutter::EncodableMap *argsList = std::get_if<flutter::EncodableMap>(method_call.arguments());
      if (argsList)
      {
        auto dataArg = argsList->find(flutter::EncodableValue("dataToSign"));
        if (dataArg != argsList->end())
        {
          const std::vector<uint8_t> *dataToSign = std::get_if<std::vector<uint8_t>>(&dataArg->second);
          if (dataToSign)
          {
            auto certArg = argsList->find(flutter::EncodableValue("certificate"));
            if (certArg != argsList->end())
            {
              const std::vector<uint8_t> *certDerList = std::get_if<std::vector<uint8_t>>(&certArg->second);
              if (certDerList)
              {
                std::vector<uint8_t> certDer = *certDerList;
                PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
                    X509_ASN_ENCODING,
                    certDer.data(),
                    static_cast<DWORD>(certDer.size()));
                if (pCertContext)
                {
                  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
                  DWORD dwKeySpec = 0;
                  BOOL bFreeHandle = FALSE;

                  BOOL bResult = CryptAcquireCertificatePrivateKey(
                      pCertContext,
                      CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                      NULL,
                      &hCryptProvOrNCryptKey,
                      &dwKeySpec,
                      &bFreeHandle);

                  if (bResult)
                  {
                    if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
                    {
                      NCRYPT_KEY_HANDLE hPrivateKey = (NCRYPT_KEY_HANDLE)hCryptProvOrNCryptKey;

                      // Set up the signing parameters
                      BCRYPT_PKCS1_PADDING_INFO paddingInfo = {0};
                      paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

                      DWORD cbSignature = 0;
                      DWORD cbData = 32;

                      // Get the size of the signature
                      NTSTATUS status = NCryptSignHash(
                          hPrivateKey,
                          &paddingInfo,
                          reinterpret_cast<PBYTE>(const_cast<uint8_t *>(dataToSign->data())),
                          cbData,
                          NULL,
                          0,
                          &cbSignature,
                          BCRYPT_PAD_PKCS1);

                      if (status == ERROR_SUCCESS)
                      {
                        std::vector<BYTE> vSignature(cbSignature);

                        // Sign the data
                        NTSTATUS signStatus = NCryptSignHash(
                            hPrivateKey,
                            &paddingInfo, // Pass the address of paddingInfo
                            reinterpret_cast<PBYTE>(const_cast<uint8_t *>(dataToSign->data())),
                            cbData,
                            vSignature.data(),
                            cbSignature,
                            &cbSignature,
                            BCRYPT_PAD_PKCS1);

                        if (signStatus == ERROR_SUCCESS)
                        {
                          flutter::EncodableValue res = flutter::EncodableValue(vSignature);
                          result->Success(res);
                        }
                        else
                        {
                          LPWSTR errorMsg = NULL;
                          FormatMessage(
                              FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                              NULL,
                              signStatus, // Your error code
                              0,          // Default language
                              (LPWSTR)&errorMsg,
                              0,
                              NULL);

                          if (errorMsg)
                          {
                            wprintf(L"Error code %d: %s\n", signStatus, errorMsg);
                            LocalFree(errorMsg);
                          }
                          else
                          {
                            wprintf(L"Failed to retrieve error message.\n");
                          }
                          result->Error("SignError", "Failed to sign data", nullptr);
                        }
                      }
                      else
                      {
                        result->Error("SignError", "Failed to get signature size", nullptr);
                      }
                    }
                    else if (dwKeySpec == AT_SIGNATURE)
                    {
                      // Key from a CSP: CryptAPI is used.
                      HCRYPTHASH hHash;
                      HCRYPTPROV hCryptProv = (HCRYPTPROV)hCryptProvOrNCryptKey;

                      if (CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
                      {
                        if (CryptSetHashParam(hHash, HP_HASHVAL, dataToSign->data(), 0))
                        {
                          BYTE *pbSignature = NULL;
                          DWORD cbSignature = 0;

                          // Determine the size required for the signature.
                          if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &cbSignature))
                          {
                            // Handle error
                          }

                          pbSignature = new BYTE[cbSignature];

                          if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &cbSignature))
                          {
                            flutter::EncodableValue res = flutter::EncodableValue(std::vector<BYTE>(pbSignature, pbSignature + cbSignature));
                            result->Success(res);
                          }
                          else
                          {
                            // Handle error
                          }

                          delete[] pbSignature;
                        }

                        CryptDestroyHash(hHash);
                      }
                    }

                    if (bFreeHandle)
                    {
                      if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
                      {
                        NCryptFreeObject(hCryptProvOrNCryptKey);
                      }
                      else
                      {
                        CryptReleaseContext(hCryptProvOrNCryptKey, 0);
                      }
                    }
                  }
                  else
                  {
                    result->Error("PrivateKeyError", "Failed to acquire private key", nullptr);
                  }

                  CertFreeCertificateContext(pCertContext);
                }
                else
                {
                  result->Error("CertContextError", "Failed to create certificate context", nullptr);
                }
              }
              else
              {
                result->Error("InvalidArguments", "Argument 'certificate' is not a Uint8List");
              }
            }
            else
            {
              result->Error("InvalidArguments", "Argument 'certificate' not found");
            }
          }
          else
          {
            result->Error("InvalidArguments", "Argument 'dataToSign' is not a Uint8List");
          }
        }
        else
        {
          result->Error("InvalidArguments", "Arguments missing or invalid");
        }
      }
      else
      {
        result->Error("InvalidArguments", "Arguments missing or invalid");
      }
    }
    else
    {
      result->NotImplemented();
    }
  }

} // namespace rsa_digitalsignature
