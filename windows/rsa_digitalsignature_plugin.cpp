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
        while ((pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext)) != NULL)
        {
          BYTE keyUsage[2]; // Assuming 16 bits of key usage flags
          if (CertGetIntendedKeyUsage(X509_ASN_ENCODING, pCertContext->pCertInfo, keyUsage, sizeof(keyUsage)) &&
              (keyUsage[0] & CERT_NON_REPUDIATION_KEY_USAGE))
          {
            std::vector<BYTE> certDer(pCertContext->pbCertEncoded, pCertContext->pbCertEncoded + pCertContext->cbCertEncoded);
            certDerList.push_back(certDer);
          }
        }
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);

        flutter::EncodableList encodableCertDerList;
        for (const auto &certDer : certDerList)
        {
          encodableCertDerList.push_back(flutter::EncodableValue(certDer));
        }
        result->Success(flutter::EncodableValue(encodableCertDerList));
      }
      else
      {
        result->Error("ProviderOpenError", "Failed to open key storage provider");
      }
    }
    else if (method_call.method_name().compare("signWithprivatekey") == 0)
    {
      const auto *argsList = std::get_if<flutter::EncodableMap>(method_call.arguments());
      if (!argsList)
      {
        result->Error("InvalidArguments", "Arguments missing or invalid");
        return;
      }

      auto dataArg = argsList->find(flutter::EncodableValue("dataToSign"));
      auto certArg = argsList->find(flutter::EncodableValue("certificate"));

      if (dataArg == argsList->end() || certArg == argsList->end())
      {
        result->Error("InvalidArguments", "Arguments 'dataToSign' or 'certificate' not found");
        return;
      }

      const auto *dataToSign = std::get_if<std::vector<uint8_t>>(&dataArg->second);
      const auto *certDerList = std::get_if<std::vector<uint8_t>>(&certArg->second);

      if (!dataToSign || !certDerList)
      {
        result->Error("InvalidArguments", "Arguments 'dataToSign' or 'certificate' are not Uint8List");
        return;
      }

      PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, certDerList->data(), static_cast<DWORD>(certDerList->size()));
      if (!pCertContext)
      {
        result->Error("CertContextError", "Failed to create certificate context");
        return;
      }

      HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
      DWORD dwKeySpec = 0;
      BOOL bFreeHandle = FALSE;

      if (!CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, NULL, &hCryptProvOrNCryptKey, &dwKeySpec, &bFreeHandle))
      {
        CertFreeCertificateContext(pCertContext);
        result->Error("PrivateKeyError", "Failed to acquire private key");
        return;
      }

      bool signSuccess = false;
      std::vector<BYTE> vSignature;

      if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
      {
        NCRYPT_KEY_HANDLE hPrivateKey = (NCRYPT_KEY_HANDLE)hCryptProvOrNCryptKey;
        BCRYPT_PKCS1_PADDING_INFO paddingInfo = {0};
        paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

        DWORD cbSignature = 0;
        NTSTATUS status = NCryptSignHash(hPrivateKey, &paddingInfo, reinterpret_cast<PBYTE>(const_cast<uint8_t *>(dataToSign->data())), static_cast<DWORD>(dataToSign->size()), NULL, 0, &cbSignature, BCRYPT_PAD_PKCS1);

        if (status == ERROR_SUCCESS)
        {
          vSignature.resize(cbSignature);
          status = NCryptSignHash(hPrivateKey, &paddingInfo, reinterpret_cast<PBYTE>(const_cast<uint8_t *>(dataToSign->data())), static_cast<DWORD>(dataToSign->size()), vSignature.data(), cbSignature, &cbSignature, BCRYPT_PAD_PKCS1);

          if (status == ERROR_SUCCESS)
          {
            signSuccess = true;
          }
        }
      }
      else if (dwKeySpec == AT_SIGNATURE)
      {
        HCRYPTHASH hHash;
        HCRYPTPROV hCryptProv = (HCRYPTPROV)hCryptProvOrNCryptKey;

        if (CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
        {
          if (CryptSetHashParam(hHash, HP_HASHVAL, dataToSign->data(), 0))
          {
            DWORD cbSignature = 0;
            if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &cbSignature))
            {
              vSignature.resize(cbSignature);
              if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, vSignature.data(), &cbSignature))
              {
                signSuccess = true;
              }
            }
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

      CertFreeCertificateContext(pCertContext);

      if (signSuccess)
      {
        result->Success(flutter::EncodableValue(vSignature));
      }
      else
      {
        result->Error("SignError", "Failed to sign data");
      }
    }
    else
    {
      result->NotImplemented();
    }
  }

} // namespace rsa_digitalsignature
