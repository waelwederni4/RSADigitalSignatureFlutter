#include "include/rsa_digitalsignature/rsa_digitalsignature_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "rsa_digitalsignature_plugin.h"

void RsaDigitalsignaturePluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar)
{
    rsa_digitalsignature::RsaDigitalsignaturePlugin::RegisterWithRegistrar(
        flutter::PluginRegistrarManager::GetInstance()
            ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
