import 'package:flutter_test/flutter_test.dart';
import 'package:rsa_digitalsignature/certificate.dart';
import 'package:rsa_digitalsignature/rsa_digitalsignature.dart';
import 'package:rsa_digitalsignature/rsa_digitalsignature_platform_interface.dart';
import 'package:rsa_digitalsignature/rsa_digitalsignature_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'package:flutter/foundation.dart';

class MockRsaDigitalsignaturePlatform
    with MockPlatformInterfaceMixin
    implements RsaDigitalsignaturePlatform {
  @override
  Future<List<Certificate>> getCertifications() => Future.value([]);
  @override
  Future<Object> signWithprivatekey(Uint8List dataToSign, Uint8List object) =>
      Future.value([]);
}

void main() {
  final RsaDigitalsignaturePlatform initialPlatform =
      RsaDigitalsignaturePlatform.instance;

  test('$MethodChannelRsaDigitalsignature is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelRsaDigitalsignature>());
  });

  test('getPlatformVersion', () async {
    RsaDigitalsignature rsaDigitalsignaturePlugin = RsaDigitalsignature();
    MockRsaDigitalsignaturePlatform fakePlatform =
        MockRsaDigitalsignaturePlatform();
    RsaDigitalsignaturePlatform.instance = fakePlatform;

    expect(await rsaDigitalsignaturePlugin.getCertifications(), '42');
  });
}
