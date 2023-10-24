import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'package:rsa_digitalsignature/certificate.dart';
import 'package:flutter/foundation.dart';
import 'rsa_digitalsignature_method_channel.dart';

abstract class RsaDigitalsignaturePlatform extends PlatformInterface {
  /// Constructs a RsaDigitalsignaturePlatform.
  RsaDigitalsignaturePlatform() : super(token: _token);

  static final Object _token = Object();

  static RsaDigitalsignaturePlatform _instance = MethodChannelRsaDigitalsignature();

  /// The default instance of [RsaDigitalsignaturePlatform] to use.
  ///
  /// Defaults to [MethodChannelRsaDigitalsignature].
  static RsaDigitalsignaturePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [RsaDigitalsignaturePlatform] when
  /// they register themselves.
  static set instance(RsaDigitalsignaturePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<List<Certificate>> getCertifications() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }

  Future<Object?> signWithprivatekey(Uint8List dataToSign, Uint8List object) {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
