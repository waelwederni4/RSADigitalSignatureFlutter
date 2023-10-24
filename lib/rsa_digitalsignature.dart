import 'package:flutter/foundation.dart';
import 'package:rsa_digitalsignature/certificate.dart';

import 'rsa_digitalsignature_platform_interface.dart';

class RsaDigitalsignature {
  Future<List<Certificate>> getCertifications() {
    return RsaDigitalsignaturePlatform.instance.getCertifications();
  }

  Future<Object?> signWithprivatekey(Uint8List dataToSign, Uint8List object) {
    return RsaDigitalsignaturePlatform.instance
        .signWithprivatekey(dataToSign, object);
  }
}
