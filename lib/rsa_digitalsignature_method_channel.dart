import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:rsa_digitalsignature/certificate.dart';
import 'package:asn1lib/asn1lib.dart';
import 'dart:typed_data';
import 'package:x509/x509.dart' as x509Cert;
import 'rsa_digitalsignature_platform_interface.dart';

/// An implementation of [RsaDigitalsignaturePlatform] that uses method channels.
class MethodChannelRsaDigitalsignature extends RsaDigitalsignaturePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('rsa_digitalsignature');

  @override
  Future<List<Certificate>> getCertifications() async {
    try {
      final response =
          await methodChannel.invokeMethod<List<dynamic>>('getCertifications');
      if (response == null || response.isEmpty) {
        return List.empty();
      }
      return response.where((item) {
        try {
          if (item is! UnmodifiableUint8ListView) {
            return false;
          }
          final bytes = Uint8List.fromList(item);
          final asn1Parser = ASN1Parser(bytes);
          final asn1Sequence = asn1Parser.nextObject();
          if (asn1Sequence is! ASN1Sequence) {
            return false;
          }
          final x509 = x509Cert.X509Certificate.fromAsn1(asn1Sequence);
          final subjectNames = x509.tbsCertificate.subject?.names;
          final cn = subjectNames?[0].values.first.toString();
          if (cn == null) {
            return false;
          }
          return true;
        } catch (e) {
          if (kDebugMode) {
            print('Error processing item: $e');
          }
          return false;
        }
      }).map<Certificate>((item) {
        final bytes = Uint8List.fromList(item);
        final asn1Parser = ASN1Parser(bytes);
        final asn1Sequence = asn1Parser.nextObject() as ASN1Sequence;
        final x509 = x509Cert.X509Certificate.fromAsn1(asn1Sequence);
        final subjectNames = x509.tbsCertificate.subject?.names;
        final cn = subjectNames?[0].values.first.toString();
        return Certificate(
          publickey: item,
          x509certificate: x509,
          cn: cn!,
        );
      }).toList();
    } catch (e) {
      rethrow;
    }
  }

  @override
  Future<Object?> signWithprivatekey(
      Uint8List dataToSign, Uint8List object) async {
    final version = await methodChannel.invokeMethod<Object?>(
        'signWithprivatekey',
        {'dataToSign': dataToSign, 'certificate': object});
    return version;
  }
}
