import 'dart:typed_data';
import 'package:x509/x509.dart';

class Certificate {
  final UnmodifiableUint8ListView publickey;
  final X509Certificate x509certificate;
  final String cn;
  const Certificate(
      {required this.publickey,
      required this.x509certificate,
      required this.cn});
}
