# RSA Digital Signature

Library for SignData use RSACNG privateKey with support for macos, windows
![Screenshot of choise certificate](https://imgur.com/WwpCUgC)
![Screenshot of Sign Data](https://imgur.com/R1dLYSI)
![Screenshot of Data signed](https://imgur.com/4a7vukg)

## Usage

### Retreive all certificate has NonRepudiation KeyUsage

```dart
import 'package:rsa_digitalsignature/rsa_digitalsignature.dart';
import 'package:rsa_digitalsignature/certificate.dart';

final RsaDigitalsignature _rsaDigitalSignaturePlugin =RsaDigitalsignature();

final List<Certificate> _certificates = await _rsaDigitalSignaturePlugin.getCertifications();

```

### SignData With PrivateKey

```dart
import 'package:fast_rsa/fast_rsa.dart';

final String message = "Hello World !";
final Uint8List dataToSign = Uint8List.fromList(utf8.encode(message));
final Digest hash = sha256.convert(dataToSign);
final dynamic publickey = await _rsaDigitalSignaturePlugin.signWithprivatekey((hash.bytes as Uint8List), _selectedCertificate!.publickey);
Uint8List datasigned = Uint8List.fromList(List<int>.from(publickey as List<dynamic>));

```

### Sign methods

```dart
import 'package:fast_rsa/fast_rsa.dart';

var result = await RSA.signPSS(message, Hash.SHA256, SaltLength.SALTLENGTH_AUTO, privateKey)
var result = await RSA.signPKCS1v15(message, Hash.SHA256, privateKey)

var result = await RSA.signPSSBytes(messageBytes, Hash.SHA256, SaltLength.SALTLENGTH_AUTO, privateKey)
var result = await RSA.signPKCS1v15Bytes(messageBytes, Hash.SHA256, privateKey)

```

### Cerificate Class

```dart
class Certificate {
  final Uint8List publickey; <-- DER Certificate
  final X509Certificate x509certificate; <-- X509 Instance
  final String cn; <-- Common Name
  const Certificate(
      {required this.publickey,
      required this.x509certificate,
      required this.cn});
}

```

## Setup

### Windows

No additional setup required.

### MacOS

No additional setup required.

## Example

Inside example folder

```bash
cd example && flutter run
```
