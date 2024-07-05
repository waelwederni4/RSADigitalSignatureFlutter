import 'package:rsa_digitalsignature/certificate.dart';
import 'package:flutter/material.dart';
import 'dart:async';
import 'package:flutter/services.dart';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:rsa_digitalsignature/rsa_digitalsignature.dart';

void main() => runApp(const MyApp());

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final List<Certificate> _certificates = [];
  Uint8List datasigned = Uint8List(0);
  final RsaDigitalsignature _rsaDigitalSignaturePlugin = RsaDigitalsignature();
  Certificate? _selectedCertificate;
  final TextEditingController _messageController = TextEditingController();
  String _errorMessage = '';

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  Future<void> initPlatformState() async {
    try {
      final certificates = await _rsaDigitalSignaturePlugin.getCertifications();
      if (!mounted) return;
      setState(() {
        _certificates.addAll(certificates);
      });
    } on PlatformException catch (e) {
      setState(() {
        _errorMessage = "Failed to get certificates: ${e.message}";
      });
    }
  }

  Future<void> signMessage() async {
    if (_selectedCertificate != null && _messageController.text.isNotEmpty) {
      try {
        final String message = _messageController.text;
        final Uint8List dataToSign = Uint8List.fromList(utf8.encode(message));
        final Digest hash = sha256.convert(dataToSign);
        final dynamic publickey =
            await _rsaDigitalSignaturePlugin.signWithprivatekey(
                hash.bytes as Uint8List, _selectedCertificate!.publickey);
        setState(() {
          datasigned =
              Uint8List.fromList(List<int>.from(publickey as List<dynamic>));
        });
      } on PlatformException catch (e) {
        setState(() {
          _errorMessage = "Failed to sign message: ${e.message}";
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        appBar: AppBar(
          title: const Center(child: Text('RSA Digital Signature Example App')),
        ),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            children: <Widget>[
              if (_errorMessage.isNotEmpty)
                Text(
                  _errorMessage,
                  style: const TextStyle(color: Colors.red),
                ),
              Align(
                alignment: Alignment.center,
                child: DropdownButton<Certificate>(
                  value: _selectedCertificate,
                  items: _certificates.map<DropdownMenuItem<Certificate>>(
                    (Certificate certificate) {
                      final cn = certificate.cn;
                      return DropdownMenuItem<Certificate>(
                        value: certificate,
                        child: Text(cn),
                      );
                    },
                  ).toList(),
                  onChanged: (value) {
                    setState(() {
                      _selectedCertificate = value;
                    });
                  },
                  hint: const Text("Select a certificate"),
                ),
              ),
              const SizedBox(height: 16.0),
              if (_selectedCertificate != null)
                TextField(
                  controller: _messageController,
                  decoration: const InputDecoration(labelText: "Message"),
                ),
              const SizedBox(height: 16.0),
              if (_selectedCertificate != null)
                ElevatedButton(
                  onPressed: signMessage,
                  child: const Text("Sign Message"),
                ),
              if (datasigned.isNotEmpty)
                Expanded(
                  child: SingleChildScrollView(
                    child: Text("Signed Data: $datasigned"),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
