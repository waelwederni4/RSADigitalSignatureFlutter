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
  final RsaDigitalsignature _certificatePluginWindowsPlugin =
      RsaDigitalsignature();
  Certificate? _selectedCertificate;
  final TextEditingController _messageController = TextEditingController();

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  Future<void> initPlatformState() async {
    try {
      _certificates
          .addAll(await _certificatePluginWindowsPlugin.getCertifications());
    } on PlatformException {
      // Handle the exception...
    }
    if (!mounted) return;
    setState(() {});
  }

  Future<void> signMessage() async {
    if (_selectedCertificate != null && _messageController.text.isNotEmpty) {
      final String message = _messageController.text;
      final Uint8List dataToSign = Uint8List.fromList(utf8.encode(message));
      final Digest hash = sha256.convert(dataToSign);
      final dynamic publickey =
          await _certificatePluginWindowsPlugin.signWithprivatekey(
              (hash.bytes as Uint8List), _selectedCertificate!.publickey);
      datasigned =
          Uint8List.fromList(List<int>.from(publickey as List<dynamic>));
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        appBar: AppBar(
          title: const Center(child: Text('RSA Digital Signature example app')),
        ),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            children: <Widget>[
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
