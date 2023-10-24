import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rsa_digitalsignature/rsa_digitalsignature_method_channel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  MethodChannelRsaDigitalsignature platform = MethodChannelRsaDigitalsignature();
  const MethodChannel channel = MethodChannel('rsa_digitalsignature');

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
      channel,
      (MethodCall methodCall) async {
        return '42';
      },
    );
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
  });

  test('getCertifications', () async {
    expect(await platform.getCertifications(), '42');
  });
}
