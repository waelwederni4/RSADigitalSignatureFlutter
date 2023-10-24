import Cocoa
import FlutterMacOS

public class RsaDigitalsignaturePlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "rsa_digitalsignature", binaryMessenger: registrar.messenger)
    let instance = RsaDigitalsignaturePlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
     case "getCertifications":
      if let certificates = CertificateHandler().getCertificates() {
        var flutterDataList = [FlutterStandardTypedData]()
        for certificate in certificates {
          let flutterData = FlutterStandardTypedData(bytes: Data(certificate))
          flutterDataList.append(flutterData)
        }
        result(flutterDataList)
      } else {
        result(FlutterError(code: "UNAVAILABLE",message: "Could not retrieve certificates",details: nil))
      }
    case "signWithprivatekey":
      guard let args = call.arguments as? [String: Any],
        let dataToSignTypedData = args["dataToSign"] as? FlutterStandardTypedData,
        let certificateTypedData = args["certificate"] as? FlutterStandardTypedData else {
        result(FlutterError(code: "UNAVAILABLE", message: "Could not retrieve params", details: nil))
        return
      }
      let dataToSign = Data(dataToSignTypedData.data)
      let certificateData = Data(certificateTypedData.data) 

      if let signature = CertificateHandler().signData(certificate: [certificateData], dataToSign: Array(dataToSign)) {
        result(signature)
      } else {
        result(FlutterError(code: "SignError", message: "Failed to sign data", details: nil))
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }
}
