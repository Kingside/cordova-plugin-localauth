import Foundation
import LocalAuthentication

@objc(SCPLocalAuth) class LocalAuth : CDVPlugin {

    var keychain: Keychain?

    enum LAError : Int {
        case AuthenticationFailed
        case UserCancel
        case UserFallback
        case SystemCancel
        case PasscodeNotSet
        case TouchIDNotAvailable
        case TouchIDNotEnrolled
    }

    private func log(message: String){
        NSLog("%@ - %@", "LocalAuth", message)
    }

    func initialize(command: CDVInvokedUrlCommand) {
        var pluginResult: CDVPluginResult?
        if let appKey = command.argumentAtIndex(0) as? String {
            keychain = Keychain(service: appKey).synchronizable(true)
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK)
        } else {
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR)
        }

        commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    private func hasUser() -> Bool {
        if let _ = try? keychain!.getString("login") {
            return true
        } else {
            return false
        }
    }

    func user(command: CDVInvokedUrlCommand) {
        var login: String?
        var pluginResult: CDVPluginResult?
        if let email = command.arguments[0] as! String as String! {
            if let password = command.arguments[1] as! String as String! {
                do {
                    try keychain!.set(email, key: "login")
                    try keychain!.set(password, key: email)
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: true)
                } catch let error {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsBool: false)
                    log("error: \(error)")
                }


            } else {
                do {
                    try login = keychain!.getString("login")
                } catch let error {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsBool: false)
                    log("error: \(error)")
                }

                if login == email {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: true)
                } else {
                    do {
                        try keychain!.remove(login!)
                        try keychain!.remove("login")
                        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: false)
                    } catch let error {
                        pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsBool: false)
                        log("error: \(error)")
                    }
                }
            }
        } else if hasUser() {
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: true)
        } else {
            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: false)
        }
        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    private func canAuthenticate() -> Bool {
        var error: NSError?
        var canEvaluate: Bool?
        let context = LAContext()

        if context.canEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, error: &error) {
            log("Touch ID is available")
            canEvaluate = true
        } else {
            switch error!.code {
            case LAError.TouchIDNotAvailable.rawValue:
                log("Touch ID is unavailable")
            case LAError.TouchIDNotEnrolled.rawValue:
                log("Touch ID not configured")
            case LAError.PasscodeNotSet.rawValue:
                log("A passcode has not been set")
            default:
                log("Failed to check Touch ID")
            }
            log((error?.localizedDescription)!)
            canEvaluate = false
        }

        return canEvaluate!
    }

    func isAvailable(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: self.canAuthenticate())

        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    func authenticate(command: CDVInvokedUrlCommand) {
        var authenticated = false
        var error: String?
        var login: String?
        var password: String?
        if canAuthenticate() {
            let context = LAContext()
            context.evaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, localizedReason: "Sign in to TripCase", reply: {
                (success: Bool, evalPolicyError: NSError?) -> Void in

                if success {
                    do {
                        try login = self.keychain!.getString("login")
                        try password = self.keychain!.getString(login!)
                        self.log("Authenticated with Touch ID")
                        authenticated = true
                    } catch let error {
                        self.log("\(error)")
                    }

                } else {
                    switch evalPolicyError!.code {
                    case LAError.SystemCancel.rawValue:
                        self.log("Authentication was cancelled by the system")
                        error = "SystemCancel"
                    case LAError.UserCancel.rawValue:
                        self.log("Authentication was cancelled by the user")
                        error = "UserCancel"
                    case LAError.UserFallback.rawValue:
                        self.log("user selected to enter custom password")
                        error = "UserFallback"
                    default:
                        self.log("Authentication failed")
                        error = "Uncaught"
                    }
                }
            })
        } else {
            error = "Unupported"
        }
        var response = "{\"success\":\(authenticated),"
        if login != nil {
            response += "\"credentials\":{\"email\":\"\(login)\",\"password\":\"\(password)\"},"
        }
        response += (error != nil) ? "\"error\":\"\(error)\"}" : "\"error\":null}"

        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsString: response)
        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

}
