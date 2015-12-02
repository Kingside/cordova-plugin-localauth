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

    private func getKeychain() -> Keychain? {
        if let appKeychain: Keychain? = Keychain(service: NSBundle.mainBundle().bundleIdentifier!) {
            appKeychain!
                .synchronizable(true)
                .label("TripCase")

            return appKeychain
        }
    }

    private func hasUser() -> Bool {
        keychain = Keychain(service: NSBundle.mainBundle().bundleIdentifier!).synchronizable(true)
        if let _ = try? keychain!.getString("login") {
            return true
        } else {
            return false
        }
    }
    override func pluginInitialize() {
        keychain = Keychain(service: NSBundle.mainBundle().bundleIdentifier!).synchronizable(true)
    }
    func user(command: CDVInvokedUrlCommand) {
        var login: String?
        var pluginResult: CDVPluginResult?
        keychain = Keychain(service: NSBundle.mainBundle().bundleIdentifier!).synchronizable(true)
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

    func checkAvailable(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: self.canAuthenticate())

        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    func enrolled(command: CDVInvokedUrlCommand) {
        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: self.hasUser())

        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    func clearUser(command: CDVInvokedUrlCommand) {
        var pluginResult: CDVPluginResult?
        var login: String?
        if let appKeychain = getKeychain() {
            do {
                try login = appKeychain.getString("login")
                if (login != nil) {
                    try appKeychain[login!] = nil
                    try appKeychain["login"] = nil
                }
                pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsBool: false)
            } catch let error {
                pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsBool: false)
                log("error: \(error)")
            }
        } else {
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsBool: false)
        }
        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
    }

    func authenticate(command: CDVInvokedUrlCommand) {
        var error: String?
        var login: String?
        var password: String?
        var response: String?
        keychain = Keychain(service: NSBundle.mainBundle().bundleIdentifier!).synchronizable(true)
        if canAuthenticate() {
            let context = LAContext()
            context.evaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, localizedReason: "Sign in to TripCase", reply: {
                (success: Bool, evalPolicyError: NSError?) -> Void in

                if success {
                    do {
                        self.log("Authenticated with Touch ID")
                        try login = self.keychain!.getString("login")
                        try password = self.keychain!.getString(login!)
                        response = "{\"email\":\"\(login!)\",\"password\":\"\(password!)\"}"
                        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsString: response)
                        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
                    } catch let error {
                        self.log("\(error)")
                    }

                } else {
                    switch evalPolicyError!.code {
                    case LAError.SystemCancel.rawValue:
                        self.log("Authentication was cancelled by the system")
                        error = "SystemCancel"
                        response = "{\"error\":\"\(error!)\"}"
                        let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsString: response)
                        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
                    case LAError.UserCancel.rawValue:
                        self.log("Authentication was cancelled by the user")
                        error = "UserCancel"
                        response = "{\"error\":\"\(error!)\"}"
                        let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsString: response)
                        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
                    // case LAError.UserFallback.rawValue:
                        // self.log("user selected to enter custom password")
                        // error = "UserFallback"
                    default:
                        self.log("Authentication failed")
                        error = "Aborted"
                        response = "{\"error\":\"\(error!)\"}"
                        let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsString: response)
                        self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
                    }
                }
            })
        } else {
            error = "Unupported"
            response = "{\"error\":\"\(error!)\"}"
            let pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAsString: response)
            self.commandDelegate!.sendPluginResult(pluginResult, callbackId: command.callbackId)
        }
    }

}
