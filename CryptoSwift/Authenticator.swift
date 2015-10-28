//
//  MAC.swift
//  CryptoSwift
//
//  Created by Marcin Krzyzanowski on 03/09/14.
//  Copyright (c) 2014 Marcin Krzyzanowski. All rights reserved.
//

private typealias _HMAC = HMAC
private typealias _Poly1305 = Poly1305

/**
*  Message Authentication
*/
public enum Authenticator {
    
    public enum Error: ErrorType {
        case AuthenticateError
    }
    
    /**
    Poly1305
    
    - parameter key: 256-bit key
    */
    case Poly1305(key: [UInt8])
    case HMAC(key: [UInt8], variant:_HMAC.Variant)
    
    /**
    Generates an authenticator for message using a one-time key and returns the 16-byte result
    
    - returns: 16-byte message authentication code
    */
    public func authenticate(message: [UInt8]) throws -> [UInt8] {
        switch (self) {
        case .Poly1305(let key):
            guard let auth = _Poly1305.authenticate(key: key, message: message) else {
                throw Error.AuthenticateError
            }
            return auth
        case .HMAC(let key, let variant):
            guard let auth = _HMAC.authenticate(key: key, message: message, variant: variant) else {
                throw Error.AuthenticateError
            }
            return auth
        }
    }
}