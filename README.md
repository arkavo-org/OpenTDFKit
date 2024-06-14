# OpenTDFKit

Swift toolkit for OpenTDF (unofficial)

## Feature

- [OpenTDF nanotdf specification](https://github.com/opentdf/spec/tree/main/schema/nanotdf)
- WebSocket rewrap

## NanoTDF creation

```mermaid
sequenceDiagram
    participant App
    participant TDFBuilder
    participant CryptoLibrary
    participant KAS

    App->>KAS: Request recipient public key
    KAS-->>App: Recipient public key

    App->>TDFBuilder: Provide cleartext and policy
    TDFBuilder->>CryptoLibrary: Generate ephemeral key pair
    CryptoLibrary-->>TDFBuilder: Ephemeral private key, Ephemeral public key

    TDFBuilder->>CryptoLibrary: Derive shared secret (ephemeral private key, recipient public key)
    CryptoLibrary-->>TDFBuilder: Shared secret

    TDFBuilder->>CryptoLibrary: Derive symmetric key (shared secret)
    CryptoLibrary-->>TDFBuilder: Symmetric key

    TDFBuilder->>CryptoLibrary: Generate Nonce (IV)
    CryptoLibrary-->>TDFBuilder: Nonce (IV)

    TDFBuilder->>CryptoLibrary: Encrypt payload (cleartext, symmetric key, Nonce (IV))
    CryptoLibrary-->>TDFBuilder: Ciphertext, Authentication tag (MAC)

    alt GMAC Binding
        TDFBuilder->>CryptoLibrary: Generate GMAC tag (symmetric key, policy body)
        CryptoLibrary-->>TDFBuilder: GMAC tag
    else ECDSA Binding
        TDFBuilder->>CryptoLibrary: Sign policy body (creator's private key)
        CryptoLibrary-->>TDFBuilder: ECDSA signature
    end

    alt Policy Key Access
        TDFBuilder->>CryptoLibrary: Generate key for policy (ephemeral private key, recipient public key)
        CryptoLibrary-->>TDFBuilder: Policy encryption key
        TDFBuilder->>CryptoLibrary: Encrypt policy (policy, policy encryption key)
        CryptoLibrary-->>TDFBuilder: Encrypted policy

        TDFBuilder->>TDFBuilder: Add Policy Key Access section (Resource Locator, Ephemeral Public Key)
    end

    alt Signature
        TDFBuilder->>CryptoLibrary: Create signature for header and payload (creator's private key)
        CryptoLibrary-->>TDFBuilder: ECDSA signature
    end

    TDFBuilder->>TDFBuilder: Construct header (metadata, ephemeral public key, policy binding, optional signature, optional encrypted policy, optional Policy Key Access)
    TDFBuilder->>TDFBuilder: Combine header, encrypted payload, and signature
    TDFBuilder-->>App: Return NanoTDF
```

## Recommended Authentication

### Sign up

```mermaid
sequenceDiagram
    participant User
    participant ClientApp
    participant Authenticator
    participant RegistrationServer
    participant iCloudKeychain

    User->>ClientApp: Initiate Registration
    ClientApp->>RegistrationServer: Request Registration Challenge
    RegistrationServer-->>ClientApp: Registration Challenge
    ClientApp->>Authenticator: Initiate WebAuthn with Challenge
    Authenticator-->>ClientApp: Public Key Credential Source
    Note right of Authenticator: Generate Passkey Pair (Public & Private Keys)
    
    Note over ClientApp, iCloudKeychain: Steps for Account's Signing Key
    ClientApp->>iCloudKeychain: Store Signing Private Key
    iCloudKeychain-->>ClientApp: Confirmation of Storage
    ClientApp->>RegistrationServer: Send Public Key Credential Source (Public Key)
    RegistrationServer-->>ClientApp: Registration Success
    ClientApp->>User: Registration Complete
```

This sequence diagram represents the following steps:

    1.    Initiate Registration: The user initiates the registration process on the client application.
    2.    Request Registration Challenge: The client application requests a registration challenge from the registration server.
    3.    Receive Registration Challenge: The registration server responds with a registration challenge.
    4.    Initiate WebAuthn with Challenge: The client application initiates the WebAuthn process with the received challenge using the authenticator (device’s built-in secure enclave).
    5.    Create Public Key Credential Source: The authenticator generates a new key pair (public and private keys). The private key is stored securely, and the public key is returned to the client application.
    6.    Store Private Key in iCloud Keychain: The client application stores the private key in iCloud Keychain for synchronization across the user’s devices.
    7.    Confirmation of Storage: The iCloud Keychain confirms that the private key has been stored securely.
    8.    Send Public Key to Registration Server: The client application sends the public key credential source (which includes the public key) to the registration server.
    9.    Registration Success: The registration server acknowledges successful registration.
    10.    Registration Complete: The client application informs the user that the registration process is complete.

### Sign in

```mermaid
sequenceDiagram
    participant User
    participant ClientApp
    participant Authenticator
    participant RegistrationServer

    User->>ClientApp: Initiate Registration
    ClientApp->>RegistrationServer: Request Registration Challenge
    RegistrationServer-->>ClientApp: Send Registration Challenge
    ClientApp->>Authenticator: Initiate WebAuthn with Challenge
    Authenticator-->>ClientApp: Return Public Key Credential Source
    ClientApp->>RegistrationServer: Send Public Key Credential Source (Public Key)
    RegistrationServer-->>ClientApp: Registration Success
    ClientApp->>User: Registration Complete
```

This diagram represents the basic WebAuthn passkey registration steps:

    1.    Initiate Registration: The user initiates the registration process on the client application.
    2.    Request Registration Challenge: The client application requests a registration challenge from the registration server.
    3.    Send Registration Challenge: The registration server responds with a registration challenge.
    4.    Initiate WebAuthn with Challenge: The client application initiates the WebAuthn process with the received challenge using the authenticator (device’s built-in secure enclave).
    5.    Return Public Key Credential Source: The authenticator generates a new key pair (public and private keys). The private key is stored securely, and the public key is returned to the client application.
    6.    Send Public Key Credential Source (Public Key): The client application sends the public key credential source (which includes the public key) to the registration server.
    7.    Registration Success: The registration server acknowledges successful registration.
    8.    Registration Complete: The client application informs the user that the registration process is complete.

