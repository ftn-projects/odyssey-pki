# Odyssey PKI

This Spring Boot application provides a comprehensive PKI (Public Key Infrastructure) backend for managing digital certificates. It enables secure certificate management operations over HTTPS connection.

## Features

- **Certificate Creation**: Administrators can create certificates with the following extensions:
    - **Basic Constraints**
    - **Key Usage**
    - **Authority Key Identifier (AKI)**
    - **Subject Key Identifier (SKI)**
- **Secure Storage**: Certificate private keys are securely stored in a separate ACL (Access Control List) file.
- **Certificate Deletion**: Administrators can delete any certificate. Deleting a certificate also removes all certificates in its subtree.
- **Host Certificate Requests**: Hosts can request certificates. The admin can either accept and create the certificate or decline the request.
- **Certificate Download**: Once a certificate is created, hosts can download their respective certificates.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ftn-projects/odyssey-pki
   ```
2. Navigate to the project directory:
   ```bash
   cd odyssey-pki
   ```
3. Build the project:
   ```bash
    mvn clean install
   ```
4. Optional - Create keystore and acl files (if you already dont have them):
   ```bash
    java -jar target/odyssey-pki-0.0.1-SNAPSHOT.jar --ODYSSEY_CREATE_KEYSTORE=true --ODYSSEY_KEY_STORE_PASSWORD=<KEYSTORE_PASS> --ODYSSEY_KEY_STORE_PATH=<KEYSTORE_PATH> --ODYSSEY_SECRET=<SECRET>
   ```
5. Run the project (default port is 8433):
   ```bash
    java -jar target/odyssey-pki-0.0.1-SNAPSHOT.jar --spring.profiles.active=ssl --ODYSSEY_CREATE_KEYSTORE=false --ODYSSEY_KEY_STORE_PASSWORD=<KEYSTORE_PASS> --ODYSSEY_KEY_STORE_PATH=<KEYSTORE_PATH> --ODYSSEY_SECRET=<SECRET>
   ```
6. Access the application at `https://localhost:8433`.
   