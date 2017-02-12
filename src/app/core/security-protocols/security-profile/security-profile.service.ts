import {Injectable} from "@angular/core";
import {KeysGenerationService} from "../keys/keys-generation.service";
import {CertificateRequestGenerationService} from "../certificates/certificates-requests-generation.service";
import {CertificateService} from "../../../domain/services/certificate/certificate.service";
import {CryptographicOperations} from "../cryptographic-operations/cryptographic-operations";
import {SecurityProfile} from "../../../domain/model/security/security-profile";
import {User} from "../../../domain/model/authentication/user";
/**
 * Created by Viki on 2/12/2017.
 */

@Injectable()
export class SecurityProfileService {

  constructor(private keysGenerationService: KeysGenerationService,
              private certificateRequestGenerationService: CertificateRequestGenerationService,
              private certificateService: CertificateService,
              private cryptographicOperations: CryptographicOperations) {
  }

  public createSecurityProfile2(certificatePEM: string, privateKey: CryptoKey, passphrase: string, user: User) {
    let keyArray = this.keysGenerationService.generateSymmetricKeyFromPassword(passphrase, 6530, 32, 'SHA256');
    this.keysGenerationService.importKey(keyArray, 'raw', 'AES-CTR').then((symmetricKey: CryptoKey) => {
      this.keysGenerationService.exportKey(privateKey, 'pkcs8').then((privateRawKey: ArrayBuffer) => {
        console.log(new Uint8Array(privateRawKey));
        this.cryptographicOperations.encrypt(
          this.cryptographicOperations.getAlgorithm('AES-CTR', 'SHA-256', 'encrypt').algorithm,
          symmetricKey, privateRawKey).then((ciphertext: ArrayBuffer) => {
          let cipherArray: Uint8Array = new Uint8Array(ciphertext);
          let encodedCipher: string = this.cryptographicOperations.convertUint8ToString(cipherArray);
          let securityProfile: SecurityProfile = new SecurityProfile();
          securityProfile.certificatePEM = certificatePEM;
          securityProfile.encryptedPrivateKey = encodedCipher;
          securityProfile.agent = user;
          this.certificateService.save(securityProfile).subscribe((result: SecurityProfile) => console.log(result));
        });
      });
    });
  }

  public createSecurityProfile(certificatePEM: string, privateKey: CryptoKey, passphrase: string,
                               user: User): Promise<SecurityProfile> {
    let sequence: Promise<any> = Promise.resolve();

    //Key generation and import region
    let keyArray: Buffer = this.keysGenerationService.generateSymmetricKeyFromPassword(passphrase, 6530, 32, 'SHA256');
    let symmetricKey: CryptoKey;
    sequence = sequence.then(() => this.keysGenerationService.importKey(keyArray, 'raw', 'AES-CTR'))
      .then((key: CryptoKey) => {
        symmetricKey = key;
      });

    //Exporting and encrypting private key. Encoding the encrypted private key
    let encodedEncryptedPrivateKey: string;
    sequence = sequence.then(() => this.keysGenerationService.exportKey(privateKey, 'pkcs8'))
      .then((privateRawKey: ArrayBuffer) => {
        this.cryptographicOperations.encrypt(
          this.cryptographicOperations.getAlgorithm('AES-CTR', 'SHA-256', 'encrypt').algorithm,
          symmetricKey, privateRawKey)
      })
      .then((ciphertext: ArrayBuffer) => {
        let cipherArray: Uint8Array = new Uint8Array(ciphertext);
        encodedEncryptedPrivateKey = this.cryptographicOperations.convertUint8ToString(cipherArray)
      });

    return sequence.then(() => {
      let securityProfile: SecurityProfile = new SecurityProfile();
      securityProfile.certificatePEM = certificatePEM;
      securityProfile.encryptedPrivateKey = encodedEncryptedPrivateKey;
      securityProfile.agent = user;
      return securityProfile;
    });
  }

}
