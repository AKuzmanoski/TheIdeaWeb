import {empty as observableEmpty, Observable, Subject} from 'rxjs';

import {expand} from 'rxjs/operators';
import {Injectable} from '@angular/core';
import {SecurityProfile} from '../../../domain/model/security/security-profile';
import {CryptographicOperations} from '../cryptographic-operations/cryptographic-operations';
import {HelperService} from '../helper.service';
import {KeysService} from '../keys/keys.service';
import {ParserPemService} from '../parsers/parser-pem.service';
import {CertificateService} from '../../../domain/services/certificate/certificate.service';
import Certificate from 'pkijs/src/Certificate';
import {ProtocolSession} from '../../../domain/model/security/protocol-session';
import {UserService} from '../../../domain/services/user/user.service';
import {SimpleSecurityProfile} from '../../../domain/model/security/simple-security-profile';
import {SecurityProfileConstructorService} from './security-profile-constructor.service';
import {SimpleCryptographicOperations} from '../cryptographic-operations/simple-cryptographic-operations';
import {AlgorithmService} from '../algorithms/algorithms.service';
import {DigitalGoodsType} from '../../../domain/model/ideas/digital_goods_type';
import {PaymentType} from '../../../domain/model/payment/payment_type';
import {Contract} from '../../../domain/model';
import {Agent} from '../../../domain/model/authentication';
import {ProtocolTransactionStepOneDataOriginator} from '../../../domain/model/security/data/protocol-transaction-step-one-data-originator';
import {ProtocolTransactionStepOneDataRecipient} from '../../../domain/model/security/data/protocol-transaction-step-one-data-recipient';
import {ProtocolTransactionStepNotice} from '../../../domain/model/security/notices/protocol-transaction-step-notice';
import {
  ProtocolTransactionHistoryStep
} from '../../../domain/protocol-transaction/components/protocol-transaction-history-step-card/protocol-transaction-history-step';
import {PreviousNoticesData} from '../../../domain/model/security/data/previous-notices-data';
import {ProtocolTransactionStepTwoDataRecipient} from '../../../domain/model/security/data/protocol-transaction-step-two-data-recipient';
import {ProtocolTransactionStepTwoDataOriginator} from '../../../domain/model/security/data/protocol-transaction-step-two-data-originator';
import {
  ProtocolTransactionStepThreeDataRecipient
} from '../../../domain/model/security/data/protocol-transaction-step-three-data-recipient';
import {
  ProtocolTransactionStepThreeDataOriginator
} from '../../../domain/model/security/data/protocol-transaction-step-three-data-originator';
import {Payment} from '../../../domain/model/payment/payment';
import {ProtocolTransactionStepFourDataRecipient} from '../../../domain/model/security/data/protocol-transaction-step-four-data-recipient';
import {ProtocolTransactionService} from '../../../domain/services/protocol-transaction/protocol-transaction.service';
import {
  ProtocolTransactionStepFourDataOriginator
} from '../../../domain/model/security/data/protocol-transaction-step-four-data-originator';
import {ProtocolTransactionStepFiveDataRecipient} from '../../../domain/model/security/data/protocol-transaction-step-five-data-recipient';
import {Epo} from '../../../domain/model/security/data/epo';
import {
  ProtocolTransactionStepFiveDataOriginator
} from '../../../domain/model/security/data/protocol-transaction-step-five-data-originator';
import {ProtocolParticipantTwoSessionData} from '../../../domain/model/security/protocol-participant-two-session-data';
import {Money} from '../../../domain/model/payment/money';
import {CertificateOperationsService} from '../certificates/certificate-operations.service';
import {Epoid} from '../../../domain/model/security/data/epoid';
import {ProtocolTransactionStepSevenNotice} from '../../../domain/model/security/notices/protocol-transaction-step-seven-notice';
import {Idea, Solution} from '../../../domain/model/ideas';
import {EncryptingService} from '../encrypting.service';
import {IdeaService} from '../../../domain/services/idea/idea.service';
import {SolutionService} from '../../../domain/services/solution/solution.service';
import {ProtocolTransactionStepSevenData} from '../../../domain/model/security/data/protocol-transaction-step-seven-data';
import {SecurityProfileContext} from '../../../domain/security/security-profile-context/security-profile-context';

/**
 * Created by Viki on 3/1/2017.
 */


@Injectable()
export class ProtocolMessagesReconstructionService {

  private securityProfile: SecurityProfile;
  private protocolSessionSubject: Subject<ProtocolSession>;

  constructor(private securityProfileContext: SecurityProfileContext,
              private cryptographicOperations: CryptographicOperations,
              private simpleCryptographicOperations: SimpleCryptographicOperations,
              private helper: HelperService,
              private algorithmService: AlgorithmService,
              private keysService: KeysService, private pemParser: ParserPemService,
              private certificateService: CertificateService,
              private securityProfileConstructor: SecurityProfileConstructorService,
              private userService: UserService,
              private transactionService: ProtocolTransactionService,
              private certificateOperations: CertificateOperationsService,
              private protocolTransactionService: ProtocolTransactionService,
              private encryptingService: EncryptingService,
              private ideaService: IdeaService,
              private solutionService: SolutionService) {
    this.initializeSecurityProfile();
  }

  public reconstructMessages(array: ProtocolTransactionStepNotice<any>[], password: string,
                             previousNotices: ProtocolTransactionHistoryStep[],
                             previousNoticesData: PreviousNoticesData,
                             protocolSession: ProtocolSession,
                             protocolSessionSubject: Subject<ProtocolSession>,
                             finishInitializationSubject: Subject<boolean>,
                             lastPaymentSubject: Subject<Payment>): Observable<PreviousNoticesData> {

    this.protocolSessionSubject = protocolSessionSubject;
    return this.reconstructProtocolMessage(array.pop(), password, previousNotices, previousNoticesData, protocolSession,
      lastPaymentSubject).pipe(expand((currentStep: ProtocolTransactionStepNotice<any>) => {
      if (array.length > 0) {
        return this.reconstructProtocolMessage(array.pop(), password, previousNotices, previousNoticesData,
          protocolSession, lastPaymentSubject);
      } else {
        finishInitializationSubject.next(true);
        return observableEmpty();
      }
    }));
  }

  public constructProtocolMessageSevenForRecipient(jsonMessage: string, password: string, protocolSession: ProtocolSession,
                                                   previousData: PreviousNoticesData): Observable<ProtocolTransactionStepSevenData> {

    const encryptedMessage: { data: string, iv: string } = JSON.parse(jsonMessage);

    return Observable.create((observer) => {

      // Get simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          // Get the session key that is shared with the server
          this.protocolTransactionService.getSessionKeyWithServer(this.userService.getAuthenticatedUser().email)
            .subscribe((encryptedServerKey: string) => {

              // Decrypt the session key
              this.cryptographicOperations.decrypt(this.algorithmService.getAsymmetricDecryptionAlgorithm().algorithm,
                simpleProfile.privateKeyEncryption, encryptedServerKey)
                .subscribe((decryptedServerKey: string) => {

                  this.keysService.importKey(decryptedServerKey, 'raw', this.algorithmService.SYMMETRIC_ALG)
                    .subscribe((serverSharedKey: CryptoKey) => {

                      // Decrypt the message from the server
                      const alg: AesCtrParams = {
                        counter: this.simpleCryptographicOperations
                          .convertStringToUint8(encryptedMessage.iv).buffer,
                        length: 112,
                        name: this.algorithmService.SYMMETRIC_ALG
                      };

                      this.cryptographicOperations.decrypt(alg, serverSharedKey, encryptedMessage.data)
                        .subscribe((newJsonMessage: string) => {

                          const message: { data: string, signature: string } = JSON.parse(newJsonMessage);

                          // Get iDeal certificate
                          this.certificateOperations.getIDealSecureCertificate()
                            .subscribe((iDealCertificate: Certificate) => {

                              // Get public key from certificate
                              iDealCertificate.getPublicKey()
                                .then((iDealPublicKey: CryptoKey) => {

                                  // Verify the signature
                                  this.cryptographicOperations.verify(this.algorithmService.ASYMMETRIC_SIGNING_ALG,
                                    iDealPublicKey, message.signature, message.data)
                                    .then((verified: boolean) => {

                                      if (verified) {
                                        // Parse receipt
                                        const data: {
                                          epoId: Epoid, key: string, productId: number, payment: string,
                                          buyer: string, owner: string, result: { status: string, message: string }
                                        }
                                          = JSON.parse(message.data);

                                        const stepFiveDataRecipient: ProtocolTransactionStepFiveDataRecipient
                                          = previousData['ProtocolTransactionStepFiveDataRecipient'];
                                        const result: ProtocolTransactionStepSevenData = {};
                                        result.outcome = data.result.status;
                                        result.goodsId = -1;
                                        result.message = data.result.message;

                                        // Check if the receipt data is correct
                                        if (!(stepFiveDataRecipient.epoid.merchant === data.epoId.merchant &&
                                          stepFiveDataRecipient.epoid.timestamp === data.epoId.timestamp &&
                                          stepFiveDataRecipient.epoid.uid === data.epoId.uid) ||
                                          stepFiveDataRecipient.epo.productId !== data.productId ||
                                          stepFiveDataRecipient.epo.payment !== data.payment ||
                                          stepFiveDataRecipient.epo.identity !== data.buyer ||
                                          stepFiveDataRecipient.epo.merchant !== data.owner) {

                                          console.log('Something went wrong');
                                        } else {
                                          // Parse the transaction result
                                          if (data.result.status === 'successful') {
                                            // If the recipient is not the owner recreate the goods
                                            if (protocolSession.digitalGoods.owner.email !==
                                              this.userService.getAuthenticatedUser().email) {

                                              // Parse the key
                                              this.keysService.importKey(data.key, 'raw', this.algorithmService.SYMMETRIC_ALG)
                                                .subscribe((goodsKey: CryptoKey) => {

                                                  // Decrypt the goods
                                                  this.saveEncryptedStringToDigitalGoods(previousData, goodsKey, protocolSession,
                                                    password, data.productId).subscribe((id) => {
                                                    result.goodsId = id;
                                                    observer.next(result);
                                                  });
                                                });
                                            } else {
                                              observer.next(result);
                                            }
                                          } else {
                                            observer.next(result);
                                          }
                                        }

                                      } else {
                                        console.log('Something went wrong');
                                      }
                                    });

                                });
                            });

                        });
                    });
                });
            });
        });
    });
  }

  public constructProtocolMessageSevenForOriginator(jsonMessage: string, password: string, protocolSession: ProtocolSession,
                                                    previousData: PreviousNoticesData): Observable<ProtocolTransactionStepSevenData> {

    const encryptedMessage: { data: string, iv: string } = JSON.parse(jsonMessage);

    return Observable.create((observer) => {

      // Get simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          // Get the session key that is shared with the server
          this.protocolTransactionService.getSessionKeyWithServer(this.userService.getAuthenticatedUser().email)
            .subscribe((encryptedServerKey: string) => {

              // Decrypt the session key
              this.cryptographicOperations.decrypt(this.algorithmService.getAsymmetricDecryptionAlgorithm().algorithm,
                simpleProfile.privateKeyEncryption, encryptedServerKey)
                .subscribe((decryptedServerKey: string) => {

                  this.keysService.importKey(decryptedServerKey, 'raw', this.algorithmService.SYMMETRIC_ALG)
                    .subscribe((serverSharedKey: CryptoKey) => {

                      // Decrypt the message from the server
                      const alg: AesCtrParams = {
                        counter: this.simpleCryptographicOperations
                          .convertStringToUint8(encryptedMessage.iv).buffer,
                        length: 112,
                        name: this.algorithmService.SYMMETRIC_ALG
                      };

                      this.cryptographicOperations.decrypt(alg, serverSharedKey, encryptedMessage.data)
                        .subscribe((newJsonMessage: string) => {

                          const message: { data: string, signature: string } = JSON.parse(newJsonMessage);

                          // Get iDeal certificate
                          this.certificateOperations.getIDealSecureCertificate()
                            .subscribe((iDealCertificate: Certificate) => {

                              // Get public key from certificate
                              iDealCertificate.getPublicKey()
                                .then((iDealPublicKey: CryptoKey) => {

                                  // Verify the signature
                                  this.cryptographicOperations.verify(this.algorithmService.ASYMMETRIC_SIGNING_ALG,
                                    iDealPublicKey, message.signature, message.data)
                                    .then((verified: boolean) => {

                                      if (verified) {
                                        // Parse receipt
                                        const data: {
                                          epoId: Epoid, key: string, productId: number, payment: string,
                                          buyer: string, owner: string, result: { status: string, message: string }
                                        }
                                          = JSON.parse(message.data);

                                        const stepFiveDataOriginator: ProtocolTransactionStepFiveDataOriginator
                                          = previousData['ProtocolTransactionStepFiveDataOriginator'];
                                        const result: ProtocolTransactionStepSevenData = {};
                                        result.outcome = data.result.status;
                                        result.goodsId = -1;
                                        result.message = data.result.message;

                                        // Check if the receipt data is correct
                                        if (!(stepFiveDataOriginator.epoid.merchant === data.epoId.merchant &&
                                          stepFiveDataOriginator.epoid.timestamp === data.epoId.timestamp &&
                                          stepFiveDataOriginator.epoid.uid === data.epoId.uid) ||
                                          stepFiveDataOriginator.productId !== data.productId ||
                                          stepFiveDataOriginator.payment.getText() !== data.payment ||
                                          stepFiveDataOriginator.identity !== data.buyer ||
                                          stepFiveDataOriginator.merchant !== data.owner) {

                                          console.log('Something went wrong');
                                        } else {
                                          // Parse the transaction result
                                          if (data.result.status === 'successful') {
                                            // If the recipient is not the owner recreate the goods
                                            if (protocolSession.digitalGoods.owner.email
                                              !== this.userService.getAuthenticatedUser().email) {

                                              // Parse the key
                                              this.keysService.importKey(data.key, 'raw', this.algorithmService.SYMMETRIC_ALG)
                                                .subscribe((goodsKey: CryptoKey) => {

                                                  // Decrypt the goods
                                                  // this.saveEncryptedStringToDigitalGoods(previousData, goodsKey, protocolSession,
                                                  //     password, data.productId).subscribe((id) => {
                                                  //     result.goodsId = id;
                                                  //     observer.next(result);
                                                  // });
                                                  result.goodsId = 138458;
                                                  observer.next(result);
                                                });
                                            } else {
                                              observer.next(result);
                                            }
                                          } else {
                                            observer.next(result);
                                          }
                                        }

                                      } else {
                                        console.log('Something went wrong');
                                      }
                                    });

                                });
                            });

                        });
                    });
                });
            });
        });
    });
  }

  private reconstructProtocolMessage(currentStep: ProtocolTransactionStepNotice<any>, password: string,
                                     previousNotices: ProtocolTransactionHistoryStep[],
                                     previousNoticesData: PreviousNoticesData,
                                     protocolSession: ProtocolSession,
                                     lastPaymentSubject: Subject<Payment>): Observable<PreviousNoticesData> {
    const historyStep = {
      messageType: currentStep.type,
      originator: currentStep.originator.email,
      when: currentStep.creationDate
    };
    previousNotices.push(historyStep);

    return Observable.create((observer) => {

      // Processing Protocol transaction steps
      if (currentStep.type === 'ProtocolTransactionStepOneNotice') {
        // Check if the authenticated user is originator or recipient of the message
        if (currentStep.originator.email === this.userService.getAuthenticatedUser().email) {
          this.constructProtocolMessageOneForOriginator(currentStep.message, password, protocolSession)
            .subscribe((data: ProtocolTransactionStepOneDataOriginator) => {
              previousNoticesData['ProtocolTransactionStepOneDataOriginator'] = data;
              lastPaymentSubject.next(data.bid);
              observer.next(previousNoticesData);
            });
        } else {
          this.constructProtocolMessageOneForRecipient(currentStep.message, password, protocolSession)
            .subscribe((data: ProtocolTransactionStepOneDataRecipient) => {
              previousNoticesData['ProtocolTransactionStepOneDataRecipient'] = data;
              lastPaymentSubject.next(data.bid);
              observer.next(previousNoticesData);
            });
        }
      } else if (currentStep.type === 'ProtocolTransactionStepTwoNotice') {
        // Check if the authenticated user is originator or recipient of the message
        if (currentStep.originator.email === this.userService.getAuthenticatedUser().email) {
          this.constructProtocolMessageTwoForOriginator(currentStep.message, password,
            protocolSession, previousNoticesData)
            .subscribe((data: ProtocolTransactionStepTwoDataOriginator) => {
              previousNoticesData['ProtocolTransactionStepTwoDataOriginator'] = data;
              lastPaymentSubject.next(data.payment);
              observer.next(previousNoticesData);
            });
        } else {
          this.constructProtocolMessageTwoForRecipient(currentStep.message, password,
            protocolSession, previousNoticesData)
            .subscribe((data: ProtocolTransactionStepTwoDataRecipient) => {
              previousNoticesData['ProtocolTransactionStepTwoDataRecipient'] = data;
              lastPaymentSubject.next(data.payment);
              observer.next(previousNoticesData);
            });
        }
      } else if (currentStep.type === 'ProtocolTransactionStepThreeNotice') {
        // Check if the authenticated user is originator or recipient of the message
        if (currentStep.originator.email === this.userService.getAuthenticatedUser().email) {
          this.constructProtocolMessageThreeForOriginator(currentStep.message, password, protocolSession)
            .subscribe((data: ProtocolTransactionStepThreeDataOriginator) => {
              previousNoticesData['ProtocolTransactionStepThreeDataOriginator'] = data;
              observer.next(previousNoticesData);
            });
        } else {
          this.constructProtocolMessageThreeForRecipient(currentStep.message, password,
            protocolSession, previousNoticesData)
            .subscribe((data: ProtocolTransactionStepThreeDataRecipient) => {
              previousNoticesData['ProtocolTransactionStepThreeDataRecipient'] = data;
              observer.next(previousNoticesData);
            });
        }
      } else if (currentStep.type === 'ProtocolTransactionStepFourNotice') {
        if (currentStep.originator.email === this.userService.getAuthenticatedUser().email) {
          this.constructProtocolMessageFourForOriginator(currentStep.message, password, protocolSession)
            .subscribe((data: ProtocolTransactionStepFourDataOriginator) => {
              previousNoticesData['ProtocolTransactionStepFourDataOriginator'] = data;
              observer.next(previousNoticesData);
            });
        } else {
          this.constructProtocolMessageFourForRecipient(currentStep.message, password, protocolSession)
            .subscribe((data: ProtocolTransactionStepFourDataRecipient) => {
              previousNoticesData['ProtocolTransactionStepFourDataRecipient'] = data;
              observer.next(previousNoticesData);
            });
        }
      } else if (currentStep.type === 'ProtocolTransactionStepFiveNotice') {
        if (currentStep.originator.email === this.userService.getAuthenticatedUser().email) {
          this.constructProtocolMessageFiveForOriginator(currentStep.message, password, protocolSession)
            .subscribe((data: ProtocolTransactionStepFiveDataOriginator) => {
              previousNoticesData['ProtocolTransactionStepFiveDataOriginator'] = data;
              observer.next(previousNoticesData);
            });
        } else {
          this.constructProtocolMessageFiveForRecipient(currentStep.message, password,
            protocolSession, previousNoticesData)
            .subscribe((data: ProtocolTransactionStepFiveDataRecipient) => {
              previousNoticesData['ProtocolTransactionStepFiveDataRecipient'] = data;
              observer.next(previousNoticesData);
            });
        }
      } else if (currentStep.type === 'ProtocolTransactionStepSevenNotice') {
        if (protocolSession.digitalGoods.owner.email !== this.userService.getAuthenticatedUser().email) {
          this.constructProtocolMessageSevenForOriginator(currentStep.message, password, protocolSession, previousNoticesData)
            .subscribe((data: ProtocolTransactionStepSevenData) => {
              previousNoticesData['ProtocolTransactionStepSevenData'] = data;
              observer.next(previousNoticesData);
            });
        } else {
          this.constructProtocolMessageSevenForRecipient(currentStep.message, password, protocolSession, previousNoticesData)
            .subscribe((data: ProtocolTransactionStepSevenData) => {
              previousNoticesData['ProtocolTransactionStepSevenData'] = data;
              observer.next(previousNoticesData);
            });
        }
      }
    });
  }

  private initializeSecurityProfile() {
    this.securityProfile = this.securityProfileContext.get();
    this.securityProfileContext.getObservable().subscribe((securityProfile: SecurityProfile) => {
      this.securityProfile = securityProfile;
    });
  }

  private constructProtocolMessageOneForRecipient(jsonMessage: string, password: string,
                                                  protocolSession: ProtocolSession): Observable<ProtocolTransactionStepOneDataRecipient> {

    return Observable.create((observer) => {

      const result: ProtocolTransactionStepOneDataRecipient = {};

      const message: { 'signature': string, 'primaryData': string, 'data': string, 'dataIntegrity': string } =
        JSON.parse(jsonMessage);

      // Integrity check of the data sent
      if (this.simpleCryptographicOperations.hash(message.data) === message.dataIntegrity) {

        // Initialize Simple Security Profile
        this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
          .subscribe((simpleSecurityProfile: SimpleSecurityProfile) => {

            // Decrypting object
            this.cryptographicOperations.decrypt(this.algorithmService.getAsymmetricDecryptionAlgorithm().algorithm,
              simpleSecurityProfile.privateKeyEncryption, message.primaryData).subscribe((jsonObject: string) => {

              // Parse decrypted object in JSON
              const object: { sessionKey: string, nonce: string, identity: string } = JSON.parse(jsonObject);
              result.nonce = object.nonce;
              result.identity = object.identity;

              // Get other party certificate to verify the signature
              this.getOtherPartySignatureVerifyingKey(protocolSession)
                .subscribe((otherPartyPublicKey: CryptoKey) => {

                  // Verify other party signature
                  this.cryptographicOperations.verify(this.algorithmService.ASYMMETRIC_SIGNING_ALG,
                    otherPartyPublicKey,
                    message.signature,
                    this.simpleCryptographicOperations.hash(jsonObject)).then((verifyResult: boolean) => {
                    if (verifyResult) {

                      // Import session key from string into CryptoKey
                      this.keysService.importKey(object.sessionKey, 'raw', this.algorithmService.SYMMETRIC_ALG)
                        .subscribe((sessionKey: CryptoKey) => {
                          result.sessionKey = sessionKey;

                          // Add the session key encrypted with own public key into protocol session
                          this.keysService.encryptSessionKey(sessionKey, simpleSecurityProfile.publicKey)
                            .subscribe((encryptedSessionKey: string) => {
                              if (protocolSession.participantTwoSessionData == null) {
                                const participant: ProtocolParticipantTwoSessionData = new ProtocolParticipantTwoSessionData();
                                participant.participant = this.userService.getAuthenticatedUser();
                                participant.sessionKeyEncrypted = encryptedSessionKey;
                                protocolSession.participantTwoSessionData = participant;
                                this.transactionService.saveProtocolSession(protocolSession).subscribe();
                              }

                              // Decrypt data sent with session key
                              this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                                sessionKey, message.data).subscribe((jsonData: string) => {
                                const data:
                                  {
                                    appData: {
                                      'goodsType': DigitalGoodsType,
                                      'paymentType': PaymentType
                                    },
                                    bid: string,
                                    tid: number
                                  }
                                  = JSON.parse(jsonData);

                                if (data.appData.paymentType === PaymentType.Money) {
                                  result.bid = new Money();
                                } else {
                                  result.bid = new Contract();
                                }
                                result.bid.constructObject(data.bid);
                                result.tid = data.tid;
                                result.paymentType = data.appData.paymentType;
                                result.goodsType = data.appData.goodsType;
                                observer.next(result);
                              });
                            });
                        });

                    } else {
                      this.abortSession(protocolSession, observer);
                    }
                  });
                });
            });
          });

      } else {
        protocolSession.aborted = true;
        this.transactionService.saveProtocolSession(protocolSession).subscribe((newProtocolSession) => {
          this.protocolSessionSubject.next(newProtocolSession);
        });
      }
    });
  }

  private constructProtocolMessageOneForOriginator(jsonMessage: string, password: string,
                                                   protocolSession: ProtocolSession): Observable<ProtocolTransactionStepOneDataOriginator> {
    return Observable.create((observer) => {
      const result: ProtocolTransactionStepOneDataOriginator = {};

      // Parse the json message into an object
      const message: { 'signature': string, 'primaryData': string, 'data': string, 'dataIntegrity': string } =
        JSON.parse(jsonMessage);

      // Initialize simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleSecurityProfile: SimpleSecurityProfile) => {

          // Get the encrypted session key for the authenticated user
          const encryptedSessionKey: string = this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession);

          // Decrypt the session key
          this.keysService.decryptSessionKey(encryptedSessionKey, simpleSecurityProfile.privateKeyEncryption)
            .subscribe((sessionKey: CryptoKey) => {

              // Decrypt the data in the sent message
              this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                sessionKey, message.data).subscribe((jsonData: string) => {

                // Parse the json data into an object
                const data: {
                  'appData': { 'goodsType': DigitalGoodsType, 'paymentType': PaymentType },
                  'bid': string, 'tid': number
                } = JSON.parse(jsonData);

                result.paymentType = data.appData.paymentType;
                result.goodsType = data.appData.goodsType;
                if (data.appData.paymentType === PaymentType.Money) {
                  result.bid = new Money();
                } else {
                  result.bid = new Contract();
                }
                result.bid.constructObject(data.bid);
                result.tid = data.tid;

                this.cryptographicOperations.decrypt(this.algorithmService.getAsymmetricDecryptionAlgorithm().algorithm,
                  simpleSecurityProfile.privateKeyEncryption, protocolSession.participantOneSessionData.nonce)
                  .subscribe((nonce: string) => {

                    result.nonce = nonce;
                    observer.next(result);
                  });
              });
            });
        });
    });
  }

  private constructProtocolMessageTwoForRecipient(jsonMessage: string, password: string, protocolSession: ProtocolSession,
                                                  previousData: PreviousNoticesData): Observable<ProtocolTransactionStepTwoDataRecipient> {

    return Observable.create((observer) => {

      // Parse the json string into an object
      const message: { signature: string, data: string } = JSON.parse(jsonMessage);

      // Get other party certificate to verify the signature
      this.getOtherPartySignatureVerifyingKey(protocolSession).subscribe((otherPartyPublicKey: CryptoKey) => {

        // Verify other party signature
        this.cryptographicOperations.verify(this.algorithmService.ASYMMETRIC_SIGNING_ALG,
          otherPartyPublicKey,
          message.signature,
          this.simpleCryptographicOperations.hash(message.data)).then((verifyResult: boolean) => {

          if (verifyResult) {
            // Get encrypted session key
            const encryptedSessionKey: string = this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession);

            // Initialize Simple Security Profile
            this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
              .subscribe((simpleSecurityProfile: SimpleSecurityProfile) => {

                // Decrypt session key
                this.keysService.decryptSessionKey(encryptedSessionKey, simpleSecurityProfile.privateKeyEncryption)
                  .subscribe((sessionKey: CryptoKey) => {

                    // Decrypt message data
                    this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                      sessionKey, message.data).subscribe((decryptedDataJson: string) => {


                      const decryptedData:
                        { productId: number, payment: string, nonce: string, tid: number } = JSON.parse(decryptedDataJson);

                      const result: ProtocolTransactionStepTwoDataRecipient = {};
                      const stepOneData: ProtocolTransactionStepOneDataOriginator =
                        previousData['ProtocolTransactionStepOneDataOriginator'];

                      if (stepOneData.nonce === decryptedData.nonce) {
                        if (stepOneData.paymentType === PaymentType.Money) {
                          const price: Money = new Money();
                          price.constructObject(decryptedData.payment);
                          result.payment = price;
                        } else if (stepOneData.paymentType === PaymentType.Contract) {
                          const contract: Contract = new Contract();
                          contract.constructObject(decryptedData.payment);
                          result.payment = contract;
                        }

                        result.productId = decryptedData.productId;
                        result.nonce = decryptedData.nonce;
                        result.tid = decryptedData.tid;

                        observer.next(result);
                      } else {
                        this.abortSession(protocolSession, observer);
                      }
                    });
                  });

              });
          } else {
            this.abortSession(protocolSession, observer);
          }
        });
      });
    });
  }

  private constructProtocolMessageTwoForOriginator(jsonMessage: string, password: string, protocolSession: ProtocolSession,
                                                   previousData: PreviousNoticesData)
    : Observable<ProtocolTransactionStepTwoDataOriginator> {

    return Observable.create((observer) => {
      // Parse the json string into an object
      const message: { signature: string, data: string } = JSON.parse(jsonMessage);

      // Initialize Simple Security Profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleSecurityProfile: SimpleSecurityProfile) => {

          // Get encrypted session key
          const encryptedSessionKey: string = this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession);

          // Decrypt session key
          this.keysService.decryptSessionKey(encryptedSessionKey, simpleSecurityProfile.privateKeyEncryption)
            .subscribe((sessionKey: CryptoKey) => {

              // Decrypt message data
              this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                sessionKey, message.data).subscribe((decryptedDataJson: string) => {


                const decryptedData: { productId: number, payment: string, nonce: number, tid: number } = JSON.parse(decryptedDataJson);
                const result: ProtocolTransactionStepTwoDataOriginator = {};
                const stepOneData: ProtocolTransactionStepOneDataRecipient = previousData['ProtocolTransactionStepOneDataRecipient'];
                if (stepOneData.paymentType === PaymentType.Money) {
                  const price: Money = new Money();
                  price.constructObject(decryptedData.payment);
                  result.payment = price;
                } else if (stepOneData.paymentType === PaymentType.Contract) {
                  const contract: Contract = new Contract();
                  contract.constructObject(decryptedData.payment);
                  result.payment = contract;
                }

                console.log(result.payment.getText());

                result.productId = decryptedData.productId;
                result.nonce = decryptedData.nonce;
                result.tid = decryptedData.tid;
                observer.next(result);

              });
            });

        });
    });
  }

  private constructProtocolMessageThreeForRecipient(jsonMessage: string, password: string, protocolSession: ProtocolSession,
                                                    previousData: PreviousNoticesData)
    : Observable<ProtocolTransactionStepThreeDataRecipient> {

    return Observable.create((observer) => {

      // Construct Simple Security Profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          // Parse JSON into an object
          const message: { signature: string, data: string } = JSON.parse(jsonMessage);
          const result: ProtocolTransactionStepThreeDataRecipient = {};

          // Extract the session key
          this.keysService.decryptSessionKey(this.helper
              .getEncryptedSessionKeyForAuthenticatedUser(protocolSession),
            simpleProfile.privateKeyEncryption).subscribe((sessionKey: CryptoKey) => {

            // Decrypt data
            this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
              sessionKey, message.data).subscribe((jsonData: string) => {

              const data: { identity: string, tid: number, nonce: number } = JSON.parse(jsonData);
              const stepTwoData: ProtocolTransactionStepTwoDataOriginator =
                previousData['ProtocolTransactionStepTwoDataOriginator'];

              // Extract other party verifying public key
              this.getOtherPartySignatureVerifyingKey(protocolSession).subscribe(
                (otherPartyVerifyingKey: CryptoKey) => {

                  // Verify signature
                  this.cryptographicOperations.verify(this.algorithmService.ASYMMETRIC_SIGNING_ALG,
                    otherPartyVerifyingKey, message.signature,
                    this.simpleCryptographicOperations.hash(jsonData))
                    .then((verifyResult: boolean) => {
                      if (verifyResult) {

                        // Verify the nonce and transaction id
                        if (data.nonce === stepTwoData.nonce && data.tid === stepTwoData.tid + 1) {
                          result.identity = data.identity;
                          result.tid = data.tid;
                          result.nonce = data.nonce;

                          observer.next(result);
                        } else {
                          this.abortSession(protocolSession, observer);
                        }

                      } else {
                        this.abortSession(protocolSession, observer);
                      }
                    });
                });

            });

          });
        });
    });
  }

  private constructProtocolMessageThreeForOriginator(jsonMessage: string, password: string,
                                                     protocolSession: ProtocolSession)
    : Observable<ProtocolTransactionStepThreeDataOriginator> {
    return Observable.create((observer) => {

      // Construct Simple Security Profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          // Parse JSON into an object
          const message: { signature: string, data: string } = JSON.parse(jsonMessage);
          const result: ProtocolTransactionStepThreeDataOriginator = {};

          // Extract the session key
          this.keysService.decryptSessionKey(this.helper
              .getEncryptedSessionKeyForAuthenticatedUser(protocolSession),
            simpleProfile.privateKeyEncryption).subscribe((sessionKey: CryptoKey) => {

            // Decrypt data
            this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
              sessionKey, message.data).subscribe((jsonData: string) => {

              const data: { identity: string, tid: number, nonce: number } = JSON.parse(jsonData);

              result.identity = data.identity;
              result.tid = data.tid;
              result.nonce = data.nonce;
              observer.next(result);
            });

          });
        });
    });
  }

  private constructProtocolMessageFourForRecipient(jsonMessage: string, password: string,
                                                   protocolSession: ProtocolSession): Observable<ProtocolTransactionStepFourDataRecipient> {

    return Observable.create((observer) => {

      // Parse JSON message
      const message: { goods: string, dataIntegrity: string } = JSON.parse(jsonMessage);

      // Initialize result
      const result: ProtocolTransactionStepFourDataRecipient = {};

      // Construct simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          result.goods = message.goods;

          // Decrypt session key
          this.keysService.decryptSessionKey(this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession),
            simpleProfile.privateKeyEncryption).subscribe((sessionKey: CryptoKey) => {

            // Decrypt dataIntegrity part
            this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
              sessionKey, message.dataIntegrity).subscribe((dataIntegrityDecrypted: string) => {

              // Parse JSON from data integrity
              const dataIntegrity: { goodsIntegrity: string, epoid: string } = JSON.parse(dataIntegrityDecrypted);

              // Verify that goods are intact
              const messageGoodsHashed = this.simpleCryptographicOperations.hash(message.goods);

              if (messageGoodsHashed === dataIntegrity.goodsIntegrity) {
                result.epoid = JSON.parse(dataIntegrity.epoid);

                // Update protocol session in order to setContext the encrypted goods
                protocolSession.participantOneSessionData.encryptedGoods = result.goods;
                this.transactionService.saveProtocolSession(protocolSession)
                  .subscribe((value: ProtocolSession) => {
                    observer.next(result);
                  });
              } else {
                this.abortSession(protocolSession, observer);
              }

            });
          });
        });
    });
  }

  private constructProtocolMessageFourForOriginator(jsonMessage: string, password: string,
                                                    protocolSession: ProtocolSession):
    Observable<ProtocolTransactionStepFourDataOriginator> {

    return Observable.create((observer) => {
      // Parse JSON message
      const message: { goods: string, dataIntegrity: string } = JSON.parse(jsonMessage);

      // Initialize result
      const result: ProtocolTransactionStepFourDataRecipient = {};

      // Construct simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          result.goods = message.goods;

          // Decrypt session key
          this.keysService.decryptSessionKey(this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession),
            simpleProfile.privateKeyEncryption).subscribe((sessionKey: CryptoKey) => {

            // Decrypt dataIntegrity part
            this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
              sessionKey, message.dataIntegrity).subscribe((dataIntegrityDecrypted: string) => {

              // Parse JSON from data integrity
              const dataIntegrity: { goodsIntegrity: string, epoid: string } = JSON.parse(dataIntegrityDecrypted);

              result.epoid = JSON.parse(dataIntegrity.epoid);

              observer.next(result);

            });
          });
        });
    });
  }

  private constructProtocolMessageFiveForRecipient(jsonMessage: string, password: string, protocolSession: ProtocolSession,
                                                   previousData: PreviousNoticesData)
    : Observable<ProtocolTransactionStepFiveDataRecipient> {

    const message: { signature: string, data: string } = JSON.parse(jsonMessage);
    const result: ProtocolTransactionStepFiveDataRecipient = {};

    return Observable.create((observer) => {

      // Construct simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          // Decrypt session key
          this.keysService.decryptSessionKey(this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession),
            simpleProfile.privateKeyEncryption)
            .subscribe((sessionKey: CryptoKey) => {

              // Decrypt message data
              this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                sessionKey, message.data)
                .subscribe((decryptedData: string) => {

                  // Decrypt signature
                  this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                    sessionKey, message.signature).subscribe((signature: string) => {

                    // Verify message signature
                    this.getOtherPartySignatureVerifyingKey(protocolSession)
                      .subscribe((otherPartyVerifyingKey: CryptoKey) => {

                        this.cryptographicOperations.verify(this.algorithmService.ASYMMETRIC_SIGNING_ALG,
                          otherPartyVerifyingKey, signature, decryptedData)
                          .then((signatureVerified: boolean) => {

                            if (signatureVerified) {

                              // Parse data into an object
                              const data: { epo: Epo, nonce: number } = JSON.parse(decryptedData);

                              // Initialize result
                              result.nonce = data.nonce;
                              result.epoid = JSON.parse(data.epo.epoid);
                              result.identity = data.epo.identity;
                              result.merchant = data.epo.merchant;
                              result.productId = data.epo.productId;
                              let payment: Payment;
                              const appData: { goodsType: DigitalGoodsType, paymentType: PaymentType } = JSON.parse(data.epo.appData);
                              if (appData.paymentType === PaymentType.Contract) {
                                payment = new Contract();
                              } else if (appData.paymentType === PaymentType.Money) {
                                payment = new Money();
                              }

                              console.log(data.epo.payment);

                              payment.constructObject(data.epo.payment);
                              result.payment = payment;
                              result.signature = signature;
                              result.epo = data.epo;

                              const stepFourData: ProtocolTransactionStepFourDataOriginator =
                                previousData['ProtocolTransactionStepFourDataOriginator'];
                              const stepThreeData: ProtocolTransactionStepThreeDataRecipient =
                                previousData['ProtocolTransactionStepThreeDataRecipient'];
                              const stepTwoData: ProtocolTransactionStepTwoDataOriginator =
                                previousData['ProtocolTransactionStepTwoDataOriginator'];

                              // Check if the data sent is correct
                              if (JSON.stringify(result.epoid) === JSON.stringify(stepFourData.epoid) &&
                                result.identity === stepThreeData.identity &&
                                result.productId === protocolSession.digitalGoods.id &&
                                result.merchant === this.userService.getAuthenticatedUser().email &&
                                data.epo.payment === stepTwoData.payment.getText()) {

                                observer.next(result);
                              } else {
                                this.abortSession(protocolSession, observer);
                              }
                            } else {
                              this.abortSession(protocolSession, observer);
                            }
                          });
                      });
                  });
                });
            });
        });
    });
  }

  private constructProtocolMessageFiveForOriginator(jsonMessage: string, password: string,
                                                    protocolSession: ProtocolSession)
    : Observable<ProtocolTransactionStepFiveDataOriginator> {

    const message: { signature: string, data: string } = JSON.parse(jsonMessage);
    const result: ProtocolTransactionStepFiveDataOriginator = {};

    return Observable.create((observer) => {

      // Construct simple security profile
      this.securityProfileConstructor.getSecurityProfileSimple(password, this.securityProfile)
        .subscribe((simpleProfile: SimpleSecurityProfile) => {

          // Decrypt session key
          this.keysService.decryptSessionKey(this.helper.getEncryptedSessionKeyForAuthenticatedUser(protocolSession),
            simpleProfile.privateKeyEncryption)
            .subscribe((sessionKey: CryptoKey) => {

              // Decrypt message data
              this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
                sessionKey, message.data)
                .subscribe((decryptedData: string) => {

                  // Parse data into an object
                  const data: { epo: Epo, nonce: number } = JSON.parse(decryptedData);

                  // Initialize result
                  result.nonce = data.nonce;
                  result.epoid = JSON.parse(data.epo.epoid);
                  result.identity = data.epo.identity;
                  result.merchant = data.epo.merchant;
                  result.productId = data.epo.productId;
                  let payment: Payment;
                  const appData: { goodsType: DigitalGoodsType, paymentType: PaymentType } = JSON.parse(data.epo.appData);
                  if (appData.paymentType === PaymentType.Contract) {
                    payment = new Contract();
                  } else if (appData.paymentType === PaymentType.Money) {
                    payment = new Money();
                  }
                  payment.constructObject(data.epo.payment);
                  result.payment = payment;

                  observer.next(result);

                });
            });
        });
    });
  }

  private saveEncryptedStringToDigitalGoods(previousData: PreviousNoticesData, decryptionKey: CryptoKey,
                                            protocolSession: ProtocolSession, password: string,
                                            goodsId: number): Observable<number> {

    return Observable.create((observer) => {
      const protocolTransactionStepOneDataForOriginator: ProtocolTransactionStepOneDataOriginator =
        previousData['ProtocolTransactionStepOneDataOriginator'];

      this.cryptographicOperations.decrypt(this.algorithmService.getSymmetricDecryptionAlgorithm().algorithm,
        decryptionKey, protocolSession.participantOneSessionData.encryptedGoods)
        .subscribe((goods: string) => {

          console.log(goods);

          // Different approaches based on the goods type
          if (protocolTransactionStepOneDataForOriginator.goodsType === DigitalGoodsType.Solution) {
            this.ideaService.getIdea(goodsId).subscribe((goodsIdea: Idea) => {
              const idea = new Idea();
              idea.problem = goodsIdea.problem;
              idea.snackPeak = goodsIdea.snackPeak;
              idea.title = goodsIdea.title;
              idea.keywords = goodsIdea.keywords;
              const solution = new Solution();
              solution.idea = idea;
              this.encryptingService.encryptSolution(goods, password).subscribe((encryptedSolution) => {
                solution.text = encryptedSolution;

                // Save the new solution
                this.solutionService.addSolution(solution).subscribe((savedSolution: Solution) => {
                  observer.next(savedSolution.idea.id);
                });
              });
            });
          } else if (protocolTransactionStepOneDataForOriginator.goodsType === DigitalGoodsType.Evaluation) {
            // TODO: Implement if the good type is evaluation
          }
        });
    });
  }

  // TODO: Validate the certificate carefully
  private getOtherPartySignatureVerifyingKey(protocolSession: ProtocolSession): Observable<CryptoKey> {
    const agent: Agent = this.userService.getAuthenticatedUser();
    let otherPartyEmail: string;

    if (protocolSession.participantOneSessionData.participant.email === agent.email) {
      otherPartyEmail = protocolSession.participantTwoSessionData.participant.email;
    } else {
      otherPartyEmail = protocolSession.participantOneSessionData.participant.email;
    }

    return Observable.create((observer) => {

      // Request other party certificate
      this.certificateService.get({email: otherPartyEmail})
        .subscribe((otherPartyCertificatePEM: string) => {
          const certificate: Certificate = this.pemParser
            .parseCertificateFromPem(otherPartyCertificatePEM);

          // Request issuer certificate
          this.certificateService.getIssuerCertificate().subscribe(
            (issuerCertificatePEM: string) => {
              const issuer: Certificate = this.pemParser
                .parseCertificateFromPem(issuerCertificatePEM);

              // Verify certificate
              certificate.verify(issuer).then((verfied: boolean) => {
                if (verfied) {

                  // Extract public key from certificate
                  certificate.getPublicKey().then((otherPartyPublicKey: CryptoKey) => {
                    observer.next(otherPartyPublicKey);
                  });

                } else {
                  console.log('Certificate did not verify');
                }
              });

            });
        });
    });

  }

  private abortSession(protocolSession: ProtocolSession, observer) {
    protocolSession.aborted = true;
    this.transactionService.saveProtocolSession(protocolSession).subscribe((newProtocolSession) => {
      this.protocolSessionSubject.next(newProtocolSession);
      observer.next({});
    });
  }

}
