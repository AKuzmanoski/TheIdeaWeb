import {Component, Input, OnInit} from "@angular/core";
import {Idea} from "../model/ideas/idea";
import {ProtocolTransaction} from "../model/security/protocol-transaction";
import {ProtocolTransactionMessageOne} from "../model/security/messages/protocol-transaction-message-one";
import {ProtocolMessageOneConstructorService} from "../../core/security-protocols/constructors/protocol-messages/protocol-message-one-constructor.service";
/**
 * Created by Viki on 2/19/2017.
 */

@Component({
  moduleId: module.id,
  selector: "ideal-protocol-transaction",
  templateUrl: "protocol-transaction.component.html"
})
export class ProtocolTransactionComponent implements OnInit {
  @Input("idea") idea: Idea;
  @Input("protocolTransaction") protocolTransaction: ProtocolTransaction;

  constructor(private protocolMessageConstructorService: ProtocolMessageOneConstructorService) {
  }

  ngOnInit() {
    if (this.protocolTransaction == null) {
      this.protocolTransaction = new ProtocolTransaction();
    }
  }

  stepOneReady(data: ProtocolTransactionMessageOne) {
    console.log(data);
    let password: string = 'viki';
    this.protocolMessageConstructorService.createProtocolMessageOne(data, this.idea.owner, password);
  }
}
