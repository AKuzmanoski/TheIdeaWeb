import {Component, OnInit} from "@angular/core";
import {Idea} from "../../../domain/model/ideas/idea";
import {ActivatedRoute} from "@angular/router";
import {CertificateService} from "../../../domain/services/certificate/certificate.service";
import {BuyingTransaction} from "../../../domain/model/security/buying-transaction";
/**
 * Created by Viki on 2/19/2017.
 */


@Component({
  moduleId: module.id,
  selector: "ideal-new-transaction-page",
  templateUrl: "new-transaction-page.component.html"
})
export class NewTransactionPageComponent implements OnInit {
  private transaction: BuyingTransaction;

  constructor(private route: ActivatedRoute, private certificateService: CertificateService) {
  }

  ngOnInit() {
    this.route.data.subscribe((data: {idea: Idea}) => {
      this.transaction = new BuyingTransaction();
      this.transaction.idea = data.idea;
    });
  }
}
