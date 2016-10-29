import {Component} from "@angular/core";
import {Alignment} from "../../../shared/widget/components/named-avatar/enum-alignment";
/**
 * Created by Viki on 10/28/2016.
 */

@Component({
  moduleId: module.id,
  selector: "ideal-auth-card",
  templateUrl: "auth-card.component.html"
})
export class AuthCardComponent {
  namedAvatarAlignment: Alignment = Alignment.center;
  firstName: string = "";
}
