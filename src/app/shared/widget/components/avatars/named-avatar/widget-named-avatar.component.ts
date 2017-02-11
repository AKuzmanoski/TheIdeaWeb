import {Input, Component} from "@angular/core";
import {Alignment} from "./enum-alignment";
import {AvatarType} from "./enum-avatar-type";
import {AbstractValueAccessor, MakeProvider} from "../../../../abstract-value-accessor";
/**
 * Created by Viki on 10/29/2016.
 */

@Component({
  moduleId: module.id,
  selector: "ideal-widget-named-avatar",
  templateUrl: "widget-named-avatar.component.html",
  styleUrls: ["widget-named-avatar.component.scss"],
  providers: [MakeProvider(WidgetNamedAvatarComponent)]
})
export class WidgetNamedAvatarComponent extends AbstractValueAccessor<string> {
  @Input("radius") radius: number = 50;
  @Input("alignment") alignment: Alignment = Alignment.center;
  @Input("name") name: string = "Guest";
  @Input("description") description: string = "";
  @Input("type") type: AvatarType = AvatarType.CHOOSER;
  @Input("nameFontSize") nameFontSize: string = "12pt";
  @Input("descriptionFontSize") descriptionFontSize: string = "12pt";
  chooserType: AvatarType = AvatarType.CHOOSER;
  displayType: AvatarType = AvatarType.DISPLAY;

  constructor() {
    super("");
  }


  isLeft(): boolean {
    return this.alignment == Alignment.left;
  }

  isRight(): boolean {
    return this.alignment == Alignment.right;
  }

  isCenter(): boolean {
    return this.alignment == Alignment.center;
  }
}
