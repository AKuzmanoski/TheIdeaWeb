import {Component, OnInit, HostBinding} from "@angular/core";
import {ActivatedRoute, Params, Router} from "@angular/router";
import {User} from "../../domain/model/authentication/user";
import {MdSnackBar} from "@angular/material";
import {FieldError} from "../../core/helper/field-error";
import {enterRightLeaveRight, routerAnimations} from "../../core/helper/standard-route-animations";
import {AuthProperties} from "../auth.properties";
/**
 * Created by AKuzmanoski on 29/10/2016.
 */
@Component({
  moduleId: module.id,
  selector: "ideal-register-page",
  templateUrl: "register-page.component.html",
  animations: [
    enterRightLeaveRight('routeAnimation')
  ]
})
export class RegisterPageComponent implements OnInit {
  @HostBinding("@routeAnimation") get routeAnimation() {
    return true;
  }

  @HostBinding("style.display") get display() {
    return "block";
  }

  @HostBinding("style.position") get position() {
    return "relative";
  }

  @HostBinding("style.opacity") get opacity() {
    return 1;
  }


  @HostBinding("style.width") get width() {
    return "100%";
  }

  email: string;
  returnUrl: string;

  constructor(private router: Router, private route: ActivatedRoute, private snackBar: MdSnackBar) {
  }

  ngOnInit(): void {
    this.route.queryParams.subscribe((params: Params) => {
      this.email = params['email'];
      this.returnUrl = params["returnUrl"];
    });
  }

  authenticate(): void {
    let queryParams: AuthProperties = {};
    if (this.email != null)
      queryParams.email = this.email;
    if (this.returnUrl != null)
      queryParams.returnUrl = this.returnUrl;
    this.router.navigate(["auth"], {queryParams: queryParams});
  }

  login(user: User): void {
    this.snackBar.open("Your registration is successful!", undefined, {duration: 3000});
    let queryParams: AuthProperties = {};
    if (this.email != null)
      queryParams.email = this.email;
    if (this.returnUrl != null)
      queryParams.returnUrl = this.returnUrl;
    this.router.navigate(["auth"], {queryParams: queryParams});
  }

  registered(user: User): void {

  }

  constraintsViolated(fieldErrors: FieldError[]): void {
    let message: string = "";
    for (let fieldError of fieldErrors) {
      message += "[" + fieldError.field + "] " + fieldError.message + "\n";
    }
    message = message.substring(0, message.length - 1);
    this.snackBar.open(message, 'Try Again', {duration: 3000});
  }
}
