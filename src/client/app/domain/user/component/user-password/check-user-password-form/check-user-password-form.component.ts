import {Component, OnInit, Output, EventEmitter} from "@angular/core";
import {User} from "../../../../model/authentication/user";
import {UserService} from "../../../user.service";
import {Response} from "@angular/http";
import {Credentials} from "../../../helper/Credentials";
import {JwtSecurityContext} from "../../../../../core/authentication/jwt/jwt-security-context.service";
import {UserObjectService} from "../../../user-object.service";
/**
 * Created by Viki on 11/1/2016.
 */

@Component({
  moduleId: module.id,
  selector: "ideal-check-user-password-form",
  templateUrl: "check-user-password-form.component.html"
})
export class CheckUserPasswordFormComponent implements OnInit {
  @Output("usernameNotChecked") usernameNotChecked: EventEmitter<void> = new EventEmitter<void>();
  @Output("passwordCorrect") passwordCorrect: EventEmitter<User> = new EventEmitter<User>();
  @Output("passwordIncorrect") passwordIncorrect: EventEmitter<void> = new EventEmitter<void>();

  constructor(private userService: UserService, private userObjectService: UserObjectService) {
  }

  user: User;

  ngOnInit(): void {
    this.user = this.userObjectService.user;
    if (this.user == null) {
      this.usernameNotChecked.emit();
    }
    this.user.password = "";
  }

  checkUserPassword(credentials: Credentials) {
    this.userService.loginUser(credentials).subscribe((response: Response) => this.onPasswordCorrect(response),
      (error: Response) => this.onPasswordWrong(error));
  }

  private onPasswordWrong(error: Response) {
    this.notifyPasswordWrong();
  }

  private onPasswordCorrect(response: Response) {
    this.notifyPasswordCorrect()
  }

  notifyPasswordCorrect(): void {
    this.passwordCorrect.emit(this.user);
  }

  notifyPasswordWrong(): void {
    this.passwordIncorrect.emit();
  }
}

