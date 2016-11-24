/**
 * Created by AKuzmanoski on 31/10/2016.
 */
import {Component, OnInit, Output, EventEmitter} from "@angular/core";
import {UserService} from "../../../user.service";
import {UserObjectService} from "../../../user-object.service";
import {User} from "../../../../model/authentication/user";
import {Response} from "@angular/http";
import {FieldError} from "../../../../../shared/helper/field-error";
@Component({
  moduleId: module.id,
  selector: "ideal-new-registration-form",
  templateUrl: "new-registration-form.component.html"
})
export class NewRegistrationFormComponent implements OnInit {
  private ConstraintViolationException: string = "ConstraintViolationException";
  private user: User;
  @Output("usernameNotChecked") usernameNotChecked: EventEmitter<void> = new EventEmitter<void>();
  @Output("registrationSuccessful") userReady: EventEmitter<User> = new EventEmitter<User>();
  @Output("constraintViolation") constraintViolation: EventEmitter<FieldError[]> = new EventEmitter<FieldError[]>();

  constructor(private userService: UserService, private userObjectService: UserObjectService) {
    //userObjectService.notify();
  }

  ngOnInit(): void {
    if (this.userObjectService.user != null) {
      this.user = this.userObjectService.user;
    }
    else {
      this.usernameNotChecked.emit();
    }
  }

  save(user: User): void {
    this.user = user;
    this.userService.addUser(this.user).then(
      (user: User) => this.onUserReady(user)
    ).catch((error: Response) => this.onError(error));
  }

  onUserReady(user: User): void {
    console.log("Here");
    this.user = user;
    this.notify();
  }

  onError(error: Response): void {
    if (error.status == 400) {
      let body = error.json();
      if (this.ConstraintViolationException == body.exception) {
        let errors: FieldError[] = body.errors;
        this.constraintViolation.emit(errors);
      }
    }
  }

  notify(): void {
    this.userObjectService.user = this.user;
    this.userReady.emit(this.user);
  }
}
