/**
 * Created by AKuzmanoski on 25/12/2016.
 */
import {Component, OnInit} from '@angular/core';
import {Router} from '@angular/router';
import {UserService} from '../../domain/services/user/user.service';
import {User} from '../../domain/model/authentication/user';

@Component({
  moduleId: module.id,
  selector: 'ideal-authenticated-user-details',
  template: ``
})
export class AuthenticationUserDetailsPageComponent implements OnInit {
  constructor(private router: Router, private userService: UserService) {

  }

  ngOnInit(): void {
    const authenticatedUser: User = this.userService.getAuthenticatedUser();
    if (authenticatedUser != null && authenticatedUser !== undefined) {
      this.router.navigate(['/users', authenticatedUser.id]);
    } else {
      this.router.navigate(['/auth']);
    }
  }
}
