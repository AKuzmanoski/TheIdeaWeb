import {Routes} from "@angular/router";
import {AuthPagesComponent} from "./components/auth-pages.component";
import {RegisterPageRoutes} from "./register-page/register-page.routes";
import {LoginPageRoutes} from "./login-page/login-page-routes";
import {AuthPageRoutes} from "./auth-page/auth-page.routes";
/**
 * Created by Viki on 10/28/2016.
 */
export const AuthPagesRoutes: Routes = [
  {
    path: "",
    component: AuthPagesComponent,
    children: [...AuthPageRoutes]
  },
  {
    path: "register",
    component: AuthPagesComponent,
    children: [...RegisterPageRoutes]
  },
  {
    path: "login",
    component: AuthPagesComponent,
    children: [...LoginPageRoutes]
  }
]
