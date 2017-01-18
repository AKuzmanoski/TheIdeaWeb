import {Injectable} from "@angular/core";
import {Router} from "@angular/router";
/**
 * Created by AKuzmanoski on 18/01/2017.
 */

@Injectable()
export class RedirectService {
  constructor(private router: Router) {}

  getAnnouncemntDetails(id: number) {
    this.router.navigate(['/announcements', id.toString()]);
  }
}
