import {Route, PreloadingStrategy} from "@angular/router";
import {of} from "rxjs/observable/of";
/**
 * Created by AKuzmanoski on 02/12/2016.
 */
export class PreloadSelectedModulesList extends PreloadingStrategy{
  preload(route: Route, load: Function) {
    return route.data && route.data["preload"] ? load() : of(null);
  }
}
