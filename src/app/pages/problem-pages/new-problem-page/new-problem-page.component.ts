/**
 * Created by AKuzmanoski on 19/10/2016.
 */
import {Component} from "@angular/core";
import {Logger} from "../../../logger.service";
import {Problem} from "../../../domain/model/ideas/problem";
import {MdSnackBar, MdSnackBarConfig} from "@angular/material";
import {Router, ActivatedRoute} from "@angular/router";
import {RedirectService} from "../../../core/navigation/redirect.service";

@Component({
  moduleId: module.id,
  selector: 'ideal-new-problem-page',
  templateUrl: 'new-problem-page.component.html',
  styleUrls: ['new-problem-page.component.scss'],
})
export class NewProblemPageComponent {
  submitText = "Save";


  constructor(private snackBar: MdSnackBar, private redirectService: RedirectService, private route: ActivatedRoute) {

  }

  problemCreated(problem: Problem) {
    this.snackBar.open("Problem successfully created!", undefined, <MdSnackBarConfig>{duration: 2000});
    this.redirectService.getProblemDetails(problem.id);
  }
}
