import {delay} from 'rxjs/operators';
import {EventEmitter, Injectable} from '@angular/core';
import {LoadingState} from './loading-state';
import {Observable} from 'rxjs';
import {TimerObservable} from 'rxjs/observable/TimerObservable';

/**
 * Created by AKuzmanoski on 14/01/2017.
 */
@Injectable()
export class LoadingService {
  private numOfLoadings = 0;
  private indefiniteLoading: LoadingState = new LoadingState();

  private _loadingStateChange: EventEmitter<LoadingState> = new EventEmitter<LoadingState>(true);

  public get loadingStateChange(): Observable<LoadingState> {
    return this._loadingStateChange.asObservable().pipe(delay(10));
  }

  private _loadingState: LoadingState;

  private set loadingState(loadingState: LoadingState) {
    this._loadingState = loadingState;
    if (loadingState == null) {
      this._loadingStateChange.emit(this._loadingState);
    } else {
      const timer = TimerObservable.create(100, 100);
      const subscription = timer.subscribe(t => {
        if (this._loadingState != null) {
          this._loadingStateChange.emit(this._loadingState);
          subscription.unsubscribe();
        }
      });
    }
  }

  public load(loadingState: LoadingState = this.indefiniteLoading) {
    this.loadingState = loadingState;
    this.numOfLoadings++;
  }

  public loadingDone(): void {
    this.numOfLoadings--;
    console.log(this.numOfLoadings);
    // TODO quick fix applied here, it will be solved when http client with inceptor will be included.
    this.loadingState = null;
  }
}
