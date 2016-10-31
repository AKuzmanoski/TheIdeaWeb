import {User} from "../../model/authentication/user";
import {ControlValueAccessor, NG_VALUE_ACCESSOR} from "@angular/forms";
import {forwardRef, Directive} from "@angular/core";
import {RegisterFieldsComponent} from "../component/register-fields/register-fields.component";
/**
 * Created by AKuzmanoski on 29/10/2016.
 */
const noop = () => {
};

export const CUSTOM_INPUT_CONTROL_VALUE_ACCESSOR: any = {
  provide: NG_VALUE_ACCESSOR,
  useExisting: forwardRef(() => UserValueAccessorDirective),
  multi: true
};

@Directive({
  selector: 'ideal-solution-fields',
  host: {'(userChange)': 'onChange($event)'},
  providers: [CUSTOM_INPUT_CONTROL_VALUE_ACCESSOR]
})
export class UserValueAccessorDirective implements ControlValueAccessor {
  //Placeholders for the callbacks which are later providesd
  //by the Control Value Accessor
  private onTouched: () => void = noop;
  private onChange: (_: any) => void = noop;

  constructor(private host: RegisterFieldsComponent) {
  }

  //From ControlValueAccessor interface
  writeValue(user: User) {
    this.host.user = user;
  }

  //From ControlValueAccessor interface
  registerOnChange(fn: any) {
    this.onChange = fn;
  }

  //From ControlValueAccessor interface
  registerOnTouched(fn: any) {
    this.onTouched = fn;
  }

  //Set touched on blur
  onBlur() {
    this.onTouched();
  }
}
