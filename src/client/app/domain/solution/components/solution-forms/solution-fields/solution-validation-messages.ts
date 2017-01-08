import {Properties} from "../../../../../shared/utils/properties";
import {ValidationMessagesErrors} from "../../../../../core/helper/validation-messages-errors";
/**
 * Created by AKuzmanoski on 06/01/2017.
 */
export interface SolutionValidationMessages {
  [key: string]: ValidationMessagesErrors;
  text?: ValidationMessagesErrors;
}
