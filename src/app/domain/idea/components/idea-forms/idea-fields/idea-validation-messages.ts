import {ValidationMessagesErrors} from "../../../../../core/helper/validation-messages-errors";
/**
 * Created by AKuzmanoski on 06/01/2017.
 */
export interface IdeaValidationMessages {
  [key: string]: ValidationMessagesErrors;
  title?: ValidationMessagesErrors;
  snackPeak?: ValidationMessagesErrors;
  tags?: ValidationMessagesErrors;
}
