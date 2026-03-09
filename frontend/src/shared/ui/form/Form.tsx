import classNames from "classnames";

import { FormRow } from "./FormRow";
import { FormSubmitErrorBlock } from "./FormSubmitErrorBlock";

import "./Form.scss";

/**
 * Props for Form component.
 */
interface IFormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  children: React.ReactNode;
}

/**
 * Form component.
 */
function FormBase({ children, ...props }: IFormProps) {
  return (
    <form {...props} className={classNames("form", props.className)}>
      {children}
    </form>
  );
}

export const Form = Object.assign(FormBase, {
  Row: FormRow,
  SubmitErrorBlock: FormSubmitErrorBlock,
});
