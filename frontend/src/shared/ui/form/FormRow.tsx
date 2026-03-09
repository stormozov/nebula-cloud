/**
 * Props for FormRow component.
 */
export interface IFormRowProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

/**
 * Form row component used to group form elements.
 *
 * @example
 * <FormRow>
 *   <Label htmlFor="name">Name</Label>
 *   <Input id="name" name="name" />
 * </FormRow>
 */
export function FormRow({ children, ...props }: IFormRowProps) {
  return (
    <div {...props} className="form__row">
      {children}
    </div>
  );
}
