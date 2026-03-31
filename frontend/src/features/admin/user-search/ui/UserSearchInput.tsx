import { ControlledInput } from "@/shared/ui";

/**
 * Props for the `UserSearchInput` component.
 */
interface UserSearchInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}

/**
 * A controlled input component designed for searching users by ID, login,
 * or email.
 */
export const UserSearchInput = ({
  value,
  onChange,
  placeholder = "Поиск по ID, логину или email",
  className,
}: UserSearchInputProps) => {
  return (
    <ControlledInput
      value={value}
      className={className}
      placeholder={placeholder}
      autoComplete="off"
      autoFocus
      onChange={onChange}
    />
  );
};
