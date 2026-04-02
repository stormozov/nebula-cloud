import { CollapsibleSearch, type ICollapsibleSearchProps } from "@/shared/ui";

/**
 * Props for the `UserSearchInput` component.
 */
type UserSearchInputProps = ICollapsibleSearchProps;

/**
 * A controlled input component designed for searching users by ID, login,
 * or email.
 */
export const UserSearchInput = (props: UserSearchInputProps) => {
  return <CollapsibleSearch {...props} />;
};
