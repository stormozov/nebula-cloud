import { copyToClipboardWithFeedback } from "@/shared/utils";

import type {
  IUserListResponse,
  IUserRegister,
  UserListItemCopyField,
} from "./types";

/**
 * Transforms form data to API request format.
 *
 * Converts camelCase to snake_case for backend compatibility.
 *
 * @param data - Form values in camelCase
 * @returns Data object in snake_case for API request
 */
export const transformDataToApi = (data: IUserRegister) => ({
  username: data.username,
  email: data.email,
  password: data.password,
  password_confirm: data.passwordConfirm,
  first_name: data.firstName,
  last_name: data.lastName,
});

/**
 * Copies a specified field of a user to clipboard with feedback.
 *
 * @param user - User object
 * @param field - Field to copy ('id', 'username', or 'email')
 * @param onSuccess - Optional success callback (receives the copied value)
 * @param onError - Optional error callback
 */
export const copyUserField = async (
  user: IUserListResponse,
  field: UserListItemCopyField,
  onSuccess?: (value: string) => void,
  onError?: () => void,
): Promise<void> => {
  let value: string;
  let label: string;

  switch (field) {
    case "id":
      value = String(user.id);
      label = `ID пользователя ${value}`;
      break;
    case "username":
      value = user.username;
      label = `Логин ${value}`;
      break;
    case "email":
      value = user.email;
      label = `Email ${value}`;
      break;
  }

  await copyToClipboardWithFeedback(
    value,
    () => onSuccess?.(label),
    () => onError?.(),
  );
};
