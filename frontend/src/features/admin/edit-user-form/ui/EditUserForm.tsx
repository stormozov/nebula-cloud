import type { UserDetailsResponse } from "@/entities/user";
import {
  Button,
  ControlledInput,
  Heading,
  PageWrapper
} from "@/shared/ui";

import { useEditUserForm } from "../lib/useEditUserForm";

import "./EditUserForm.scss";

/**
 * Props interface for the EditUserForm component.
 */
interface IEditUserFormProps {
  user: UserDetailsResponse;
  onSuccess?: () => void;
  onCancel?: () => void;
}

/**
 * Form component for editing user details.
 *
 * @example
 * <EditUserForm
 *   user={userData}
 *   onSuccess={() => console.log('User updated')}
 *   onCancel={() => console.log('Edit cancelled')}
 * />
 */
export function EditUserForm({
  user,
  onSuccess,
  onCancel,
}: IEditUserFormProps) {
  const { formValues, handleChange, handleSubmit, isLoading } = useEditUserForm(
    { user, onSuccess, onCancel },
  );

  return (
    <form onSubmit={handleSubmit} className="edit-user-form">
      <Heading level={4}>Основная информация</Heading>

      <ControlledInput
        value={formValues.email}
        label="Email"
        name="email"
        autoComplete="email"
        onChange={(value) => handleChange("email", value)}
      />

      <ControlledInput
        value={formValues.firstName}
        label="Имя"
        name="firstName"
        autoComplete="name"
        onChange={(value) => handleChange("firstName", value)}
      />

      <ControlledInput
        value={formValues.lastName}
        label="Фамилия"
        name="lastName"
        autoComplete="family-name"
        onChange={(value) => handleChange("lastName", value)}
      />

      <PageWrapper className="edit-user-form__buttons" justify="end">
        <Button variant="secondary" icon={{ name: "close" }} onClick={onCancel}>
          Отмена
        </Button>
        <Button type="submit" icon={{ name: "save" }} loading={isLoading}>
          Сохранить
        </Button>
      </PageWrapper>
    </form>
  );
}
