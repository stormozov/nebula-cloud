import classNames from "classnames";
import { useExportUserDataMutation } from "@/entities/user";
import { Button, type IButtonProps, Icon } from "@/shared/ui";
import { downloadFile } from "@/shared/utils";

/**
 * Props for the UserJsonDataExport component.
 */
interface IUserJsonDataExportProps {
  userId: number;
  buttonProps?: IButtonProps;
}

/**
 * A component that renders a button to export user data in JSON format.
 *
 * When clicked, it triggers a mutation to fetch the user's data,
 * converts the response into a JSON Blob, and initiates a download.
 *
 * @example
 * <UserJsonDataExport userId={123} buttonProps={{ size: 'sm' }} />
 */
export function ExportUserJson({
  userId,
  buttonProps,
}: IUserJsonDataExportProps) {
  const [exportUserData, { isLoading }] = useExportUserDataMutation();

  const handleExportUserData = async () => {
    const response = await exportUserData(userId).unwrap();
    const blob = new Blob([JSON.stringify(response, null, 2)], {
      type: "application/json",
    });
    downloadFile(blob, `user_${userId}_data.json`);
  };

  return (
    <Button
      aria-label={`Экспорт JSON данных пользователя ${userId}`}
      {...buttonProps}
      className={classNames(
        "user-json-data-export-btn",
        buttonProps?.className,
      )}
      loading={isLoading}
      disabled={isLoading}
      onClick={handleExportUserData}
    >
      <Icon name="export" />
      Экспорт JSON
    </Button>
  );
}
