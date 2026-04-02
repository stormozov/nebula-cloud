import { copyToClipboard } from "@/shared/utils";

/**
 * Interface defining the return type of the `useClipboardWithHandlers` hook.
 */
interface IUseClipboardWithHandlersReturns {
  /** Handles click on a single row of user information. */
  handleRowClick: (value: string, title: string) => void;
  /** Handles copying all values from a block of user information at once. */
  handleCopyBlock: (blockTitle: string, copyValues: string[]) => void;
}

/**
 * Custom hook providing clipboard functionality with user interaction handlers.
 *
 * Exposes methods to copy individual values or entire blocks of user data
 * to the clipboard, with proper error handling and feedback.
 */
export const useClipboardWithHandlers =
  (): IUseClipboardWithHandlersReturns => {
    const handleRowClick = async (copyValue: string, title: string) => {
      if (copyValue) {
        const success = await copyToClipboard(copyValue);

        if (success) {
          console.log(
            `✔ Поле "${title}" со значением "${copyValue}"`,
            "скопировано в буфер обмена",
          );
        } else {
          console.warn(`⚠️ Не удалось скопировать поле "${title}"`);
        }
      } else {
        console.warn(`⚠️ Поле "${title}" не содержит текста для копирования`);
      }
    };

    const handleCopyBlock = async (
      blockTitle: string,
      copyValues: string[],
    ) => {
      const nonEmptyValues = copyValues.filter((v) => v !== "");
      if (nonEmptyValues.length === 0) return;
      const combined = nonEmptyValues.join("\n");
      const success = await copyToClipboard(combined);

      if (success) {
        console.log(`✔ Блок "${blockTitle}" скопирован в буфер обмена`);
      } else {
        console.warn(`⚠️ Не удалось скопировать блок "${blockTitle}"`);
      }
    };

    return { handleRowClick, handleCopyBlock };
  };
