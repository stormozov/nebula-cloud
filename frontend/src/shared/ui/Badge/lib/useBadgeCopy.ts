import { useCallback } from "react";
import { toast } from "react-toastify";

import { copyToClipboardWithFeedback } from "@/shared/utils";

/**
 * Return type for the `useBadgeCopy` hook.
 */
interface IUseBadgeCopyReturns {
  /** Function to handle badge copy */
  handleCopy: () => void;
  /** Function to handle badge keydown */
  handleKeyDown: (event: React.KeyboardEvent<HTMLSpanElement>) => void;
  /** Combined click handler */
  combinedClickHandler: React.MouseEventHandler<HTMLSpanElement>;
}

/**
 * Custom React hook that manages copy functionality for a badge component.
 *
 * @param copyable - If `true`, enables the copy-to-clipboard functionality.
 * @param dot - If `true`, disables copying (dot badges are`t meant to be copied).
 * @param displayContent - The formatted content currently displayed
 * in the badge (e.g., "99+").
 * @param children - The original content of the badge (number, string, etc.).
 * @param externalOnClick - Optional click handler from props; will be called
 * after copy logic.
 *
 * @example
 * const { combinedClickHandler, handleKeyDown } = useBadgeCopy(true, false, "5", 5);
 * return (
 *   <span onClick={combinedClickHandler} onKeyDown={handleKeyDown} tabIndex={0}>
 *     {content}
 *   </span>
 * );
 */
export const useBadgeCopy = (
  copyable: boolean,
  dot: boolean,
  displayContent: React.ReactNode,
  children: React.ReactNode,
  externalOnClick?: React.MouseEventHandler<HTMLElement>,
): IUseBadgeCopyReturns => {
  const onCopySuccess = useCallback(() => {
    toast.success("Скопировано в буфер обмена", { autoClose: 2000 });
  }, []);

  const onCopyError = useCallback(() => {
    toast.error("Не удалось скопировать в буфер обмена", { autoClose: 2000 });
  }, []);

  const handleCopy = useCallback(async () => {
    if (!copyable || dot) return;
    const textToCopy =
      typeof displayContent === "string"
        ? displayContent
        : String(children || "");
    await copyToClipboardWithFeedback(textToCopy, onCopySuccess, onCopyError);
  }, [copyable, dot, displayContent, children, onCopySuccess, onCopyError]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLElement>) => {
      if (!copyable) return;
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        handleCopy();
      }
    },
    [copyable, handleCopy],
  );

  const combinedClickHandler = useCallback(
    (e: React.MouseEvent<HTMLElement>) => {
      handleCopy();
      externalOnClick?.(e);
    },
    [handleCopy, externalOnClick],
  );

  return { handleCopy, handleKeyDown, combinedClickHandler };
};
