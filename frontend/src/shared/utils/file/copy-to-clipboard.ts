/**
 * Copies text to clipboard using execCommand.
 *
 * @param text - Text to copy
 * @returns True on success, false on failure
 */
const copyToClipboardLegacy = (text: string): boolean => {
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "-9999px";
    textarea.setAttribute("aria-hidden", "true");

    document.body.append(textarea);

    // Save focus to restore later
    const activeElement = document.activeElement as HTMLElement | null;

    textarea.focus();
    textarea.select();

    const success = document.execCommand("copy");

    document.body.removeChild(textarea);

    // Restore focus
    if (activeElement?.focus) activeElement.focus();

    return success;
  } catch {
    return false;
  }
};

/**
 * Copies text to clipboard using modern Clipboard API.
 *
 * Falls back to legacy execCommand for older browsers.
 *
 * @param text - Text to copy
 * @returns Promise that resolves to true on success, false on failure
 *
 * @example
 * const success = await copyToClipboard('https://example.com/file/abc123');
 * if (success) {
 *   console.log('Link copied!');
 * }
 */
export const copyToClipboard = async (text: string): Promise<boolean> => {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (err) {
    console.warn("Clipboard API failed, falling back", err);
  }

  // Delegate to legacy implementation
  return copyToClipboardLegacy(text);
};

/**
 * Copies text to clipboard with user feedback.
 *
 * Shows success/error message via callback.
 *
 * @param text - Text to copy
 * @param onSuccess - Callback on successful copy
 * @param onError - Callback on failed copy
 *
 * @returns Promise that resolves when copy attempt completes
 *
 * @example
 * await copyToClipboardWithFeedback(
 *   link,
 *   () => showToast('Ссылка скопирована!'),
 *   () => showToast('Ошибка копирования')
 * );
 */
export const copyToClipboardWithFeedback = async (
  text: string,
  onSuccess?: () => void,
  onError?: () => void,
): Promise<void> => {
  const success = await copyToClipboard(text);

  if (success) {
    onSuccess?.();
  } else {
    onError?.();
  }
};
