import { SECTION_TITLES } from "./constants";
import type {
  IHelpKeyboardShortcutsData,
  IHelpKeyboardShortcutsGroup,
  IHelpKeyboardShortcutsModalContent,
} from "./types";

/**
 * Transforms a context-based shortcut data object into an array of grouped
 * shortcuts, where each group corresponds to a section (e.g., "view",
 * "download") and is localized using `SECTION_TITLES`.
 *
 * @param contextData - A record mapping section keys to arrays of keyboard
 * shortcut data. Each key represents a functional area, and its value contains
 * associated shortcuts.
 *
 * @returns An array of `IHelpKeyboardShortcutsGroup` objects, each containing
 * a localized title and list of shortcuts.
 *
 * @example
 * const contextData = {
 *   view: [{ key: "V", description: "View file" }],
 *   download: [{ key: "D", description: "Download file" }]
 * };
 *
 * const groups = transformContextToGroups(contextData);
 * // Returns:
 * // [
 * //   { title: "Просмотр", shortcuts: [...] },
 * //   { title: "Скачивание", shortcuts: [...] }
 * // ]
 */
export function transformContextToGroups(
  contextData: Record<string, IHelpKeyboardShortcutsData[]>,
): IHelpKeyboardShortcutsGroup[] {
  return Object.entries(contextData).map(([sectionKey, shortcuts]) => ({
    title: SECTION_TITLES[sectionKey] || sectionKey,
    shortcuts,
  }));
}

/**
 * Prepares keyboard shortcuts data for display in the help modal by converting
 * raw context data into a structured format of either a flat list or grouped
 * shortcuts.
 *
 * @param contextData - The raw shortcut data to process.
 *
 * @returns An array of shortcut entries or groups, ready for rendering
 * in the modal. Returns an empty array if input is invalid or missing.
 *
 * @example
 * const result = prepareShortcuts({
 *   view: [{ key: "V", description: "View file" }],
 *   edit: [{ key: "E", description: "Edit file" }]
 * });
 * // Returns: [
 * //   { title: "Просмотр", shortcuts: [...] },
 * //   { title: "Редактирование", shortcuts: [...] }
 * // ]
 */
export function prepareShortcuts(
  contextData: unknown,
): IHelpKeyboardShortcutsModalContent["shortcuts"] {
  if (!contextData) return [];

  // If it is an array, return it (already flattened or grouped)
  if (Array.isArray(contextData)) {
    return contextData as IHelpKeyboardShortcutsModalContent["shortcuts"];
  }

  // If the object has sections
  if (typeof contextData === "object" && contextData !== null) {
    const record = contextData as Record<string, IHelpKeyboardShortcutsData[]>;
    return transformContextToGroups(record);
  }

  return [];
}

/**
 * Normalizes various forms of shortcut input into a standardized array
 * of `IHelpKeyboardShortcutsGroup`.
 *
 * Supports flat arrays, grouped arrays, and nested objects.
 *
 * @param shortcuts - The input shortcuts in any supported format: flat array,
 * grouped array, or object.
 *
 * @returns An array of shortcut groups, each containing a title and list
 * of shortcuts. Returns an empty array if input is falsy or unrecognizable.
 *
 * @example
 * // Flat array input
 * normalizeShortcuts([{ key: "Esc", description: "Close" }])
 * // → [{ shortcuts: [...] }]
 *
 * @example
 * // Object input
 * normalizeShortcuts({ view: [...], edit: [...] })
 * // → [{ title: "Просмотр", shortcuts: [...] }, { title: "Редактирование", shortcuts: [...] }]
 */
export function normalizeShortcuts(
  shortcuts: IHelpKeyboardShortcutsModalContent["shortcuts"],
): IHelpKeyboardShortcutsGroup[] {
  if (!shortcuts) return [];

  // Case 1: Already array of data or groups
  if (Array.isArray(shortcuts) && shortcuts.length > 0) {
    // If the first element has a 'key' field, then it is a flat list
    if ("key" in shortcuts[0]) {
      return [{ shortcuts: shortcuts as IHelpKeyboardShortcutsData[] }];
    }
    // Otherwise, we assume that this is already an array of groups
    return shortcuts as IHelpKeyboardShortcutsGroup[];
  }

  // Case 2: Nested object like {view: [...], download: [...]}
  if (shortcuts && typeof shortcuts === "object" && !Array.isArray(shortcuts)) {
    return Object.entries(shortcuts).map(([sectionKey, sectionShortcuts]) => ({
      title: SECTION_TITLES[sectionKey] || sectionKey,
      shortcuts: sectionShortcuts as IHelpKeyboardShortcutsData[],
    }));
  }

  return [];
}
