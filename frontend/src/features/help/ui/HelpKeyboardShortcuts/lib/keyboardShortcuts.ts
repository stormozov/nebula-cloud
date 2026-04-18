import keyboardShortcutsData from "@/shared/configs/keyboard-shortcuts.json";

import type { IKeyboardShortcutJSON } from "./types";

/**
 * The main data structure containing keyboard shortcuts, typed and validated
 * using `satisfies` to ensure it conforms to the `IKeyboardShortcutJSON`
 * interface while preserving type inference for individual properties.
 */
export const keyboardShortcuts =
  keyboardShortcutsData satisfies IKeyboardShortcutJSON;

/**
 * A type representing the available contexts for keyboard shortcuts.
 * It is derived from the keys of the `keyboardShortcuts` object,
 * ensuring that only valid context names can be used in the application.
 *
 * @example
 * type Context = KeyboardShortcutContext; // e.g., "file-manager", etc.
 */
export type KeyboardShortcutContext = keyof typeof keyboardShortcuts;

/**
 * The default context used for keyboard shortcuts when no other context
 * is specified. This value should correspond to one of the keys
 * in the `keyboardShortcuts` object.
 */
export const DEFAULT_CONTEXT: KeyboardShortcutContext = "file-manager";
