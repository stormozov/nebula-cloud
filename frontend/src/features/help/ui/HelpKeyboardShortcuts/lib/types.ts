/**
 * Represents a single keyboard shortcut entry, containing the key combination
 * and its associated description.
 */
export interface IHelpKeyboardShortcutsData {
  /** The keyboard combination as a string (e.g., "Ctrl+C", "Escape"). */
  key: string;
  /** A human-readable description of what the shortcut does. */
  description: string;
}

/**
 * Represents a group of related keyboard shortcuts, optionally with a title.
 *
 * Used to organize shortcuts into logical sections within the help modal.
 */
export interface IHelpKeyboardShortcutsGroup {
  /** Optional title for the group of shortcuts. */
  title?: string;
  /** An array of keyboard shortcut data objects that belong to this group. */
  shortcuts: IHelpKeyboardShortcutsData[];
}

/**
 * Defines the structure of the content displayed in the keyboard shortcuts help
 * modal.
 */
export interface IHelpKeyboardShortcutsModalContent {
  /** The main title of the modal, usually indicating the context. */
  title: string;
  /** Optional list of shortcuts or grouped shortcuts to display in the modal. */
  shortcuts?: IHelpKeyboardShortcutsData[] | IHelpKeyboardShortcutsGroup[];
}

/**
 * Interface describing the JSON structure of keyboard shortcut configurations.
 *
 * It maps context names to objects, which in turn map action keys to arrays
 * of shortcut data.
 */
export interface IKeyboardShortcutJSON {
  [key: string]: {
    [key: string]: IHelpKeyboardShortcutsData[];
  };
}
