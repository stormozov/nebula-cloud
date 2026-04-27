import type { ReactElement } from "react";

import type { Button, IconName } from "@/shared/ui";

/**
 * Action item for the dropdown menu.
 */
export interface IDropdownMenuActionItem<T> {
  /** Unique identifier */
  id: string;
  /** Label to display */
  label: string;
  /** Alternative label for screen readers */
  arialLabel?: string;
  /** Optional icon */
  icon?: IconName;
  /** Custom class names */
  classNames?: string;
  /** Is the action destructive? */
  isDanger?: boolean;
  /** Disabled state (boolean or function) */
  disabled?: boolean | ((item: T) => boolean);
  /** Handler for the action */
  onClick: (item: T) => void;
}

/**
 * Interface representing a separator item in a dropdown menu.
 */
export interface IDropdownMenuSeparatorItem {
  /** The type of the menu item, used to distinguish it from other types. */
  type: "separator";
  /** Optional unique identifier for the separator. */
  id?: string; // Лучше использовать string для консистентности с action id
}

/**
 * Menu item type (union of action and separator).
 */
export type DropdownMenuItem<T> =
  | IDropdownMenuActionItem<T>
  | IDropdownMenuSeparatorItem
  | React.ReactElement;

/**
 * Placement options for the dropdown menu.
 */
export type DropdownMenuActionItemPlacement =
  | "bottom-start"
  | "bottom-end"
  | "top-start"
  | "top-end";

export interface IDropdownMenuProps<T> {
  /** The trigger element. */
  trigger?: ReactElement;
  /**
   * Props for the trigger button. The button will be rendered inside a wrapper
   * that handles positioning reference. Do not provide `onClick` – it will be
   * overwritten to toggle the menu.
   */
  triggerButtonProps?: Omit<React.ComponentProps<typeof Button>, "onClick">;
  /** List of items (actions and separators) to display in the menu. */
  items: DropdownMenuItem<T>[];
  /** The data object (file, user, etc.) to pass to action handlers. */
  item: T;
  /**
   * Fixed position (e.g., for context menu).
   * If provided, menu is opened at these coordinates.
   */
  position?: { x: number; y: number };
  /** Preferred placement relative to the trigger element. */
  placement?: DropdownMenuActionItemPlacement;
  /** Controlled open state. */
  isOpen?: boolean;
  /** Whether to close the menu when clicking outside. Default true. */
  closeOnClickOutside?: boolean;
  /** Whether to close the menu on Escape key. Default true. */
  closeOnEscape?: boolean;
  /** Callback when open state changes. */
  onOpenChange?: (open: boolean) => void;
}

/**
 * Context state for the `UserListItem` component.
 */
export interface IContextMenuState {
  /** Whether the menu is open */
  isOpen: boolean;
  /** The position of the menu */
  position: { x: number; y: number };
}
