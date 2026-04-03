import type { Button, IconName } from "@/shared/ui";

/**
 * Action item for the dropdown menu.
 */
export interface IDropdownMenuActionItem<T> {
  /** Unique identifier */
  id: string;
  /** Label to display */
  label: string;
  /** Optional icon */
  icon?: IconName;
  /** Is the action destructive? */
  isDanger?: boolean;
  /** Handler for the action */
  onClick: (item: T) => void;
  /** Disabled state (boolean or function) */
  disabled?: boolean | ((item: T) => boolean);
}

/**
 * Placement options for the dropdown menu.
 */
export type DropdownMenuActionItemPlacement =
  | "bottom-start"
  | "bottom-end"
  | "top-start"
  | "top-end";

export interface IDropdownMenuProps<T> {
  /**
   * Props for the trigger button. The button will be rendered inside a wrapper
   * that handles positioning reference. Do not provide `onClick` – it will be
   * overwritten to toggle the menu.
   */
  triggerButtonProps?: Omit<React.ComponentProps<typeof Button>, "onClick">;
  /** List of actions to display in the menu. */
  actions: IDropdownMenuActionItem<T>[];
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
  /** Callback when open state changes. */
  onOpenChange?: (open: boolean) => void;
  /** Whether to close the menu when clicking outside. Default true. */
  closeOnClickOutside?: boolean;
  /** Whether to close the menu on Escape key. Default true. */
  closeOnEscape?: boolean;
}

/**
 * Context state for the `UserListItem` component.
 */
export interface IContextMenuState {
  isOpen: boolean;
  position: { x: number; y: number };
}
