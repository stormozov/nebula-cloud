import type { IHelpKeyboardShortcutsModalContent } from "../../lib/types";
import { normalizeShortcuts } from "../../lib/utils";
import { HelpKeyboardShortcutsGroup } from "../HelpKeyboardShortcutsGroup";

import "./HelpKeyboardShortcutsList.scss";

/**
 * Props interface for the `HelpKeyboardShortcutsList` component.
 */
interface IHelpKeyboardShortcutsListProps {
  /** The content to display in the keyboard shortcuts list. */
  content: IHelpKeyboardShortcutsModalContent;
}

/**
 * A React component that renders a list of keyboard shortcut groups without
 * a modal wrapper.
 *
 * @example
 * <HelpKeyboardShortcutsList
 *   content={{
 *     title: "File Manager Shortcuts",
 *     shortcuts: [
 *       {
 *         title: "Просмотр",
 *         shortcuts: [{ key: "V", description: "View file" }]
 *       }
 *     ]
 *   }}
 * />
 */
export function HelpKeyboardShortcutsList({
  content,
}: IHelpKeyboardShortcutsListProps) {
  const groups = normalizeShortcuts(content.shortcuts);

  return (
    <div className="help-keyboard-shortcuts-list">
      {groups.map((group, index) => (
        <HelpKeyboardShortcutsGroup
          key={group.title ?? `group-${index}`}
          title={group.title}
          shortcuts={group.shortcuts}
        />
      ))}
    </div>
  );
}
