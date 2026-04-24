import { Heading } from "@/shared/ui";

import type { IHelpKeyboardShortcutsGroup } from "../../lib/types";
import { HelpKeyboardShortcutsTable } from "../HelpKeyboardShortcutsTable";

import "./HelpKeyboardShortcutsGroup.scss";

/**
 * Props type for the `HelpKeyboardShortcutsGroup` component.
 */
type IHelpKeyboardShortcutsGroupProps = IHelpKeyboardShortcutsGroup;

/**
 * A React component that renders a grouped section of keyboard shortcuts.
 *
 * @example
 * <HelpKeyboardShortcutsGroup
 *   title="Navigation"
 *   shortcuts={[
 *     { key: "ArrowUp", description: "Move up" },
 *     { key: "ArrowDown", description: "Move down" }
 *   ]}
 * />
 */
export function HelpKeyboardShortcutsGroup({
  title,
  shortcuts,
}: IHelpKeyboardShortcutsGroupProps) {
  if (!shortcuts.length) return null;

  return (
    <div className="help-keyboard-shortcuts-group">
      {title && (
        <Heading
          level={3}
          align="center"
          className="help-keyboard-shortcuts-group__title"
        >
          {title}
        </Heading>
      )}
      <HelpKeyboardShortcutsTable shortcuts={shortcuts} />
    </div>
  );
}
