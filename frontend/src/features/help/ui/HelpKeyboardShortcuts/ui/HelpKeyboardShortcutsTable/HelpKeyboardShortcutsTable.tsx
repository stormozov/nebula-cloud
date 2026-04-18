import type { IHelpKeyboardShortcutsData } from "../../lib/types";

import "./HelpKeyboardShortcutsTable.scss";

/**
 * Props interface for the `HelpKeyboardShortcutsTable` component.
 */
interface IHelpKeyboardShortcutsTableProps {
  /** An array of keyboard shortcut data entries to be displayed in the table. */
  shortcuts: IHelpKeyboardShortcutsData[];
}

/**
 * A React component that renders a tabular representation of keyboard shortcuts.
 *
 * @example
 * <HelpKeyboardShortcutsTable
 *   shortcuts={[
 *     { key: "Ctrl+C", description: "Copy selected content" },
 *     { key: "Ctrl+V", description: "Paste content" }
 *   ]}
 * />
 */
export function HelpKeyboardShortcutsTable({
  shortcuts,
}: IHelpKeyboardShortcutsTableProps) {
  return (
    <table className="help-keyboard-shortcuts-table">
      <thead className="help-keyboard-shortcuts-table__header">
        <tr className="help-keyboard-shortcuts-table__header-row">
          <th className="help-keyboard-shortcuts-table__cell">Клавиша</th>
          <th className="help-keyboard-shortcuts-table__cell">Описание</th>
        </tr>
      </thead>
      <tbody className="help-keyboard-shortcuts-table__body">
        {shortcuts.map(({ key, description }) => (
          <tr
            key={`${key}-${description}`}
            className="help-keyboard-shortcuts-table__row"
          >
            <td className="help-keyboard-shortcuts-table__cell">
              <code className="help-keyboard-shortcuts-table__key">{key}</code>
            </td>
            <td className="help-keyboard-shortcuts-table__cell">
              {description}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
