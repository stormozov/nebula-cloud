import classNames from "classnames";
import { useRef } from "react";
import { createPortal } from "react-dom";

import { Button, Icon } from "@/shared/ui";

import { useDropdownKeyboard } from "./hooks/useDropdownKeyboard";
import { useDropdownMenu } from "./hooks/useDropdownMenu";
import { useDropdownPositioning } from "./hooks/useDropdownPositioning";
import type { IDropdownMenuActionItem, IDropdownMenuProps } from "./types";

import "./DropdownMenu.scss";

/**
 * A reusable dropdown menu that can be triggered by a button or used
 * as a context menu.
 *
 * @template T - The type of the item associated with the dropdown actions.
 * This allows action handlers to operate on a specific data context
 * (e.g., a row in a table, a product, etc.).
 *
 * @example
 * // Trigger mode
 * <DropdownMenu
 *   triggerButtonProps={{ children: 'Actions', variant: 'secondary' }}
 *   actions={[
 *     { id: 'edit', label: 'Edit', onClick: handleEdit },
 *     { id: 'delete', label: 'Delete', isDanger: true, onClick: handleDelete }
 *   ]}
 *   item={currentItem}
 * />
 *
 * @example
 * // Context menu mode (no trigger)
 * <DropdownMenu
 *   actions={contextActions}
 *   item={clickedItem}
 *   position={{ x: 200, y: 300 }}
 *   isOpen={true}
 *   onOpenChange={handleClose}
 * />
 */
export function DropdownMenu<T>(props: IDropdownMenuProps<T>) {
  const {
    triggerButtonProps,
    actions,
    item,
    position,
    isOpen: isOpenControlled,
    onOpenChange,
    placement = "bottom-start",
    closeOnClickOutside = true,
    closeOnEscape = true,
  } = props;

  const { isOpen, close, toggle, menuRef } = useDropdownMenu({
    isOpenControlled,
    onOpenChange,
    closeOnClickOutside,
    closeOnEscape,
  });

  const triggerRef = useRef<HTMLDivElement>(null);
  const { menuStyle } = useDropdownPositioning({
    isOpen,
    triggerRef,
    menuRef,
    position,
    placement,
  });

  const handleSelectAction = (action: IDropdownMenuActionItem<T>) => {
    const disabled =
      typeof action.disabled === "function"
        ? action.disabled(item)
        : action.disabled;
    if (!disabled) {
      action.onClick(item);
    }
  };

  const { focusedIndex, actionRefs, handleKeyDown } = useDropdownKeyboard({
    isOpen,
    actions,
    item,
    onClose: close,
    onSelect: handleSelectAction,
  });

  const renderMenu = () => {
    if (!isOpen) return null;

    return createPortal(
      <div
        ref={menuRef}
        className="dropdown-menu__menu"
        style={menuStyle}
        role="menu"
        onKeyDown={handleKeyDown}
        onContextMenu={(e) => {
          e.stopPropagation();
          e.preventDefault();
        }}
        tabIndex={focusedIndex}
      >
        {actions.map((action, idx) => {
          const disabled =
            typeof action.disabled === "function"
              ? action.disabled(item)
              : action.disabled;
          return (
            <button
              key={action.id}
              type="button"
              ref={(el) => {
                actionRefs.current[idx] = el;
              }}
              className={classNames("dropdown-menu__item", {
                "dropdown-menu__item--danger": action.isDanger,
                "dropdown-menu__item--disabled": disabled,
              })}
              role="menuitem"
              disabled={disabled}
              onClick={() => {
                handleSelectAction(action);
                close();
              }}
            >
              {action.icon && (
                <Icon
                  name={action.icon}
                  size={16}
                  className="dropdown-menu__item-icon"
                />
              )}
              <span className="dropdown-menu__item-label">{action.label}</span>
            </button>
          );
        })}
      </div>,
      document.body,
    );
  };

  // Context menu mode only (without a trigger)
  if (!triggerButtonProps) return renderMenu();

  // Trigger mode
  return (
    <div className="dropdown-menu">
      <div ref={triggerRef} className="dropdown-menu__trigger-wrapper">
        <Button {...triggerButtonProps} onClick={toggle} />
      </div>
      {renderMenu()}
    </div>
  );
}
