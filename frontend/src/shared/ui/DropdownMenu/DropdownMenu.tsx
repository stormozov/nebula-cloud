import classNames from "classnames";
import { cloneElement, useRef } from "react";
import { createPortal } from "react-dom";

import { Button, Divider, Icon } from "@/shared/ui";

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
 *   triggerButtonProps={{ children: 'items', variant: 'secondary' }}
 *   items={[
 *     { id: 'edit', label: 'Edit', onClick: handleEdit },
 *     { id: 'delete', label: 'Delete', isDanger: true, onClick: handleDelete }
 *   ]}
 *   item={currentItem}
 * />
 *
 * @example
 * // Context menu mode (no trigger)
 * <DropdownMenu
 *   items={contextActions}
 *   item={clickedItem}
 *   position={{ x: 200, y: 300 }}
 *   isOpen={true}
 *   onOpenChange={handleClose}
 * />
 */
export function DropdownMenu<T>(props: IDropdownMenuProps<T>) {
  const {
    trigger,
    triggerButtonProps,
    items,
    item,
    position,
    isOpen: isOpenControlled,
    onOpenChange,
    placement = "bottom-start",
    closeOnClickOutside = true,
    closeOnEscape = true,
  } = props;

  const { isOpen, menuRef, close, toggle, closeAndRestoreFocus } =
    useDropdownMenu({
      isOpenControlled,
      closeOnClickOutside,
      closeOnEscape,
      onOpenChange,
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
      closeAndRestoreFocus();
    }
  };

  const { focusedIndex, actionRefs, handleKeyDown } = useDropdownKeyboard({
    isOpen,
    items,
    item,
    onClose: close,
    onSelect: handleSelectAction,
  });

  let actionCounter = 0;

  const renderMenu = () => {
    if (!isOpen) return null;

    return createPortal(
      <div
        ref={menuRef}
        className="dropdown-menu__menu"
        style={menuStyle}
        role="menu"
        tabIndex={-1}
        onKeyDown={handleKeyDown}
        onContextMenu={(e) => {
          e.stopPropagation();
          e.preventDefault();
        }}
      >
        {items.map((menuItem) => {
          // If it's a separator
          if ((menuItem as IDropdownMenuActionItem<T>).onClick === undefined) {
            const separator = menuItem;
            return (
              <Divider key={separator.id ?? `sep-${Math.random()}`} gap={4} />
            );
          }

          // If it's an action
          const action = menuItem as IDropdownMenuActionItem<T>;
          const currentActionIndex = actionCounter++;
          const disabled =
            typeof action.disabled === "function"
              ? action.disabled(item)
              : action.disabled;

          return (
            <button
              key={action.id}
              type="button"
              ref={(el) => {
                actionRefs.current[currentActionIndex] = el;
              }}
              className={classNames("dropdown-menu__item", {
                "dropdown-menu__item--danger": action.isDanger,
                "dropdown-menu__item--disabled": disabled,
              })}
              role="menuitem"
              title={action.arialLabel}
              aria-label={action.arialLabel}
              aria-disabled={disabled}
              disabled={disabled}
              tabIndex={focusedIndex === currentActionIndex ? 0 : -1}
              onClick={() => handleSelectAction(action)}
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

  // Context menu (without trigger)
  if (!trigger && !triggerButtonProps) return renderMenu();

  // Trigger via custom ReactElement
  if (trigger) {
    const triggerElement = trigger as React.ReactElement<{
      onClick?: React.MouseEventHandler;
      onKeyDown?: React.KeyboardEventHandler;
      "aria-haspopup"?: boolean;
      "aria-expanded"?: boolean;
    }>;

    const triggerWithHandlers = cloneElement(triggerElement, {
      onClick: toggle,
      onKeyDown: (e: React.KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggle();
        }
        if (typeof triggerElement.props.onKeyDown === "function") {
          triggerElement.props.onKeyDown(e);
        }
      },
      "aria-haspopup": true,
      "aria-expanded": isOpen,
    });

    return (
      <div className="dropdown-menu">
        <div ref={triggerRef} className="dropdown-menu__trigger-wrapper">
          {triggerWithHandlers}
        </div>
        {renderMenu()}
      </div>
    );
  }

  // Trigger via triggerButtonProps (standard button)
  if (triggerButtonProps) {
    return (
      <div className="dropdown-menu">
        <div ref={triggerRef} className="dropdown-menu__trigger-wrapper">
          <Button
            {...triggerButtonProps}
            onClick={toggle}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.stopPropagation();
              }
              triggerButtonProps.onKeyDown?.(e);
            }}
          />
        </div>
        {renderMenu()}
      </div>
    );
  }

  return null;
}
