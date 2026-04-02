import classNames from "classnames";
import { useEffect, useRef, useState } from "react";

import { useClickOutside } from "@/shared/hooks";
import {
  Button,
  ControlledInput,
  type IButtonProps,
  type IControlledInputProps,
  Icon,
} from "@/shared/ui";

import "./CollapsibleSearch.scss";

/**
 * Interface defining the props for the `CollapsibleSearch` component.
 */
export interface ICollapsibleSearchProps {
  buttonProps?: IButtonProps;
  inputProps?: IControlledInputProps;
}

/**
 * A collapsible search component that displays an input field when activated.
 *
 * @example
 * <CollapsibleSearch
 *   inputProps={{
 *     value: searchTerm,
 *     onChange: (e) => setSearchTerm(e.target.value),
 *     placeholder: "Найти файл..."
 *   }}
 * />
 */
export const CollapsibleSearch = ({
  buttonProps = {},
  inputProps = { value: "", onChange: () => {} },
}: ICollapsibleSearchProps) => {
  const { value, onChange, placeholder, className } = inputProps;

  const [isOpen, setIsOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useClickOutside(containerRef, () => {
    if (value === "") setIsOpen(false);
  });

  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [isOpen]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") setIsOpen(false);
  };

  return (
    <div
      ref={containerRef}
      className={classNames(
        "collapsible-search",
        {
          "collapsible-search--open": isOpen,
        },
        className,
      )}
    >
      <Button
        variant="secondary"
        className="collapsible-search__button"
        onClick={() => setIsOpen(true)}
        title="Поиск"
        aria-label="Поиск"
        {...buttonProps}
      >
        <Icon name="search" />
        {buttonProps.children}
      </Button>
      <ControlledInput
        ref={inputRef}
        value={value}
        className="collapsible-search__input"
        placeholder={placeholder}
        autoComplete="off"
        onChange={onChange}
        onKeyDown={handleKeyDown}
      />
    </div>
  );
};
