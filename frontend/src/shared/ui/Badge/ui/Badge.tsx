import classNames from "classnames";
import type React from "react";
import { forwardRef, useImperativeHandle, useRef } from "react";

import type { AnchorPosition } from "@/shared/types/common";

import { Icon, type IconName } from "../../Icon";
import type { BadgeVariant } from "../lib/types";
import { useBadgeCopy } from "../lib/useBadgeCopy";
import { useViewportBoundary } from "../lib/useViewportBoundary";
import { formatDisplayContent, shouldHideBadge } from "../lib/utils";

import styles from "./Badge.module.scss";

/**
 * Props for Badge component.
 */
export interface IBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Badge content (text or number) */
  children?: React.ReactNode;
  /** Optional icon name from Icon component */
  icon?: IconName;
  /** Position relative to parent element. */
  position?: AnchorPosition;
  /** Color variant */
  variant?: BadgeVariant;
  /** Display as superscript (only works when position is not specified) */
  superscript?: boolean;
  /** Maximum number to display (e.g., 99+) */
  maxCount?: number;
  /** Whether to show badge when value is 0 */
  showZero?: boolean;
  /** Dot mode (no text, fixed size) */
  dot?: boolean;
  /** Additional class name */
  className?: string;
  /** Whether badge content can be copied on click */
  copyable?: boolean;
}

/**
 * Badge component for statuses, notifications and counters.
 * When `position` is specified, parent must have `position: relative`.
 */
export const Badge = forwardRef<HTMLSpanElement, IBadgeProps>(
  (
    {
      children,
      icon,
      position,
      variant = "default",
      maxCount,
      showZero = false,
      superscript = false,
      dot = false,
      className,
      style,
      copyable = false,
      ...restProps
    },
    ref,
  ) => {
    const innerRef = useRef<HTMLSpanElement>(null);
    useImperativeHandle(ref, () => innerRef.current as HTMLSpanElement, []);

    const shouldHide = shouldHideBadge(children, showZero, dot);
    const displayContent = formatDisplayContent(children, maxCount, dot);

    const transform = useViewportBoundary(innerRef, position);

    const { handleKeyDown, combinedClickHandler } = useBadgeCopy(
      copyable,
      dot,
      displayContent,
      children,
      restProps.onClick,
    );

    if (shouldHide) return null;

    const isPositioned = position !== undefined;
    const isInteractive = copyable && !dot;
    const useButtonTag = isInteractive && !isPositioned;

    const commonClassNames = classNames(
      styles.badge,
      isPositioned && styles[`badge--${position}`],
      styles[`badge--${variant}`],
      {
        [styles["badge--dot"]]: dot,
        [styles["badge--with-icon"]]: !!icon,
        [styles["badge--relative"]]: !isPositioned,
        [styles["badge--superscript"]]: !isPositioned && superscript,
        [styles["badge--copyable"]]: isInteractive,
      },
      className,
    );

    const combinedStyle: React.CSSProperties = {
      ...style,
      transform: isPositioned ? transform : undefined,
    };

    const content = (
      <>
        {icon && <Icon name={icon} className={styles.badge__icon} />}
        {!dot && displayContent && (
          <span className={styles.badge__content}>{displayContent}</span>
        )}
      </>
    );

    if (useButtonTag) {
      return (
        <button
          ref={innerRef as React.Ref<HTMLButtonElement>}
          className={commonClassNames}
          style={combinedStyle}
          type="button"
          onClick={combinedClickHandler}
          onKeyDown={handleKeyDown}
          {...(restProps as Omit<typeof restProps, "ref" | "onClick">)}
        >
          {content}
        </button>
      );
    }

    return (
      // biome-ignore lint/a11y/noStaticElementInteractions: role="button" provides semantics
      <span
        ref={innerRef}
        className={commonClassNames}
        style={combinedStyle}
        role={dot ? "presentation" : isInteractive ? "button" : "status"}
        tabIndex={isInteractive ? 0 : undefined}
        aria-hidden={dot ? undefined : false}
        onClick={combinedClickHandler}
        onKeyDown={handleKeyDown}
        {...restProps}
      >
        {content}
      </span>
    );
  },
);

Badge.displayName = "Badge";
