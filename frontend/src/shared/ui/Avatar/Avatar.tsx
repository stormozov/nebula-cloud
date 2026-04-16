import classNames from "classnames";
import { useState } from "react";

import { getInitials } from "@/shared/utils";
import "./Avatar.scss";

/**
 * Props interface for the Avatar component.
 *
 * Defines the available properties for rendering a user avatar, which can be
 * an image or a fallback with initials.
 */
interface IAvatarProps {
  /**
   * The URL of the avatar image. If not provided or fails to load, a fallback
   * with initials will be displayed.
   */
  src?: string;
  /**
   * The alternative text describing the avatar, used for accessibility
   * and generating initials. Required even for fallback mode to ensure proper
   * labeling.
   */
  alt: string;
  /** 
   * The size of the avatar.
   */
  size?: "sm" | "md" | "lg";
  /**
   * Additional CSS classes to apply to the avatar container for custom styling.
   */
  className?: string;
}

/**
 * Avatar component that displays a user's profile image or a fallback
 * with initials.
 *
 * Renders an `<img>` element if `src` is provided and loads successfully.
 * If `src` is missing or the image fails to load, it falls back to a colored
 * placeholder showing the initials generated from the `alt` text.
 *
 * Supports different sizes and accepts additional CSS classes for customization.
 *
 * @example
 * <Avatar src="https://example.com/user.jpg" alt="John Doe" size="lg" />
 *
 * @example
 * <Avatar alt="Alice Smith" size="sm" className="border-2 border-white" />
 */
export function Avatar({ src, alt, size = "md", className }: IAvatarProps) {
  const [hasError, setHasError] = useState(false);

  const initials = getInitials(alt);

  if (!src || hasError) {
    return (
      <div
        className={classNames(
          "avatar",
          `avatar--${size}`,
          "avatar--fallback",
          className,
        )}
      >
        {initials}
      </div>
    );
  }

  return (
    <img
      src={src}
      alt={alt}
      className={classNames("avatar", `avatar--${size}`, className)}
      onError={() => setHasError(true)}
    />
  );
}
