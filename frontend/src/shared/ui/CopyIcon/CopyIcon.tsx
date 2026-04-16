import classNames from "classnames";
import { useEffect, useState } from "react";
import { Icon, type IIconProps } from "../Icon";

/**
 * Props for the `CopyIcon` component.
 */
export interface CopyButtonProps {
  iconProps?: IIconProps;
}

/**
 * A button with an icon that toggles between a copy and check icon to indicate 
 * copy-to-clipboard status.
 */
export function CopyIcon({ iconProps }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const classes = classNames("copy-icon", iconProps?.className);

  useEffect(() => {
    if (!copied) return;
    setTimeout(() => setCopied(false), 1000);
  }, [copied]);

  return (
    <Icon
      name={copied ? "check" : "copy"}
      {...iconProps}
      className={classes}
      onClick={() => setCopied(true)}
    />
  );
}
