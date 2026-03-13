import classNames from "classnames";

import "./Logo.scss";

/**
 * Props interface for the Logo component, extending standard HTML attributes
 * for div elements.
 */
interface ILogoProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
}

/**
 * Logo component that renders the app's logo as a styled div containing text.
 */
export function Logo({ ...props }: ILogoProps) {
  return (
    <div {...props} className={classNames("logo", props.className)}>
      <p>Nebula Cloud</p>
    </div>
  );
}
