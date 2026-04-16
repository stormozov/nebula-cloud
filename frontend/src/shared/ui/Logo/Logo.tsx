import classNames from "classnames";
import { Link } from "react-router";

import { Icon } from "../Icon";

import "./Logo.scss";

/**
 * Props interface for the Logo component, extending standard HTML attributes
 * for div elements.
 */
interface ILogoProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Additional class names */
  className?: string;
}

/**
 * Logo component that renders the app's logo as a styled div containing text.
 */
export function Logo({ ...props }: ILogoProps) {
  return (
    <Link to="/">
      <div {...props} className={classNames("logo", props.className)}>
        <Icon name="cloud" size={30} color="primary" className="logo__icon" />
        <p>Nebula Cloud</p>
      </div>
    </Link>
  );
}
