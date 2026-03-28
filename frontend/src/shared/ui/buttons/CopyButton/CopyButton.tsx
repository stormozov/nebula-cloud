import classNames from "classnames";
import { Icon, type IIconProps } from "../../Icon";
import { Button, type IButtonProps } from "../Button";

export interface CopyButtonProps {
  buttonProps: IButtonProps;
  iconProps?: IIconProps;
  onClick: () => void;
}

export function CopyButton({ buttonProps, iconProps }: CopyButtonProps) {
  const classes = classNames("copy-button", buttonProps.className);
  return (
    <Button variant="text" className={classes} {...buttonProps}>
      <Icon {...iconProps} name="copy" />
    </Button>
  );
}
