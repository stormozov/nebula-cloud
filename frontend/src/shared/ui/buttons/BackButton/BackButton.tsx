import { useNavigate } from "react-router";

import { Icon } from "../../Icon";
import { Button } from "../Button";

/**
 * Props for the BackButton component.
 */
export interface BackButtonProps {
  text?: string;
}

/**
 * A reusable back button component that navigates to the previous page
 * in history.
 * 
 * @example
 * <BackButton text="" /> // Without text, only icon
 * 
 * @example
 * <BackButton /> // With default text
 */
export function BackButton({ text = "Назад" }: BackButtonProps) {
  const navigate = useNavigate();

  const handleClick = () => navigate(-1);

  return (
    <Button
      className="back-button"
      variant="secondary"
      size="small"
      title="Вернуться назад"
      aria-label="Вернуться назад"
      onClick={handleClick}
    >
      <Icon name="arrowLeft" />
      {text}
    </Button>
  );
}
