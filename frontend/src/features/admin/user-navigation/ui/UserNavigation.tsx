import { Button, Icon } from "@/shared/ui";

import { useKeyboardNavigation } from "../lib/useKeyboardNavigation";
import { useUserNavigation } from "../lib/useUserNavigation";

import "./UserNavigation.scss";

/**
 * Interface defining the props for the `UserNavigation` component.
 */
export interface IUserNavigationProps {
  currentUserId: number;
  allUserIds: number[];
  onNavigate: (userId: number) => void;
}

/**
 * Navigation component that allows switching between users using "Previous"
 * and "Next" buttons.
 */
export function UserNavigation({
  currentUserId,
  allUserIds,
  onNavigate,
}: IUserNavigationProps) {
  const { hasPrev, hasNext, handlePrev, handleNext } = useUserNavigation({
    currentUserId,
    allUserIds,
    onNavigate,
  });

  useKeyboardNavigation({
    hasPrev,
    hasNext,
    onPrev: handlePrev,
    onNext: handleNext,
  });

  return (
    <div className="user-navigation">
      <Button
        variant="ghost"
        size="small"
        title="Предыдущий пользователь (←)"
        aria-label="Предыдущий пользователь"
        disabled={!hasPrev}
        onClick={handlePrev}
      >
        <Icon name={hasPrev ? "arrowLeft" : "doNotDisturb"} />
        Пред.
      </Button>
      <Button
        variant="ghost"
        size="small"
        title="Следующий пользователь (→)"
        aria-label="Следующий пользователь"
        disabled={!hasNext}
        onClick={handleNext}
      >
        След.
        <Icon name={hasNext ? "arrowRight" : "doNotDisturb"} />
      </Button>
    </div>
  );
}
