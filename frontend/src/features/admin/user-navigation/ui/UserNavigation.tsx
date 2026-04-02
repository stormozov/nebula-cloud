import { Button } from "@/shared/ui";

import { useKeyboardNavigation } from "../lib/useKeyboardNavigation";
import { useUserNavigation } from "../lib/useUserNavigation";

import "./UserNavigation.scss";

/**
 * Interface defining the props for the `UserNavigation` component.
 */
export interface IUserNavigationProps {
  currentUserId: number;
  allUserIds: number[];
  hasPaginationMore: boolean;
  onNavigate: (userId: number) => void;
  onLoadMore: (shouldAutoNavigate: boolean) => void;
}

/**
 * Navigation component that allows switching between users using "Previous"
 * and "Next" buttons.
 */
export function UserNavigation({
  currentUserId,
  allUserIds,
  hasPaginationMore,
  onNavigate,
  onLoadMore,
}: IUserNavigationProps) {
  const { hasPrev, hasNext, handlePrev, handleNext } = useUserNavigation({
    currentUserId,
    allUserIds,
    hasPaginationMore,
    onNavigate,
    onLoadMore,
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
        icon={{ name: hasPrev ? "arrowLeft" : "doNotDisturb" }}
        disabled={!hasPrev}
        onClick={handlePrev}
      >
        Пред.
      </Button>
      <Button
        variant="ghost"
        size="small"
        title="Следующий пользователь (→)"
        aria-label="Следующий пользователь"
        icon={{ name: hasNext ? "arrowRight" : "doNotDisturb", isRight: true }}
        disabled={!hasNext}
        onClick={handleNext}
      >
        След.
      </Button>
    </div>
  );
}
