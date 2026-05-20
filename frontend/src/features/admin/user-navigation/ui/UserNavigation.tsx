import { useMediaQuery } from "@/shared/hooks";
import { Button } from "@/shared/ui";
import type { SelectUser } from "@/widgets/admin-user-manager";

import { useKeyboardNavigation } from "../lib/useKeyboardNavigation";
import { useUserNavigation } from "../lib/useUserNavigation";

import "./UserNavigation.scss";

/**
 * Interface defining the props for the `UserNavigation` component.
 */
export interface IUserNavigationProps {
  currentUserId: SelectUser;
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

  const isMobile576px = useMediaQuery({ query: "(max-width: 576px)" });

  const buttonsSize = isMobile576px ? "medium" : "small";

  return (
    <div className="user-navigation">
      <Button
        variant="ghost"
        size={buttonsSize}
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
        size={buttonsSize}
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
