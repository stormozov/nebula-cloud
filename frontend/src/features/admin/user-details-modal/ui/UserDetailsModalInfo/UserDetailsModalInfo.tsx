import classNames from "classnames";

import type { IStorageStatsResponse, IUser } from "@/entities/user";
import { Button, Heading, Icon } from "@/shared/ui";

import type { IUserDetailsInfoItem } from "../../lib/types";
import { useBlockHover } from "../../lib/useBlockHover";
import { useClipboardWithHandlers } from "../../lib/useClipboardWithHandlers";
import { useUserBlocksData } from "../../lib/useUserBlocksData";

import "./UserDetailsModalInfo.scss";

/**
 * Props interface for the UserDetailsModalInfo component.
 */
interface IUserDetailsModalInfoProps {
  user: IUser;
  storageStats?: IStorageStatsResponse;
}

/**
 * Modal component for displaying detailed user info in structured blocks.
 *
 * Renders user data grouped into sections. Each section is interactive
 * — supports hover states and copying values via clipboard hooks.
 */
export function UserDetailsModalInfo({
  user,
  storageStats,
}: IUserDetailsModalInfoProps) {
  const blocks = useUserBlocksData(user, storageStats);
  const { handleRowClick, handleCopyBlock } = useClipboardWithHandlers();
  const { isHovered, handleMouseEnter, handleMouseLeave } = useBlockHover();

  // An auxiliary function for rendering a block
  const renderSection = (title: string, items: IUserDetailsInfoItem[]) => {
    const copyValues = items.map((item) => item.copyValue);

    return (
      <section
        key={title}
        className="user-details-modal-info__section"
        aria-label={`Блок информации о пользователе: ${title}`}
        onMouseEnter={() => handleMouseEnter(title)}
        onMouseLeave={handleMouseLeave}
      >
        <header
          className={classNames("user-details-modal-info__header", {
            hovered: isHovered(title),
          })}
        >
          <Heading
            level={4}
            size="sm"
            noMargin
            className="user-details-modal-info__title"
          >
            {title}
          </Heading>
          <Button
            variant="text"
            className="user-details-modal-info__copy-block-btn"
            onClick={() => handleCopyBlock(title, copyValues)}
            aria-label={`Скопировать все поля блока "${title}"`}
          >
            <Icon name="copy" />
          </Button>
        </header>
        <div className="user-details-modal-info__items">
          {items.map((info) => (
            <button
              key={info.title}
              type="button"
              className="user-details-modal-info__item w-full"
              title={info.originalValue}
              aria-label={`Скопировать ${info.title}`}
              onClick={() => handleRowClick(info.copyValue, info.title)}
            >
              <p className="user-details-modal-info__label">{info.title}:</p>
              <span className="user-details-modal-info__value">
                {info.value}
              </span>
              <Icon
                name="copy"
                color="text-tertiary"
                className="user-details-modal-info__copy-decor-icon"
              />
            </button>
          ))}
        </div>
      </section>
    );
  };

  return (
    <aside className="user-details-modal-info">
      {blocks.map(({ title, items }) => renderSection(title, items))}
    </aside>
  );
}
