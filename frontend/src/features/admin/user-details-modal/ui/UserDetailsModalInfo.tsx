import type { IStorageStatsResponse, IUser } from "@/entities/user";
import { Heading, PageWrapper, StatusBadge } from "@/shared/ui";
import { formatDate, truncateWithMiddleEllipsis } from "@/shared/utils";

import "./UserDetailsModal.scss";

/**
 * Props interface for the UserDetailsModalInfo component.
 */
interface IUserDetailsModalInfoProps {
  user: IUser;
  storageStats?: IStorageStatsResponse;
}

/**
 * Component that displays detailed user information in a structured format.
 *
 * @example
 * <UserDetailsModalInfo user={userData} storageStats={storageData} />
 */
export function UserDetailsModalInfo({
  user,
  storageStats,
}: IUserDetailsModalInfoProps) {
  const generalInfo = [
    { title: "ID", value: user.id },
    { title: "Логин", value: user.username },
    {
      title: "Email",
      value: truncateWithMiddleEllipsis(user.email),
      originalValue: user.email,
    },
    { title: "ФИО", value: user.fullName },
  ];

  const additionalInfo = [
    { title: "Регистрация", value: formatDate(user.dateJoined) },
    { title: "Посл. вход", value: formatDate(user.lastLogin) },
    { title: "Активен", value: <StatusBadge isActive={user.isActive} /> },
    {
      title: "Администратор",
      value: (
        <StatusBadge
          isActive={user.isStaff}
          activeText="Да"
          inactiveText="Нет"
        />
      ),
    },
  ];

  const storageInfo = [
    { title: "Путь хранилища", value: storageStats?.storage.path },
    { title: "Кол-во файлов", value: storageStats?.storage.fileCount },
    { title: "Общий размер", value: storageStats?.storage.totalSizeFormatted },
  ];

  return (
    <PageWrapper
      direction="column"
      className="user-details-modal__info-section"
    >
      <div className="user-details-modal__info">
        <Heading
          level={4}
          align="center"
          size="sm"
          className="user-details-modal__info-title"
        >
          Основная информация
        </Heading>
        {generalInfo.map((info) => (
          <div
            key={info.title}
            className="user-details-modal__info-path"
            title={info.originalValue}
          >
            <p className="user-details-modal__info-title">{info.title}:</p>
            <span>{info.value}</span>
          </div>
        ))}
      </div>

      <div className="user-details-modal__info">
        <Heading
          level={4}
          align="center"
          size="sm"
          className="user-details-modal__info-title"
        >
          Доп. информация
        </Heading>
        {additionalInfo.map((info) => (
          <div key={info.title} className="user-details-modal__info-path">
            <p className="user-details-modal__info-title">{info.title}:</p>
            <span>{info.value}</span>
          </div>
        ))}
      </div>

      <div className="user-details-modal__info">
        <Heading
          level={4}
          align="center"
          size="sm"
          className="user-details-modal__info-title"
        >
          Статистика диска
        </Heading>
        {storageInfo.map((info) => (
          <div key={info.title} className="user-details-modal__info-path">
            <p className="user-details-modal__info-title">{info.title}:</p>
            <span>{info.value}</span>
          </div>
        ))}
      </div>
    </PageWrapper>
  );
}
