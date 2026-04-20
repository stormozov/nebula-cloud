import { useMemo } from "react";

import type { IStorageStatsResponse, IUser } from "@/entities/user";
import { StorageProgressBar, useStorageUsage } from "@/features/storage-usage";
import { StatusBadge } from "@/shared/ui";
import { formatDate, truncateWithMiddleEllipsis } from "@/shared/utils";

import type { IUserDetailsInfoItem } from "./types";

/**
 * Interface for the return value of the useUserBlocksData hook.
 */
interface IUseUserBlocksDataReturns {
  title: string;
  items: IUserDetailsInfoItem[];
}

/**
 * Custom React hook that prepares and formats user data into structured blocks
 * for display.
 *
 * Organizes user information into categories.
 */
export const useUserBlocksData = (
  user: IUser,
  storageStats?: IStorageStatsResponse,
): IUseUserBlocksDataReturns[] => {
  const { used, limit, usedFormatted, limitFormatted, percent } =
    useStorageUsage(user.id);

  return useMemo(() => {
    const generalInfo: IUserDetailsInfoItem[] = [
      {
        title: "ID",
        value: user.id,
        copyValue: String(user.id),
        originalValue: `ID: ${user.id}`,
      },
      {
        title: "Логин",
        value: user.username,
        copyValue: user.username,
        originalValue: `Логин: ${user.username}`,
      },
      {
        title: "Email",
        value: truncateWithMiddleEllipsis(user.email),
        copyValue: user.email,
        originalValue: `Email: ${user.email}`,
      },
      {
        title: "ФИО",
        value: user.fullName,
        copyValue: user.fullName,
        originalValue: `ФИО: ${user.fullName}`,
      },
    ];

    const additionalInfo: IUserDetailsInfoItem[] = [
      {
        title: "Регистрация",
        value: formatDate(user.dateJoined),
        copyValue: formatDate(user.dateJoined),
        originalValue: `Дата регистрации: ${formatDate(user.dateJoined)}`,
      },
      {
        title: "Посл. вход",
        value: formatDate(user.lastLogin),
        copyValue: formatDate(user.lastLogin),
        originalValue: `Последний вход: ${formatDate(user.lastLogin)}`,
      },
      {
        title: "Активен",
        value: <StatusBadge isActive={user.isActive} />,
        copyValue: `Активен: ${user.isActive ? "Да" : "Нет"}`,
        originalValue: `Активен: ${user.isActive ? "Да" : "Нет"}`,
      },
      {
        title: "Администратор",
        value: (
          <StatusBadge
            isActive={user.isStaff}
            activeText="Да"
            inactiveText="Нет"
          />
        ),
        copyValue: `Администратор: ${user.isStaff ? "Да" : "Нет"}`,
        originalValue: `Администратор: ${user.isStaff ? "Да" : "Нет"}`,
      },
    ];

    const storageInfo: IUserDetailsInfoItem[] = [
      {
        title: "Общий размер",
        value: (
          <div className="user-details-modal-info__item user-details-modal-info__storage-progress">
            <p className="user-details-modal-info__label">Занятость диска:</p>
            <StorageProgressBar
              used={used}
              total={limit}
              usedFormatted={usedFormatted}
              totalFormatted={limitFormatted}
              percent={percent}
              showLabels
            />
          </div>
        ),
        copyValue: "",
        originalValue: `Общий размер: ${
          storageStats?.storage.totalSizeFormatted || ""
        }`,
      },
      {
        title: "Кол-во файлов",
        value: storageStats?.storage.fileCount || 0,
        copyValue: String(storageStats?.storage.fileCount ?? 0),
        originalValue: `Кол-во файлов: ${storageStats?.storage.fileCount || 0}`,
      },
      {
        title: "Общий размер",
        value: storageStats?.storage.totalSizeFormatted || "",
        copyValue: storageStats?.storage.totalSizeFormatted ?? "",
        originalValue: `Общий размер: ${
          storageStats?.storage.totalSizeFormatted || ""
        }`,
      },
      {
        title: "Путь хранилища",
        value: storageStats?.storage.path,
        copyValue: storageStats?.storage.path ?? "",
        originalValue: `Путь хранилища: ${storageStats?.storage.path ?? ""}`,
      },
    ];

    return [
      { title: "Основная информация", items: generalInfo },
      { title: "Доп. информация", items: additionalInfo },
      { title: "Статистика диска", items: storageInfo },
    ];
  }, [user, storageStats, limit, usedFormatted, limitFormatted, percent, used]);
};
