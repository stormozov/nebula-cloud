import { useMemo } from "react";

import {
  type IStorageStats,
  isAdminResponse,
  useGetStorageSummaryQuery,
} from "@/entities/user";

import { STORAGE_WARNING_THRESHOLD } from "./constants";

/**
 * The result object returned by the `useStorageUsage` hook.
 */
interface UseStorageUsageResult {
  /** The raw data fetched from the API. */
  data: IStorageStats | undefined;
  /** A boolean indicating whether the data is currently being fetched. */
  isLoading: boolean;
  /** Any error that occurred during the fetch operation. */
  error: unknown;
  /** The amount of storage used in bytes. */
  used: number;
  /** The total storage limit in bytes. */
  limit: number;
  /** Formatted string representation of the used storage (e.g., "2.5 ГБ"). */
  usedFormatted: string;
  /** Formatted string representation of the storage limit (e.g., "10 ГБ"). */
  limitFormatted: string;
  /** The percentage of storage used out of the total limit. */
  percent: number;
  /** Indicates whether the user has exceeded their storage limit. */
  isExceeded: boolean;
  /** Indicates whether the storage usage has reached the warning threshold. */
  isWarning: boolean;
}

/**
 * Custom React Hook that fetches and computes user storage usage statistics.
 *
 * @param userId - Optional ID of the user whose storage data should be
 * retrieved. If not provided, the query may default to the current user.
 */
export const useStorageUsage = (userId?: number): UseStorageUsageResult => {
  const { data, isLoading, error } = useGetStorageSummaryQuery(userId);

  const stats: IStorageStats | undefined = useMemo(() => {
    if (!data) return undefined;
    if (isAdminResponse(data)) return data.storage;
    return data;
  }, [data]);

  const used = stats?.totalSize ?? 0;
  const limit = stats?.storageLimit ?? 0;
  const usedFormatted = stats?.totalSizeFormatted ?? "0 Б";
  const limitFormatted = stats?.storageLimitFormatted ?? "0 Б";
  const percent = stats?.usagePercent ?? 0;

  const isExceeded = percent >= 100;
  const isWarning = percent >= STORAGE_WARNING_THRESHOLD * 100;

  return {
    data: stats,
    isLoading,
    error,
    used,
    limit,
    usedFormatted,
    limitFormatted,
    percent,
    isExceeded,
    isWarning,
  };
};
