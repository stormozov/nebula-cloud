/**
 * File size units for human-readable formatting.
 */
const FILE_SIZE_UNITS = ["Б", "КБ", "МБ", "ГБ", "ТБ"] as const;

/**
 * Converts bytes to human-readable file size string.
 *
 * Uses appropriate unit (B, KB, MB, GB, TB) based on size magnitude.
 *
 * @param bytes - File size in bytes
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted file size string (e.g., "1.5 MB", "256 КБ")
 *
 * @example
 * formatFileSize(1024) // "1.00 КБ"
 * formatFileSize(1048576) // "1.00 МБ"
 * formatFileSize(1073741824) // "1.00 ГБ"
 * formatFileSize(500, 0) // "500 Б"
 */
export const formatFileSize = (bytes: number, decimals: number = 2): string => {
  if (bytes === 0) return "0 Б";

  const byteNumber = Math.abs(bytes);
  const base = Math.floor(Math.log10(byteNumber) / Math.log10(1024));
  const unitIndex = Math.min(base, FILE_SIZE_UNITS.length - 1);
  const value = bytes / 1024 ** unitIndex;

  return `${value.toFixed(decimals)} ${FILE_SIZE_UNITS[unitIndex]}`;
};

/**
 * Parses human-readable file size string back to bytes.
 *
 * @param sizeString - Formatted size string (e.g., "1.5 MB", "256 КБ")
 * @returns Size in bytes
 *
 * @example
 * parseFileSize('1.00 МБ') // 1_048_576
 * parseFileSize('500 Б') // 500
 */
export const parseFileSize = (sizeString: string): number => {
  const match = sizeString.match(/^([\d.]+)\s*([БКМГТ][Б]?)/i);
  if (!match) return 0;

  const value = parseFloat(match[1]);
  const unit = match[2].toUpperCase();

  const unitMultipliers: Record<string, number> = {
    Б: 1,
    КБ: 1024,
    МБ: 1024 ** 2,
    ГБ: 1024 ** 3,
    ТБ: 1024 ** 4,
  };

  return Math.round(value * unitMultipliers[unit]);
};
