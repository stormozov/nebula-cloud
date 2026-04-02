/**
 * Formats a date string into a localized date and time representation.
 *
 * @param dateString - The date string to format, or `null` if no date
 *  is available.
 *
 * @returns A formatted date-time string in the Russian locale (`ru-RU`)
 *  with numeric year, two-digit month and day, and two-digit hour and minute.
 *  Returns "—" if the input is `null` or an empty string.
 *
 * @example
 * ```ts
 * formatDate("2023-10-05T14:30:00Z"); // → "05.10.2023, 14:30"
 * formatDate(null); // → "—"
 * ```
 */
export const formatDate = (dateString: string | null | undefined): string => {
  if (!dateString) return "—";
  return new Date(dateString).toLocaleDateString("ru-RU", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};
