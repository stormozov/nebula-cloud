/**
 * Generates initials from a full name string.
 *
 * Splits the input name by spaces, takes the first character of each part,
 * joins them into a single string, converts to uppercase, and truncates
 * to the specified length.
 *
 * @param name - The full name from which to generate initials. Expected to be
 * a non-empty string.
 * @param maxLength - Maximum number of characters to include in the result.
 * @returns A string containing the uppercase initials, truncated to `maxLength`.
 *
 * @example
 * getInitials("John Doe"); // Returns "JD"
 * getInitials("Alice Bob Charlie", 3); // Returns "ABC"
 * getInitials("Single", 2); // Returns "S"
 */
export const getInitials = (name: string, maxLength = 2): string => {
  return name
    .split(" ")
    .map((part) => part[0])
    .join("")
    .toUpperCase()
    .slice(0, maxLength);
};
