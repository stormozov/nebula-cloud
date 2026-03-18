import type { SnakeToCamelObj, SnakeToCamelReturn } from "../types/converters";

/**
 * Converts snake_case keys to camelCase recursively.
 */
export const snakeToCamel = (obj: SnakeToCamelObj): SnakeToCamelReturn => {
  if (Array.isArray(obj)) return obj.map(snakeToCamel);
  if (obj && typeof obj === "object") {
    if (obj instanceof File || obj instanceof Blob) return obj;
    return Object.fromEntries(
      Object.entries(obj).map(([key, value]) => [
        key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()),
        snakeToCamel(value),
      ]),
    );
  }
  return obj;
};
