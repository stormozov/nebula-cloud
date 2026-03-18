import type { IFile } from "@/entities/file";

/** Object to convert from snake_case to camelCase */
export type SnakeToCamelObj = IFile[] | Record<string, unknown> | unknown;

/** Return type for converting from snake_case to camelCase */
export type SnakeToCamelReturn = SnakeToCamelObj;
