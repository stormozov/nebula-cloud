/**
 * Represents a single public route configuration item.
 */
export type PublicRoutesConfigItem = {
  /** The path pattern of the public route. */
  path: string;
};

/**
 * Represents the complete configuration for public routes.
 */
export type PublicRoutesConfig = PublicRoutesConfigItem[];
