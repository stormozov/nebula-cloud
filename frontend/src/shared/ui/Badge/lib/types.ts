/**
 * Represents the semantic color variants for badges that convey specific
 * meanings.
 *
 * Each variant corresponds to a particular context:
 * - "primary": Main actions or primary information.
 * - "success": Successful or positive states.
 * - "warning": Cautionary or warning states.
 * - "error": Error or failure states.
 * - "info": Informational messages or hints.
 */
type SemanticVariant = "primary" | "success" | "warning" | "error" | "info";

/**
 * Represents light versions of semantic variants.
 */
type LightVariant = `${SemanticVariant}-light`;

/**
 * Union type defining all available visual styles (variants) for a badge.
 */
export type BadgeVariant = "default" | SemanticVariant | LightVariant;
