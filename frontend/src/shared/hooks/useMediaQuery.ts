import { useEffect, useState } from "react";

/**
 * Determines the initial matching state of a given media query.
 *
 * @param query - A valid CSS media query string (e.g., `(max-width: 768px)`
 * or `(prefers-color-scheme: dark)`).
 *
 * @returns A boolean indicating whether the media query currently matches.
 *
 * @example
 * ```ts
 * const isMobile = getInitialMatches("(max-width: 768px)");
 * ```
 */
export const getInitialMatches = (query: string): boolean => {
  if (typeof window === "undefined") return false;
  return window.matchMedia(query).matches;
};

/**
 * Custom React hook that monitors changes in a CSS media query.
 *
 * @remarks
 * This hook returns a boolean indicating whether the document currently matches
 * the given media query. It uses `window.matchMedia` API to subscribe
 * to real-time updates and automatically cleans up event listeners on unmount.
 *
 * On the server side (e.g., during SSR), it defaults to `false` since `window`
 * is not available.
 *
 * The initial value is computed lazily using `useState`, and the effect handles
 * dynamic updates.
 *
 * @example
 * ```tsx
 * function Component() {
 *   const isDarkMode = useMediaQuery({ query: "(prefers-color-scheme: dark)" });
 *   return <div>Dark mode is {isDarkMode ? "on" : "off"}</div>;
 * }
 * ```
 */
export const useMediaQuery = ({ query }: { query: string }): boolean => {
  const [matches, setMatches] = useState(() => getInitialMatches(query));

  useEffect(() => {
    const media = window.matchMedia(query);
    const listener = (e: MediaQueryListEvent) => setMatches(e.matches);
    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }, [query]);

  return matches;
};
