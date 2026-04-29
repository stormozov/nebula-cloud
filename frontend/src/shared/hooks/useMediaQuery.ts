import { useEffect, useState } from "react";

/**
 * Interface defining the input parameters for the {@link useMediaQuery} hook.
 */
interface IMediaQueryParams {
  /**
   * The media query string to evaluate.
   *
   * @remarks
   * Must be a valid CSS media query, such as `(max-width: 768px)`
   * or `(prefers-color-scheme: dark)`. This query will be used to determine
   * the current matching state and listen for changes.
   */
  query: string;
}

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
export const useMediaQuery = ({ query }: IMediaQueryParams): boolean => {
  const [matches, setMatches] = useState(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia(query).matches;
  });

  useEffect(() => {
    const media = window.matchMedia(query);
    const listener = (e: MediaQueryListEvent) => setMatches(e.matches);

    media.addEventListener("change", listener);
    return () => media.removeEventListener("change", listener);
  }, [query]);

  return matches;
};
